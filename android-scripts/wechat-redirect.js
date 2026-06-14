/**
 * WeChat MMTLS Traffic Redirector
 *
 * Intercepts TCP connect() calls from any process and redirects connections
 * destined for WeChat server IPs (from WEIXIN_IPS in config.js) to a
 * user-configured mitm proxy (REDIRECT_TARGET_HOST:REDIRECT_TARGET_PORT).
 *
 * Based on the native-connect-hook.js pattern from
 * https://github.com/httptoolkit/frida-interception-and-unpinning/
 *
 * Load order: frida -l config.js -l wechat-redirect.js -f com.tencent.mm
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

(() => {
    // ── Pre-process IP lists ────────────────────────────────────────────────────────────────────
    // Convert WEIXIN_IPS to packed-integer Sets for O(1) lookup at connect time.
    // IPv4: pack 4 octets into a Uint32 (network byte order: big-endian).
    // IPv6: store as normalized lowercase colon-hex string.

    const WEIXIN_IPv4_SET = new Set();
    const WEIXIN_IPv6_SET = new Set();

    for (const ip of WEIXIN_IPS) {
        if (ip.includes(':')) {
            WEIXIN_IPv6_SET.add(ip.toLowerCase());
        } else {
            const parts = ip.split('.');
            if (parts.length !== 4) {
                if (DEBUG_MODE) console.warn(`[wechat-redirect] Skipping malformed IP: ${ip}`);
                continue;
            }
            const packed = (parseInt(parts[0], 10) << 24)
                         | (parseInt(parts[1], 10) << 16)
                         | (parseInt(parts[2], 10) << 8)
                         | parseInt(parts[3], 10);
            WEIXIN_IPv4_SET.add(packed);
        }
    }

    if (DEBUG_MODE) {
        console.log(`[wechat-redirect] Loaded ${WEIXIN_IPv4_SET.size} IPv4 + ${WEIXIN_IPv6_SET.size} IPv6 WeChat addresses`);
    }

    // ── Pre-compute target proxy bytes ──────────────────────────────────────────────────────────

    const TARGET_IPv4_BYTES = REDIRECT_TARGET_HOST.split('.').map(Number);
    // IPv4-mapped IPv6: ::ffff:a.b.c.d
    const TARGET_IPv6_BYTES = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff,
        TARGET_IPv4_BYTES[0], TARGET_IPv4_BYTES[1],
        TARGET_IPv4_BYTES[2], TARGET_IPv4_BYTES[3],
    ];

    // Pre-compute packed target host IP for loop detection
    const TARGET_PACKED_IPv4 = (TARGET_IPv4_BYTES[0] << 24)
                              | (TARGET_IPv4_BYTES[1] << 16)
                              | (TARGET_IPv4_BYTES[2] << 8)
                              | TARGET_IPv4_BYTES[3];

    // ── Non-blocking socket flags ───────────────────────────────────────────────────────────────

    const F_GETFL = 3;
    const F_SETFL = 4;
    const O_NONBLOCK = (Process.platform === 'darwin') ? 4 : 2048; // Linux/Android

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────

    const getReadableAddress = (hostBytes, isIPv6) => {
        if (isIPv6) {
            const groups = [];
            for (let i = 0; i < 16; i += 2) {
                groups.push(((hostBytes[i] << 8) | hostBytes[i + 1]).toString(16));
            }
            return groups.join(':');
        }
        return hostBytes.join('.');
    };

    const areArraysEqual = (arrayA, arrayB) => {
        if (arrayA.length !== arrayB.length) return false;
        for (let i = 0; i < arrayA.length; i++) {
            if (arrayA[i] !== arrayB[i]) return false;
        }
        return true;
    };

    // ── Hook connect() ──────────────────────────────────────────────────────────────────────────

    let conn;
    let systemModule;

    try {
        systemModule = Process.findModuleByName('libc.so') ??
                       Process.findModuleByName('libc.so.6') ??
                       Process.findModuleByName('libsystem_c.dylib');

        if (!systemModule) throw new Error('Could not find libc or libsystem_c');

        conn = systemModule.getExportByName('connect');
    } catch (e) {
        console.error('[wechat-redirect] Failed to find connect() export:', e);
        return;
    }

    if (!conn) {
        console.error('[wechat-redirect] connect() not found — aborting.');
        return;
    }

    // ── Diagnostic: hook socket() to see domain families used ───────────────
    const _socketAddr = systemModule.getExportByName('socket');
    Interceptor.attach(_socketAddr, {
        onEnter(args) {
            const domain = args[0].toInt32();
            const type = args[1].toInt32();
            const protocol = args[2].toInt32();
            let domainStr = ['AF_UNSPEC', 'AF_UNIX', 'AF_INET', 'AF_AX25', 'AF_IPX', 'AF_APPLETALK', 'AF_NETROM', 'AF_BRIDGE', 'AF_AAL5', 'AF_X25', 'AF_INET6'][domain] || `AF_${domain}`;
            if (domain === 2 || domain === 10 || domain === 0) {
                console.log(`[wechat-redirect] socket(domain=${domainStr}, type=0x${type.toString(16)}, protocol=${protocol})`);
            }
        }
    });

    // ── Diagnostic: hook sendto/sendmsg for TCP data detection ───────────
    const _sendAddr = systemModule.getExportByName('sendto');
    Interceptor.attach(_sendAddr, {
        onEnter(args) {
            const fd = args[0].toInt32();
            const buf = args[1];
            const len = args[2].toInt32();
            const sockType = Socket.type(fd);
            if (sockType === 'tcp' || sockType === 'tcp6') {
                console.log(`[wechat-redirect] sendto(fd=${fd}, len=${len}, type=${sockType})`);
            }
        }
    });

    // ── Look for 'connect' in key modules ──────────────────────────────────
    for (const name of ['libc.so', 'libcutils.so', 'libnetd_client.so', 'libwechatcommon.so']) {
        const mod = Process.findModuleByName(name);
        if (mod) {
            try {
                const addr = mod.getExportByName('connect');
                console.log(`[wechat-redirect]   'connect' in ${name} @ ${addr}`);
            } catch (_) {}
        }
    }

    // ── Try alternative: hook __wrap_connect, __connect if they exist ──────
    for (const name of ['__wrap_connect', '__connect', 'connect@LIBC']) {
        try {
            const alt = Module.findExportByName(null, name);
            if (alt) {
                console.log(`[wechat-redirect] Also hooking ${name} @ ${alt}`);
                Interceptor.attach(alt, {
                    onEnter(args) {
                        console.log(`[wechat-redirect] ${name} called!`);
                    }
                });
            }
        } catch (_) {}
    }

    // ── Main connect() hook ─────────────────────────────────────────────────
    Interceptor.attach(conn, {
        onEnter(args) {
            const fd = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);

            const addrPtr = ptr(args[1]);
            const addrLen = args[2].toInt32();
            const addrData = addrPtr.readByteArray(addrLen);

            const isTCP = sockType === 'tcp' || sockType === 'tcp6';
            const isUDP = sockType === 'udp' || sockType === 'udp6';
            const isIPv6 = sockType === 'tcp6' || sockType === 'udp6';

            if (DEBUG_MODE) {
                let debugFamily = 'unknown';
                if (addrData && addrData.byteLength >= 2) {
                    const famView = new DataView(addrData.slice(0, 2));
                    // sa_family is host byte order (little-endian on ARM64)
                    const family = famView.getUint16(0, true);
                    if (family === 2) debugFamily = 'AF_INET';
                    else if (family === 10) debugFamily = 'AF_INET6';
                    else if (family === 1) debugFamily = 'AF_UNIX';
                    else if (family === 0) debugFamily = 'AF_SPECIAL';
                    else debugFamily = `AF_${family}`;
                }
                console.log(`[wechat-redirect] connect(fd=${fd}, type=${sockType}, family=${debugFamily}, len=${addrLen})`);
            }

            if (!isTCP && !isUDP) {
                this.state = 'ignored';
                return;
            }

            // Only redirect TCP; UDP left alone
            if (!isTCP) {
                this.state = 'ignored';
                return;
            }

            // Read port (big-endian uint16 at offset 2)
            const portView = new DataView(addrData.slice(2, 4));
            const port = portView.getUint16(0, false);

            // Read IP bytes
            let hostBytes;
            if (isIPv6) {
                // sockaddr_in6: 2 family, 2 port, 4 flowinfo, 16 ip, 4 scope_id
                hostBytes = new Uint8Array(addrData.slice(8, 8 + 16));
            } else {
                // sockaddr_in: 2 family, 2 port, 4 ip, 8 zeros
                hostBytes = new Uint8Array(addrData.slice(4, 4 + 4));
            }

            // ── Check: already connecting to the proxy? ─────────────────────────────────────────
            if (port === REDIRECT_TARGET_PORT) {
                if (isIPv6) {
                    // Check if this is the IPv4-mapped target
                    if (areArraysEqual(hostBytes, TARGET_IPv6_BYTES)) {
                        this.state = 'ignored';
                        return;
                    }
                    // Also check last 4 bytes against packed target (for native IPv6 target)
                    // If target is IPv4, it'll be ::ffff: so this won't match native IPv6
                } else {
                    const packed = (hostBytes[0] << 24) | (hostBytes[1] << 16)
                                 | (hostBytes[2] << 8) | hostBytes[3];
                    if (packed === TARGET_PACKED_IPv4) {
                        this.state = 'ignored';
                        return;
                    }
                }
            }

            // ── Check: is this a WeChat IP? ─────────────────────────────────────
            let isWeChatIP = REDIRECT_ALL;

            if (!isWeChatIP) {
                if (isIPv6) {
                    // Check native IPv6 addresses
                    const ipStr = getReadableAddress(hostBytes, true);
                    if (WEIXIN_IPv6_SET.has(ipStr)) {
                        isWeChatIP = true;
                    }

                    // Also check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
                    // First 12 bytes should be 0s followed by 0xff 0xff
                    let isMapped = true;
                    for (let i = 0; i < 10; i++) {
                        if (hostBytes[i] !== 0) { isMapped = false; break; }
                    }
                    if (isMapped && hostBytes[10] === 0xff && hostBytes[11] === 0xff) {
                        // Extract the embedded IPv4
                        const mappedPacked = (hostBytes[12] << 24) | (hostBytes[13] << 16)
                                           | (hostBytes[14] << 8) | hostBytes[15];
                        if (WEIXIN_IPv4_SET.has(mappedPacked)) {
                            isWeChatIP = true;
                        }
                    }
                } else {
                    // IPv4: pack and check
                    const packed = (hostBytes[0] << 24) | (hostBytes[1] << 16)
                                 | (hostBytes[2] << 8) | hostBytes[3];
                    if (WEIXIN_IPv4_SET.has(packed)) {
                        isWeChatIP = true;
                    }
                }
            }

            if (!isWeChatIP) {
                this.state = 'ignored';
                return;
            }

            // ── Redirect! ───────────────────────────────────────────────────────────────────────
            this.state = 'redirected';

            if (DEBUG_MODE) {
                console.log(
                    `[wechat-redirect] Redirecting TCP connection to ` +
                    `${getReadableAddress(hostBytes, isIPv6)}:${port} → ` +
                    `${REDIRECT_TARGET_HOST}:${REDIRECT_TARGET_PORT}`
                );
            }

            // Overwrite port
            const portArr = new Uint8Array(2);
            new DataView(portArr.buffer).setUint16(0, REDIRECT_TARGET_PORT, false);
            addrPtr.add(2).writeByteArray(portArr);

            // Overwrite address
            if (isIPv6) {
                addrPtr.add(8).writeByteArray(TARGET_IPv6_BYTES);
            } else {
                addrPtr.add(4).writeByteArray(TARGET_IPv4_BYTES);
            }
        },

        onLeave(retval) {
            if (this.state === 'ignored' || this.state === undefined) return;

            if (DEBUG_MODE) {
                const ret = retval.toInt32();
                const fd = this.sockFd;
                if (ret === 0) {
                    console.debug(`[wechat-redirect] Redirected fd ${fd}: connected to proxy`);
                } else if (ret === -115 || ret === -36) {
                    // EINPROGRESS (-115 on Linux, -36 on iOS) = normal for non-blocking
                    console.debug(`[wechat-redirect] Redirected fd ${fd}: connecting (non-blocking, EINPROGRESS)`);
                } else {
                    console.warn(`[wechat-redirect] Redirected fd ${fd}: connect failed (errno ${ret})`);
                }
            }
        }
    });

    console.log(
        `[wechat-redirect] Active — redirecting ${REDIRECT_ALL ? 'ALL' : 'WeChat'} TCP traffic to ` +
        `${REDIRECT_TARGET_HOST}:${REDIRECT_TARGET_PORT}`
    );
})();
