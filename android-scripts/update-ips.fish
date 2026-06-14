#!/usr/bin/env fish
#
# update-ips.fish — Refresh WeChat server IP list for the Frida redirect script
#
# Queries WeChat's DNS endpoint via mmtls-cli (--output http), extracts all
# IPv4 and IPv6 addresses from the XML response, and updates the WEIXIN_IPS
# array in android-scripts/config.js.
#
# Usage:  ./android-scripts/update-ips.fish
# Depends: cargo (in workspace), grep

set -l SCRIPT_DIR (dirname (status filename))
cd "$SCRIPT_DIR"

set -l CONFIG_FILE "config.js"
set -l HOST "dns.weixin.qq.com.cn"
set -l REQ_PATH "/cgi-bin/micromsg-bin/newgetdns"

echo "==> Querying WeChat DNS endpoint: $HOST$REQ_PATH"

# Run mmtls-cli with --output http (renders XML response with IPs in <ip> tags)
set -l http_output (cargo run --bin mmtls-cli -- $HOST $REQ_PATH --output http 2>/dev/null)
set -l cargo_exit $status

if test $cargo_exit -ne 0
    echo "Error: mmtls-cli failed (exit code $cargo_exit). Is the workspace built?"
    echo "Run 'cargo build --bin mmtls-cli' first, or check network connectivity."
    exit 1
end

if test -z "$http_output"
    echo "Error: mmtls-cli returned empty output."
    exit 1
end

# Extract all IPv4 addresses (the DNS response uses dotted-decimal)
set -l ipv4_ips (echo "$http_output" | grep -oE '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' || true)

# Extract IPv6 addresses (colon-hex format)
set -l ipv6_ips (echo "$http_output" | grep -oE '\b[0-9a-fA-F:]+:[0-9a-fA-F:]+\b' | string lower || true)

# Merge, deduplicate, sort
set -l all_ips $ipv4_ips $ipv6_ips
set -l sorted_ips (printf '%s\n' $all_ips | sort -Vu)

set -l ip_count (count $sorted_ips)

if test $ip_count -eq 0
    echo "Warning: no IPs found in DNS response. Config will be set to empty."
    echo "This may indicate a network issue or changed API response format."
end

echo "==> Found $ip_count unique IPs"

# Format as JS array entries: "  '1.2.3.4',"
set -l formatted_ips
for ip in $sorted_ips
    set formatted_ips $formatted_ips "  '$ip',"
end

# Build the replacement array text
set -l array_text "const WEIXIN_IPS = ["
if test $ip_count -gt 0
    set array_text "$array_text\n"(string join '\n' $formatted_ips)
end
set array_text "$array_text\n];"

# Replace the WEIXIN_IPS array in config.js using awk
set -l tmpfile (mktemp)
awk -v replacement="$array_text" '
    index($0, "const WEIXIN_IPS = [") == 1 { in_array = 1; print replacement; next }
    in_array && $0 == "]" { in_array = 0; next }
    in_array { next }
    { print }
' "$CONFIG_FILE" > "$tmpfile" && mv "$tmpfile" "$CONFIG_FILE"

# Make sure we don't leave a temp file behind
if test -f "$tmpfile"
    rm -f "$tmpfile"
end

echo "==> Updated $CONFIG_FILE with $ip_count WeChat server IPs"
