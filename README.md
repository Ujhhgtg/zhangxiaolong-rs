# zhangxiaolong-rs

a foss reimplementation of a wechat server, in rust. work in progress.

## crates

### `mmtls` (library)

implementation of mmtls — the custom tls protocol wechat uses (shortlink variant). supports:

- ecdhe + psk handshake flows over tcp
- aes-128-gcm record encryption (traffic keys derived via hkdf)
- ecdsa signature verification
- record-level parsing and pretty-printing of the binary protocol
- shortlink http requests (one-shot tcp connect → handshake → http request → response)
- session caching (tickets)

not implemented: longlink (persistent connection with heartbeats).

### `mmtls-cli` (cli tool)

a debugging tool that sends mmtls requests and prints the response.

```bash
mmtls-cli [--link-mode shortlink] <host> <path> [options]
```

features:

- raw request bytes from file (`--req-file`), or inline/from-file protobuf json (`--req-proto-json`, `--req-proto-json-file`) converted to wire format
- `--output http` to decode the http response and body (with deflate/gzip decompression and syntax highlighting)
- `--pretty-printing` toggle for syntax highlighting (default on, respects `NO_COLOR` and piped output)

examples:

```bash
# send a raw request from file, print hex response
mmtls-cli dns.weixin.qq.com /cgi-bin/micromsg-bin/newgetdns --req-file req.bin

# send protobuf json as request body, parse http response
mmtls-cli dns.weixin.qq.com /cgi-bin/micromsg-bin/newgetdns \
  --req-proto-json '{"1": "hello"}' \
  --output http
```

### `zhangxiaolong` (server)

the wechat server itself. work in progress.
