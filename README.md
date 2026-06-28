# aSuspect

[中文](README_zh.md)

<p align="center">
<a><img alt="Logo" width="80%" src="./avatar.webp" /></a>
<br>
A lightweight, portable, and easy-to-use aTrust VPN proxy core implemented in Go
</p>

## Overview

aSuspect is a lightweight VPN proxy core that only starts a SOCKS5 proxy service. It needs to be used with other tools like mihomo/singbox for traffic splitting. aSuspect forwards traffic based on resource information obtained from the server — non-compliant traffic is simply dropped. The implementation references ZJU and aTrust binaries.

It all started because some implementations install root certificates on your computer — greater privileges deserve greater scrutiny!

CAS authentication uses a tool called fakeProxy, which enables easy authentication for headless devices and could theoretically support OAuth2 authentication as well.

Due to SOCKS5 limitations, only TCP, UDP, and DNS forwarding are supported; other traffic will be dropped. If needed, use IP-over-UDP or similar solutions for transport.

TCP traffic has two forwarding modes: l4quic (L4 fast connection) and l3tun. The former transmits over TCP for higher speed, while the latter uses the versatile l3tun tunnel. For speed, use UDP-over-TCP over l4quic; for stability, use l3tun. L3 is single-connection — the original implementation has a transport pool that groups more traffic into batches, but personal testing showed no significant advantage, so it was not implemented.

Limited by personal authentication access, CAS authentication is currently working well. Other authentication methods and SPA knocking are only theoretical implementations at this stage and have not been tested.

## Quick Start

First login:

```bash
./aSuspect -server <server> -auth auth/<type>
```

To list available auth types:

```bash
./aSuspect -server <server> -auth-info
```

After login, session info is saved to `aSuspect_session.json`, and subsequent runs no longer require login parameters. If migrating, copy the `aSuspect_session.json` file to the new environment.

## TODO
- [ ] SPA knocking verification
- [ ] Other authentication method verification
- [ ] IPv6 support
