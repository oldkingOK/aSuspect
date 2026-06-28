# aSuspect

Lightweight aTrust VPN proxy implemented in Go.

## Architecture

- `auth/`: authenticator implementations.
- `gatherer/`: `InfoGatherer` and `SessionStore`; fetches `clientResource` and builds shared state.
- `l4quic/`: L4 TCP tunnel using TLS and binary framing, one TLS connection per TCP connection.
- `l3tun/`: L3 tunnel using gVisor netstack, TLS, and conntrack.
- `proxy/`: SOCKS5 server, routing, DNS resolver, and tunnel orchestration.
- `spa/`: Single Packet Authorization ClientHello extension support.
- `shared/`: shared config and domain types.

gVisor provides the userspace TCP/IP stack. TCP can use the L4 tunnel for lower overhead, while DNS and L3 traffic use the L3 tunnel.

## Session Flow

First login:

```bash
./aSuspect -server <server> -auth auth/psw
```

The login flow saves `aSuspect_session.json`.

Later runs:

```bash
./aSuspect -server <server>
```

The saved session is loaded, resources are gathered, and the local SOCKS5 proxy starts.
