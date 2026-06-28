# aSuspect

[English](README.md)

<p align="center">
<a><img alt="Logo" width="80%" src="./avatar.webp" /></a>
<br>
易用便携的 Go 轻量级 aTrust VPN 代理核心实现
</p>

## 概述

aSuspect 是一个轻量级的 VPN 代理核心，仅仅开启 SOCKS5 代理服务，需要配合其他工具如 mihomo/singbox 进行分流使用，aSuspect 根据服务器得到的资源信息进行流量转发，不合规的流量会直接丢弃，实现参考 zju 以及 aTrust 二进制。

事情起源于某实现会在电脑中添加根证书，更高的权限应当受到更多的质疑！

cas认证采用了一个叫做 fakeProxy 的工具，可以方便的对无头设别进行认证，理论上也可以为oauth2认证添加支持。

受于 socks5 限制，有 TCP/UDP 以及 DNS 转发，其余流量会被丢弃，如有需要请采用 IP-over-UDP 等方案进行传输。

TCP 流量有两种转发方式，l4quic (l4快连) 以及 l3tun，前者在 TCP 基础上进行传输，速度快，后者在全能的 l3tun 上进行传输，追求速度可以采用 UDP-over-TCP 方案在 l4quic 上进行传输，追求稳定可以采用 l3tun 方案。l3是单连接的，在原版实现中有一个传输池，简而言之就是收集更多流量为一组进行传输，在个人单位的实测并无明显优势，故没有实现。

受限于个人单位认证方式，目前cas认证完好，其他认证以及 SPA 敲门目前只是理论实现，没有测试。

## 快速开始

首次登录：

```bash
./aSuspect -server <server> -auth auth/<type>
```

登陆类型可以通过

```bash
./aSuspect -server <server> -auth-type
```

获取，登录后会保存登陆信息到 `aSuspect_session.json`，后续运行不再需要加入登陆参数。如果迁移需要保留登陆信息，请将 `aSuspect_session.json` 文件拷贝到新环境。

# TODO
- [ ] SPA 敲门验证
- [ ] 其他认证方式验证
- [ ] IPv6 支持