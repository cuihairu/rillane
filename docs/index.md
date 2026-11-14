---
layout: home

hero:
  name: Rillane
  text: One proxy kernel, three scenarios
  tagline: General proxy / game acceleration / web acceleration share a single datapath (ingress -> routing -> egress/transport), obfuscation is a cross-cutting layer. Rust monorepo, inspired by sing-box / Clash / Surge, protocol stack split per crate.
  image:
    src: /logo.svg
    alt: Rillane logo
  actions:
    - theme: brand
      text: Architecture overview
      link: /architecture
    - theme: alt
      text: Protocol support
      link: /PROTOCOLS
    - theme: alt
      text: Design docs
      link: /design/positioning
    - theme: alt
      text: GitHub
      link: https://github.com/cuihairu/rillane

features:
  - title: General proxy
    details: socks5/http/mixed ingress, direct/socks5/http/shadowsocks/trojan/hysteria2/vmess/vless/wireguard egress, rule-based routing, group-policy path selection and subscription hot reload.

  - title: Game acceleration
    details: NAT-style UDP session table (P0-1) + SOCKS5 UDP ASSOCIATE (P0-2) + direct/ss/wg UDP underlay (P0-3) + mesh multi-hop UDP plane (P0-4) all landed; UDP observability and config (P0-5) include the /udp/stats snapshot and the rillane_udp_* metric family.

  - title: Web acceleration
    details: mesh multi-hop chains with mandatory mTLS, 7 group policies, failover and Dry Run pre-checks; egress connection pool + TLS session resumption landed (P1-5, inspectable at /egress/pool/stats).

  - title: One kernel
    details: the three scenarios share one datapath, scenario differences collapse into route rules and policy profiles (P2-3 presets), no separate code path -- acceleration = routing + disguise, obfuscation = slipping past detection.

  - title: Mesh cooperation
    details: registration / heartbeat and offline detection / topology / ACLs and quotas; client -> relay -> exit multi-hop forwarding, CA rotation and dual trust windows (rillanectl mtls).

  - title: Observability
    details: /metrics Prometheus metrics + Grafana template, one-shot rillanectl stats / diagnose, chain Dry Run policy simulation.
---
