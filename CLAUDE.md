# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Shell one-click installer for proxy cores on Linux VPS. Public repo: `uerax/taffy-onekey` (`origin` → `git@github.com:uerax/taffy-onekey.git`). End users run as **root** on **Debian / Ubuntu / Alpine**. CentOS is explicitly rejected (`centos fuck out!`).

There is **no build system, package manager, or test suite**. No Cursor/Copilot rule files. Validation is manual.

## Commands

```bash
# Syntax check (match shebang: sh vs bash)
sh -n taffy.sh configuration.sh install-mihomo.sh install-mihomo-cn.sh
bash -n taffy-cn.sh install-xray.sh install-singbox.sh
# install-xray-cn.sh / install-yq.sh have no shebang; treat as sh-ish snippets piped remotely

# Optional static analysis
shellcheck -s sh taffy.sh configuration.sh
shellcheck -s bash taffy-cn.sh install-xray.sh

# Interactive (needs root Linux; pulls templates from GitHub raw at runtime)
sudo bash taffy.sh                 # menu
sudo bash taffy.sh install         # one-key Xray
sudo bash taffy.sh singbox         # one-key Sing-box
sudo bash taffy.sh mihomo          # one-key Mihomo
sudo bash taffy.sh uninstall

# China entry (all GitHub URLs via gh-proxy.com)
sudo bash taffy-cn.sh
# README CN: wget via gh-proxy.com then bash taffy-cn.sh

# Share-link / client-snippet dump from already-installed configs
sudo bash configuration.sh xray|singbox|mihomo
```

README remote one-liners (what users actually run):

```bash
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ xray
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ singbox
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ uninstall
```

| Core | Config path | Notes |
|------|-------------|--------|
| Xray | `/usr/local/etc/xray/config.json` | Extra dir `/opt/xray/` |
| Sing-box | `/etc/sing-box/config.json` | Service name `sing-box` |
| Mihomo | `/etc/mihomo/config.yaml` | Base template from `config/Clash/config.yaml` |

## Architecture

### Layers

```
taffy.sh (v4.1.7, #!/bin/sh)     # full product: menu + protocol orchestration
taffy-cn.sh (v3.0.3, bash)       # thinner China fork (duplicated logic, not a wrapper)
  → install-xray.sh / -cn        # binary + unit only (xray from XTLS install lineage)
  → install-singbox.sh           # latest sing-box .deb
  → install-mihomo.sh / -cn      # mihomo package + systemd/OpenRC + base YAML
  → install-yq.sh                # mikefarah/yq (or apk yq on Alpine)
  → config/<Protocol>/…          # templates with ${placeholders}, fetched by URL
  → configuration.sh             # parse live configs → share links / QX / Clash / outbounds
```

- **`taffy.sh`**: Xray + Sing-box + Mihomo, BBR, routing helpers, replace + append flows. Template URLs are `raw.githubusercontent.com/uerax/taffy-onekey/master/config/...`.
- **`taffy-cn.sh`**: Fewer menus/cores (no Sing-box path like main); every GitHub URL prefixed with `gh-proxy.com`. Treat as a **separate** codebase that must be patched independently if behavior should match.
- **`configuration.sh`**: Standalone. Often pulled **remotely** by `show_*_info` via `run_remote_script` (not sourced locally). Walks inbounds with `jq` (Xray/Sing-box) or `yq` (Mihomo `listeners`).
- **`install-*.sh`**: Install binaries/services only; protocol config is owned by `taffy*.sh` + `config/`.

### Critical runtime behavior: templates come from GitHub `master`

Protocol functions **`wget`/`curl` templates from the remote repo**, not from a local checkout path. Editing `config/` on a machine only affects installs after that change is on the branch the URL points at (default: `master`). To test unpublished templates, temporarily point the URL constants at the top of `taffy.sh` (or host files yourself). Same for self-update and remote `configuration.sh`.

External rule packs (not in this repo): `bakasine/rules` (`ukonw_url`, `singbox_route_url`).

### Configure / append pipeline

Shared shape for nearly every protocol function:

1. Secrets: `xray uuid` / `xray x25519`, `sing-box generate …`, `mihomo generate uuid`, `openssl`, urandom passwords.
2. `set_port` + `port_check` (netstat LISTEN).
3. Download template into config path or a temp fragment (`append.json`, YAML snippet).
4. `sed -i` substitute placeholders (`~` delimiter). Keep names lockstep with templates—including the typo **`${pubicKey}`**.
5. Merge if append; build share URL + Clash/QX/outbound strings; `restart_service` + `enable_service`.

**Merge differs by core** (do not copy the wrong one):

| Core | Replace | Append merge |
|------|---------|--------------|
| Xray | overwrite `config.json` | fragment + `xray run -confdir=./ -dump > config.json` (some paths use `jq '.inbounds += [input]'`) |
| Sing-box | overwrite `config.json` | `sing-box merge tmp.json -c config.json -c append.json` then rename |
| Mihomo | often rewrite listeners | several `*_append` functions simply call the full install helper; `mihomo_clear_listeners` truncates after `listeners:` via `sed` |

Default REALITY / self-signed SNI target is hard-coded **`www.python.org`** in many functions and templates.

`open_bbr` downloads `config/BBR/sysctl.conf` and **writes it over `/etc/sysctl.conf` entirely** (not a drop-in snippet)—then `sysctl -p`.

### Cross-cutting utilities (`taffy.sh`)

- **OS**: `get_system` → `/etc/os-release`; `PKG_MANAGER` = `apt install -y` or `apk add --no-cache`.
- **Services**: `_exec_service_action` prefers systemd → OpenRC → `service` → `/etc/init.d`. Prefer `start_service` / `restart_service` / `enable_service` / `service_is_active` over raw systemctl (Alpine).
- **Remote**: `run_remote_script url [args…]` pipes curl/wget into bash/sh.
- **UI**: `info`/`ok`/`warn`/`error`/`judge`; menus use `printf` + `read -r` (not `read -p`) for Alpine/POSIX. Prefer `printf` when editing `#!/bin/sh` files.

### Primary menus in `taffy.sh` (protocol surface)

| Core | Replace (onekey / 更换) | Append (插入) |
|------|-------------------------|---------------|
| Xray | reality-tcp/grpc/h2, redirect, shadowsocket | ss, socks5, redirect, reality-tcp/grpc |
| Sing-box | hy2, reality-tcp/grpc/h2, ss, redirect | ss, hy2, reality-tcp/grpc, redirect |
| Mihomo | ss, reality-grpc/tcp, hy2, redirect | same set |

README-advertised set: hysteria2, vless reality (tcp/grpc/h2), shadowsocket-2022. Older dirs (`Trojan*`, `VLESS-WS-TLS`, `VMESS-WS-TLS`, `Naive`, …) are template leftovers, not the main menu path.

Template naming under `config/<Family>/`: `config.json`/`append.json` (Xray), `singbox.json`/`singbox_ap.json` (Sing-box), `mihomo.yaml` (listener fragment), occasional `nginx.conf` for legacy TLS fronts. `config/Clash/config.yaml` is Mihomo **server** base (listeners), not a client profile.

## Conventions when editing

- **Placeholder lockstep**: every `${…}` in templates must match `sed` in `taffy.sh` / `taffy-cn.sh` (and vice versa). Do not “fix” `${pubicKey}` without updating both.
- **Four-way protocol changes**: replace function, `_append` sibling (if any), outbound builder, and `configuration.sh` parser branch for that inbound type.
- **URL constants** at the top of `taffy.sh` / `taffy-cn.sh` must match `config/` paths; CN must keep `gh-proxy.com` prefixes.
- **Shebang discipline**: no bashisms in `#!/bin/sh` files (`taffy.sh`, `configuration.sh`, mihomo installers). `taffy-cn.sh` and `install-xray.sh` are bash.
- **README caveat**: share links may fail client import—fix generation in `configuration.sh` / outbound builders first.
- **Do not assume local `config/` is used at runtime** until URLs are pointed at it or changes are published to the URL’s branch.
