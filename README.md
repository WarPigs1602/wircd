# wircd (ircu2.10-based IRC daemon)

`wircd` is a fork of the Undernet IRC daemon (`ircu2.10`).
It provides a full IRC server with P10 server-link support, classic client and
operator command handling, multiple scalable event engines, optional TLS
backends, and runtime-configurable behavior through feature settings.

## Table of contents

- [Overview](#overview)
- [Compatibility](#compatibility)
- [Quick start](#quick-start)
- [First-time bring-up (practical)](#first-time-bring-up-practical)
- [Implemented functionality](#implemented-functionality)
- [Command coverage](#command-coverage)
- [Operations and maintenance](#operations-and-maintenance)
- [Platform-specific notes](#platform-specific-notes)
- [Documentation and references](#documentation-and-references)
- [Repository structure](#repository-structure)
- [Historical notes](#historical-notes)
- [License](#license)

## Overview

### At a glance

- Protocol family: **P10** (server-to-server)
- Upstream lineage: **ircu2.10.12**
- Repository patch level: `19+wircd(1.0)` (see `include/patchlevel.h`)
- Configuration format: block-based `ircd.conf` syntax (see `doc/example.conf`)
- Build system: autotools-style (`configure` + `make`)

### Legacy highlights from ircu2.10.12

Historical upstream notes for `ircu2.10.12` highlight three major improvements
that remain relevant in this code line:

- Rewritten network event subsystem with asynchronous poller support.
- Runtime-tunable features (`F:` lines / `Feature`) via `GET`/`SET`.
- P10 account propagation behavior to improve service continuity across
  netsplits.

## Compatibility

- This codebase includes feature work derived from
  [nefarious](https://github.com/evilnet/nefarious2) and
  [snircd](https://codeberg.org/quakenet/snircd).
- User account handling is intended to remain compatible with snircd account
  semantics used by services integrations.
- Server-to-server compatibility is limited to **P10-speaking peers**.
- Some protocol/runtime features are only fully available between
  `ircu2.10.12`-compatible implementations.
- Compatibility statements in this repository are behavioral targets and should
  be validated in your own deployment topology (services, link peers, policy).

## Quick start

### 1) Build

```bash
./configure
make
make install
```

### 2) Prepare configuration

- Use `doc/example.conf` as your baseline template.
- Create/adjust runtime `ircd.conf` (server name, numerics, classes,
  client/server blocks, operators, feature toggles).
- If migrating from old `2.10.11` style config, use `convert-conf`.

### 3) Run

- Start the daemon with your configured paths/environment.
- Verify listener and startup behavior using logs and basic IRC checks:
  `/LUSERS`, `/MAP`, `/STATS`, `/VERSION`.

## First-time bring-up (practical)

Recommended sequence for a safe first deployment:

1. Derive a minimal configuration from `doc/example.conf`.
2. Enable only listeners, base classes, and one operator account.
3. Start the daemon and check logs for parser/bind errors.
4. Connect with an IRC client and validate `/LUSERS`, `/VERSION`, `/STATS`.
5. Add server-link blocks and optional features only after baseline validation.
6. Validate feature changes incrementally via `GET`/`SET`.

## Implemented functionality

Capabilities are implemented in `ircd/` and declared in `include/`.

### Core server runtime

- Connection accept/listen lifecycle
- Packet parsing and send/receive queueing
- Server registration and relay logic
- DNS resolver subsystem (`ircd_res.c`, `ircd_reslib.c`)
- Memory and utility layers (`ircd_alloc`, snprintf/string helpers)
- Hash/list management for runtime objects (clients/channels/state)

### Event engine support

Platform-oriented polling backends:

- `engine_select.c`
- `engine_poll.c`
- `engine_epoll.c`
- `engine_kqueue.c`
- `engine_devpoll.c`

### TLS and crypto

Build-dependent TLS providers:

- OpenSSL (`tls_openssl.c`)
- GnuTLS (`tls_gnutls.c`)
- libtls (`tls_libtls.c`)
- no-TLS stub (`tls_none.c`)

Credential/hash helpers:

- Multiple oper password mechanisms (`ircd_crypt_*`)
- MD5 helpers (`ircd_md5.c`, `md5.c`)
- Password generation utility (`ircd/umkpasswd.c`)

### Identity and policy controls

- Host hiding/cloaking support (`cloak.c`, related headers)
- IP validation and checking (`IPcheck.c`)
- Silence lists (`m_silence.c`)
- G-line and jupe handling (`gline.c`, `jupe.c`, command handlers)
- Runtime feature toggles (`ircd_features.c`, `doc/readme.features`)

## Command coverage

Command handlers are implemented as dedicated `m_*.c` modules.

### Client/session commands

`PASS`, `NICK`, `USER`, `QUIT`, `PING`, `PONG`, `AWAY`, `AUTHENTICATE`,
`CAP`, `TAGMSG`

### Messaging commands

`PRIVMSG`, `NOTICE`, `CPRIVMSG`, `CNOTICE`, `WALLOPS`, `WALLCHOPS`,
`WALLUSERS`, `WALLVOICES`

### Channel commands

`JOIN`, `PART`, `MODE`, `TOPIC`, `NAMES`, `INVITE`, `KICK`, `LIST`,
`CREATE`, `CLEARMODE`

### Discovery/statistics commands

`WHO`, `WHOIS`, `WHOWAS`, `USERHOST`, `USERIP`, `ISON`, `LUSERS`, `MAP`,
`LINKS`, `TRACE`, `STATS`

### Server/link commands

`SERVER`, `SQUIT`, `CONNECT`, `BURST`, `ENDBURST`, `PROTO`, `ERROR`

### Operator/admin commands

`OPER`, `KILL`, `GLINE`, `JUPE`, `OPMODE`, `REHASH`, `RESTART`, `DIE`,
`ADMIN`, `INFO`, `VERSION`, `TIME`, `SET`, `GET`, `RESET`, `CHECK`, `HELP`

### Service/query commands

`ACCOUNT`, `PSEUDO`, `XQUERY`, `XREPLY`

### Diagnostic/utility commands

`RPING`, `RPONG`, `UPING`, `SETHOST`, `SETTIME`, `MOTD`, `DEFAULTS`,
`DESTRUCT`, `DESYNCH`

## Operations and maintenance

### Upgrade notes

- The repository ships migration tooling for older configs (`convert-conf`).
- Upstream `RELEASE.NOTES` documents semantic/config changes across versions.

### Build and toolchain notes

- Preferred toolchain: GNU `make` + `gcc` (see `INSTALL`)
- Inspect build options with `./configure --help`
- Event engine and TLS availability depend on platform and build configuration

### Performance tuning (general)

- Use high-scale pollers (`epoll`, `kqueue`, `/dev/poll`) where available.
- Tune file descriptor and kernel/network limits for expected load.
- Keep DNS resolvers low-latency/nearby for high connect rates.
- Prefer lean, dedicated hosts for large populations.

### Time synchronization (critical)

Clock drift between IRC servers can cause severe protocol and operational
issues. Run time synchronization (`ntpd` or equivalent modern NTP service) on
all servers.

### Information hiding defaults

Legacy `ircu2.10.12` behavior defaults to hiding selected information from
non-operator users (historically HIS defaults). Override via `ircd.conf`
feature controls if your policy differs.

### Troubleshooting (quick entry points)

- Build/config issues: `INSTALL`
- Feature behavior: `doc/readme.features`
- Server/network behavior: `doc/features.txt`, `doc/readme.*`

## Platform-specific notes

### Linux

- Linux `2.6+` supports `epoll`, which scales much better than classic poll
  loops.
- Ensure user/global descriptor limits are high enough for expected concurrency.

### FreeBSD

- Use `kqueue` where available for improved event-loop performance.
- Typical boot-time tuning examples from legacy notes:

```sh
sysctl -w kern.maxfiles=16384
sysctl -w kern.maxfilesperproc=16384
sysctl -w net.inet.tcp.rfc1323=1
sysctl -w net.inet.tcp.delayed_ack=0
sysctl -w net.inet.tcp.restrict_rst=1
sysctl -w kern.ipc.maxsockbuf=2097152
sysctl -w kern.ipc.somaxconn=2048
```

- Additional historical guidance referenced `maxusers`, `NMBCLUSTERS` and ICMP
  tuning for very high-scale systems.

### Solaris

- Use `/dev/poll` on supported releases for better scalability than `poll()`.
- Legacy `/etc/system` examples for descriptor limits:

```conf
set rlim_fd_max = 16384
set rlim_fd_cur = 8192
```

- On older Solaris 7 environments, `/dev/poll` required vendor patching per
  historical documentation.

## Documentation and references

### Primary configuration references

- `doc/example.conf` — canonical configuration template
- `doc/readme.features` — runtime feature toggles (`Feature`/F-line behavior)
- `doc/readme.iauth` — external authorization protocol
- `doc/snomask.html` — server notice mask behavior

### Recommended configuration workflow

1. Start from a minimal leaf-style config.
2. Validate listener, client class and operator access.
3. Add server-link blocks and hub/leaf policy carefully.
4. Enable optional features incrementally and monitor effects.

### Documentation map

- Build/install process: `INSTALL`
- Release changes: `RELEASE.NOTES`
- Feature matrix and numerics: `doc/features.txt`
- Runtime feature switches: `doc/readme.features`
- Base configuration template: `doc/example.conf`

## Repository structure

- `ircd/` — daemon core, command handlers, protocol, engines, TLS backends
- `include/` — headers, feature declarations, protocol definitions
- `doc/` — configuration examples and operator/admin documentation
- `tests/` — test-related assets
- `tools/` — helper utilities/scripts
- `patches/` — optional patch material and references

## Historical notes

Operational sections in this document are adapted from upstream
`ircu2.10.12` materials (including platform tuning guidance authored in 2002).
Treat numeric values and OS-specific commands as historical baselines and
validate against modern OS documentation before production use.

## License

See `LICENSE` in the repository root.
