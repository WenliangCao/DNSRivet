# DNSRivet

> Compact encrypted DNS forwarding for macOS 11 or later.

English | [中文](#中文)

DNSRivet is a small, single-process DNS daemon written in Rust. It accepts
local UDP and TCP queries, forwards them over encrypted transports, and keeps
the hot path deliberately narrow.

**Platform status: macOS only.** DNSRivet is not a cross-platform DNS client.
Its service lifecycle and system DNS integration are built specifically for
macOS and `launchd`.

One binary. One runtime thread. No telemetry. No control plane.

## Core

- DoH, DoH3, DoT, DoQ, and conventional UDP/TCP upstreams
- Persistent multiplexed encrypted connections
- Ordered failover with hedging, per-upstream timeouts, and exponential reconnect backoff
- Direct fallback to system DNS only when every configured upstream fails to return a DNS response
- Bootstrap resolution that bypasses the system resolver to prevent loops
- Local UDP and pipelined TCP listeners with bounded concurrency
- 4,096-entry LRU cache by default, with wire-level TTL aging
- RFC 2308 negative caching and EDNS-aware UDP truncation
- Transactional system DNS takeover and restoration
- Native `launchd` service management
- One-line CLI configuration backed by the same TOML validation path

## 0.4.1 changes

- After macOS sleeps, encrypted upstreams drop their connection and re-resolve
  the bootstrap address before the next query, instead of sending into a stale
  connection until the deadline and falling back to plaintext system DNS
- Update `webpki-roots` to 1.0.11, which removes the emSign Root CA - C1 and
  emSign ECC Root CA - C3 trust anchors
- Refresh dependencies, including tokio 1.54.1, quinn 0.11.12, h2 0.4.20, and
  lru 0.19

0.4.0 moved encrypted transports to patched Hickory releases and hardened
failover, caching, and service lifecycle handling.

## Runtime profile

The release profile is optimized for size with LTO, a single codegen unit,
symbol stripping, and abort-on-panic behavior.

| Measurement | Observed value |
| --- | ---: |
| Stripped arm64 binary | 2,606,376 bytes (2.49 MiB) |
| Stripped x86_64 binary | 3,042,976 bytes (2.90 MiB) |
| RSS after a fresh DoH3 connection | 4,656 KiB |
| RSS after load and about four minutes | 4,912 KiB |
| Tokio runtime threads | 1 |
| Cached UDP latency, p50 / p95 | 0.087 / 0.112 ms |
| Unique DoH3 latency, p50 / p95 | 8.72 / 9.92 ms |

Binary sizes were measured on 2026-11-09 before Developer ID signing. Other
measurements were taken on Apple Silicon with macOS 27.0 using 200 cached queries and 40
unique queries against a public DoH3 endpoint. These numbers describe one
development machine and network path; they are not universal guarantees.

### Repeatable local performance checks

Compare two release binaries without changing system DNS or using public resolvers:

```bash
python3 scripts/benchmark-local.py \
  --binary before=/path/to/before/dnsrivet \
  --binary after=target/release/dnsrivet \
  --queries 30000 --samples 3 --concurrency 1 32 \
  --json target/benchmark.json
```

This measures cached UDP and one-/two-upstream legacy forwarding, alternating
binary order. Add `--mode tcp-cached` to measure persistent TCP cache hits.
It reports p50/p95, throughput, daemon CPU time per query, and RSS.
The Python load generator and OS scheduling can limit throughput; compare repeated
runs on the same machine rather than treating these as maximum-capacity results.
CPU time includes startup and shutdown, amortized over the query count.

Focused in-process checks (prefix Cargo commands with `mbx` when using its cache):

```bash
mbx test --release benchmark_cache_hits -- --ignored --nocapture
mbx test --release benchmark_wire_validation -- --ignored --nocapture
mbx test --release benchmark_encrypted_dispatch -- --ignored --nocapture
```

The encrypted benchmark measures warm local dispatch, not TLS or network latency.
The cache benchmark measures repeated hits; TTL aging happens once per elapsed
whole second per entry, retaining its original expiration deadline.

## Build

Requirements: macOS 11 or later and stable Rust.

```bash
git clone https://github.com/WenliangCao/DNSRivet.git
cd DNSRivet
mbx test --all-targets --all-features
mbx build --release
./target/release/dnsrivet version
```

## Install

DNSRivet supports two alternative installation methods. Do not combine them
on the same machine.

### Signed macOS package

Download `DNSRivet-*.pkg` from the
[latest release](https://github.com/WenliangCao/DNSRivet/releases/latest) and
open it in Finder. The signed and notarized installer places the universal
Apple Silicon/Intel binary on the system, but deliberately does not choose an
upstream or take over DNS. Configure and start it explicitly:

```bash
sudo dnsrivet start \
  --upstream 'doh3=https://resolver.example/profile'
```

Installing a newer PKG restarts an already running DNSRivet service while
preserving its configuration and DNS backup. If the restart or DNS probe fails
(for example while offline), installation succeeds and prints recovery commands.

### Homebrew

```bash
brew install dnsrivet/tap/dnsrivet
sudo dnsrivet start \
  --upstream 'doh3=https://resolver.example/profile'
```

The tap installs the signed universal binary from the GitHub release. If Homebrew
refuses to load a non-official tap, trust it first with
`brew trust --tap dnsrivet/tap`.

After an upgrade, explicitly load the new binary into the system service:

```bash
brew upgrade dnsrivet
sudo dnsrivet restart
```

Before removing the formula, restore system DNS and remove the launchd service:

```bash
sudo dnsrivet uninstall
brew uninstall dnsrivet
```

## Run in the foreground

For a one-line test, pass the listener and one or more ordered upstreams directly:

```bash
./target/release/dnsrivet run \
  --listen 127.0.0.1:5354 \
  --upstream 'doh3=https://resolver.example/profile'
```

Each upstream uses `TYPE=ENDPOINT`; repeat `--upstream` to define failover order.
The accepted types are `doh`, `doh3`, `dot`, `doq`, and `legacy`.

To keep the configuration as TOML, generate and validate it from the same CLI
options:

```bash
./target/release/dnsrivet config init \
  --upstream 'doh3=https://resolver.example/profile'
./target/release/dnsrivet config check --config dnsrivet.toml
```

`config init` refuses to replace an existing file unless `--force` is present.
Generated files use mode `0600`.

Copy the example and set the listener port to `5354` when testing without root:

```bash
cp example.config.toml dnsrivet.toml
./target/release/dnsrivet run --config dnsrivet.toml
dig @127.0.0.1 -p 5354 example.com A
dig @127.0.0.1 -p 5354 +tcp example.com AAAA
```

`run` never changes system DNS settings. Without `--config`, DNSRivet checks:

1. `./dnsrivet.toml`
2. `/Library/Application Support/DNSRivet/config.toml`

## Install as a macOS service

Service mode requires a loopback listener on port 53, normally
`127.0.0.1:53`. Replace the documentation-only upstream endpoints in the
example configuration before starting the service.

```bash
sudo ./target/release/dnsrivet start \
  --upstream 'doh3=https://resolver.example/profile'
dnsrivet status
sudo dnsrivet restart
sudo dnsrivet stop
sudo dnsrivet uninstall
```

`start` validates the configuration and ports, installs the binary and config,
loads `io.github.wenliangcao.dnsrivet` through `launchd`, probes the local DNS
listener, then backs up and replaces DNS settings for each active network
service. A partial failure rolls back services already changed.

The first successful `start` installs a stable command at
`/usr/local/bin/dnsrivet` unless that command is already the package-manager
entry which invoked DNSRivet. It never replaces an unrelated path, and removes
the link only if DNSRivet owns it.

Installed state lives under `/Library/Application Support/DNSRivet/`. The DNS
backup is written atomically with mode `0600`; without that backup, DNSRivet
will not guess how to rewrite existing DNS settings. Service commands use the
installed configuration, explicit `--config`, or CLI options; they never import
`./dnsrivet.toml` implicitly. Logs are written to `/var/log/dnsrivet.log` with mode
`0640`. Connection messages are debug-only; dependency logs are limited to errors.
The service permits 4,096 file descriptors and at most 64 client TCP connections.

When upgrading an older installation, run `sudo dnsrivet stop` followed by
`sudo dnsrivet start` once to load the new launchd resource limits, startup
recovery environment, and network-location backup metadata.

Logs are not automatically rotated. To rotate without leaving a running process
writing into a renamed file, stop the service, archive its log, then start it:

```bash
sudo dnsrivet stop
sudo mv /var/log/dnsrivet.log /var/log/dnsrivet.log.previous
sudo dnsrivet start
```

For a service startup error (invalid configuration, logger or listener failure),
the managed daemon attempts to restore the original DNS before exiting. This
cannot run if the binary is missing or blocked, or if macOS Safe Mode does not
launch it. First try `sudo dnsrivet stop`. If the binary cannot run, list services
with `networksetup -listallnetworkservices`; for a service that normally uses
DHCP DNS, restore automatic DNS with `sudo networksetup -setdnsservers "Wi-Fi" Empty`.
For static DNS, restore the known addresses from the backup instead.

A backup records its macOS network location. Stop DNSRivet before switching
locations. If already switched, return to the backed-up location and stop there;
the watchdog and restoration refuse to apply that location's settings elsewhere.
Older backups remain readable, but lack this location check until recreated.

`start`, `stop`, `restart`, and `uninstall` are serialized across processes.
`stop` restores DNS and disables the job while preserving the installed binary,
configuration, and property list. If a renamed or untracked network service
still points at DNSRivet, it retains the backup and refuses to stop rather than
leave a dead resolver. Restore that service's known DNS settings or its original
name, then retry. `uninstall` also removes the installed binary
and `/Library/LaunchDaemons/io.github.wenliangcao.dnsrivet.plist`. User
configuration remains intact.

Install a replacement TOML atomically with:

```bash
sudo dnsrivet restart --config dnsrivet.toml
```

If the new service fails its DNS probe or cannot verify an active system DNS
takeover, DNSRivet restores the previous config and restarts it.

Before taking over macOS DNS, DNSRivet snapshots the effective system DNS
servers. If every configured upstream fails to return a DNS response, it queries those
servers directly with a two-second bound per server. A configured SERVFAIL is
returned if no other configured upstream succeeds; it never triggers system
fallback. Answers from system fallback are not cached. Loopback and self-listener addresses are
discarded, so the fallback cannot recurse through DNSRivet. If no usable
pre-takeover server exists, exhaustion still returns `SERVFAIL`.

While the service runs, a takeover watchdog re-checks every two minutes
(immediately on daemon start) that each backed-up network service still
points exactly at the takeover address. macOS updates are known to rewrite
network preferences and silently drop the takeover; the watchdog detects
that, captures the network's current DNS as a fresh runtime fallback, and
re-applies the takeover. Original per-service DNS settings are never replaced;
new services and takeover-address history are saved before further DNS changes.
If an external tool keeps rewriting DNS, the watchdog backs off to a 30-minute
cadence and says so in the log instead of fighting it.

If macOS reports an enabled network service that was not present at startup,
the watchdog records that service's original DNS settings before pointing it
at DNSRivet. `stop` restores those settings together with the original
services. The watchdog skips subprocess checks when network preferences and the takeover
marker have not changed. A new service already using a takeover address is
skipped with a warning, allowing other services to be repaired without inventing
its original DNS settings.

A lightweight route-source check runs once per second. After a source change,
DNSRivet reads DHCP DNS from the selected interface with `ipconfig`, even while
`scutil` exposes only the takeover resolver. Watchdog checks also refresh from
non-loopback global resolvers when available. If neither source exposes usable
servers, the previous list is retained. A network change that keeps the same
source address, DHCPv6-only DNS, or VPN-scoped DNS may not be detected by the DHCP
refresh; captive portal access is not guaranteed. Use `sudo dnsrivet stop` to
restore the network's resolver when necessary.

## Configuration

```toml
[service]
log_level = "info"
log_path = ""
cache_enable = true
cache_size = 4096

[listener.0]
ip = "127.0.0.1"
port = 53

[upstream.0]
name = "Primary DoH3"
type = "doh3" # doh | doh3 | dot | doq | legacy
endpoint = "https://resolver.example/dns-query"
bootstrap_ip = ""
timeout = 5000 # milliseconds; omitted = 5000
ip_stack = "both" # both | v4 | v6
```

For foreground listeners reachable from other hosts, bind a specific interface
address instead of `0.0.0.0` or `::`; wildcard UDP listeners may reply from a
different source address on machines with multiple interfaces. Configuration
validation warns about non-loopback listeners.

An explicit `timeout = 0` disables the timeout and is a dangerous advanced
option: when the first upstream black-holes traffic (drops packets without
refusing), that query never reaches later upstreams or the system fallback,
and sustained load hangs queries one by one until the in-flight budget of 512
is exhausted and further UDP queries are dropped. Use it only when the first
upstream's reachability is fully trusted.

Failover is hedged: when an upstream has not answered within 300 ms, the next
upstream is queried in parallel and the first valid non-SERVFAIL answer wins.
Losing legacy attempts are cancelled; encrypted attempts keep running to their
own timeout so stalled connections still back off. All attempts, including
background losers and system fallback, share a 512-attempt budget. Upstreams
with `timeout = 0` are never raced. Hedging means a later upstream can see a
query the first one would have answered slowly, so order upstreams you are
equally willing to send queries to. Prefer `doh` before `doh3` for steadier first
queries after idle periods; DoH3 peers may close idle QUIC connections after
30 seconds. QUIC keep-alive and 0-RTT are not enabled.

See [`example.config.toml`](example.config.toml) for the complete annotated
example. DoH and DoH3 default to port 443; DoT and DoQ default to 853;
conventional DNS defaults to 53.

The cache accepts standard single-question recursive queries, preserves each
client's question casing, and stores responses up to 4,096 bytes. `cache_size`
is limited to 16,384 entries. Queries with EDNS options, a non-zero EDNS version,
`RD=0`, or answer/authority records bypass the cache. Unsupported encrypted
query shapes are rejected locally as described below. Cache keys include the canonical name, record
type, class, EDNS presence, and DNSSEC request bits. Negative answers expire at
the shorter of SOA TTL and SOA.MINIMUM, capped at 600 seconds without extending
short TTLs; a zero TTL is not cached.

A QUERY carrying more than one question is answered locally with a
header-only FORMERR and never forwarded (RFC 9619). Question-less queries
such as RFC 7873 cookie probes can be forwarded when only `legacy` upstreams are
configured. With encrypted upstreams configured, malformed queries receive
FORMERR and unsupported shapes (including zero questions, non-QUERY opcodes,
and non-OPT resource records/signatures) receive NOTIMP locally. Packets with
QR=1 are discarded. Every upstream and
fallback response must echo the query's question before it is returned or
cached (RFC 5452).

## Security boundary

- DNSRivet encrypts transport to compatible upstreams; it does not perform
  local DNSSEC validation.
- System fallback may use conventional unencrypted DNS, depending on the
  pre-takeover macOS configuration.
- Takeover is guarded by a periodic watchdog; between checks there is a
  window (up to the check interval) in which an externally cleared takeover
  leaves queries on the system's own DNS.
- VPN and Network Extension scoped resolvers are outside the takeover and are
  never used as fallback servers.
- DHCP fallback refresh depends on a change in route source address and an
  interface exposing DHCP DNS; otherwise the prior fallback may remain in use.
- Local names (including unicast `.local` and `.lan` queries) are forwarded to
  configured upstreams. There is no split DNS routing for private names; a public
  upstream may receive them and fail to resolve them. Configure an appropriate
  resolver if local names are required.
- The daemon runs as root for port 53 and system DNS management.
- Debug logs can contain queried domain names and complete upstream URLs.
- Service commands modify system-wide `launchd` and network DNS state and
  therefore require `sudo`.
- The source intentionally refuses to compile for non-macOS targets.
- Dependency advisories, input constraints, and audit exceptions are documented
  in [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).

---

## 中文

> 面向 macOS 11 及后续版本的紧凑型加密 DNS 转发器。

DNSRivet 是一个以 Rust 编写的小型单进程 DNS 守护程序。它接收本机 UDP/TCP
查询，通过加密传输转发，并尽量缩短高频路径。

**平台状态：目前仅支持 macOS。** DNSRivet 不是跨平台 DNS 客户端；服务生命周期、
系统 DNS 接管和恢复均针对 macOS 与 `launchd` 实现。

单一二进制。单运行时线程。无遥测。无控制平面。

## 核心能力

- 支持 DoH、DoH3、DoT、DoQ 和传统 UDP/TCP 上游
- 加密连接持久化并复用
- 带对冲的顺序故障转移、独立超时和指数退避重连
- 所有配置上游均未返回 DNS 应答时，才直接回退到系统 DNS
- bootstrap 解析绕过系统 resolver，避免 DNS 自环
- UDP/TCP 本地监听、有界并发及 TCP 查询流水线
- 默认 4,096 项 LRU 缓存，直接在 DNS wire 层递减 TTL
- RFC 2308 负缓存和 EDNS 感知的 UDP 截断
- 事务式接管和恢复系统 DNS
- 原生 `launchd` 服务管理
- 一行终端参数配置，并与 TOML 共用同一套校验逻辑

## 0.4.1 更新

- macOS 睡眠唤醒后，加密上游会先丢弃旧连接并重新解析 bootstrap 地址再发送下一个
  查询，不再把查询发进已失效的连接直到超时、再回退到明文系统 DNS
- 将 `webpki-roots` 更新至 1.0.11，移除 emSign Root CA - C1 与 emSign ECC Root
  CA - C3 两个根证书
- 更新依赖，包括 tokio 1.54.1、quinn 0.11.12、h2 0.4.20 与 lru 0.19

0.4.0 已将加密传输迁移到修复后的 Hickory 版本，并加固了故障转移、缓存与服务生命
周期处理。

## 运行开销

release 配置启用 LTO、单 codegen unit、符号剥离和 panic abort，以控制体积。

| 测量项 | 实测值 |
| --- | ---: |
| 剥离后的 arm64 二进制 | 2,606,376 bytes（2.49 MiB） |
| 剥离后的 x86_64 二进制 | 3,042,976 bytes（2.90 MiB） |
| 新建 DoH3 连接后的 RSS | 4,656 KiB |
| 负载结束约四分钟后的 RSS | 4,912 KiB |
| Tokio 运行时线程 | 1 |
| UDP 缓存命中延迟 p50 / p95 | 0.087 / 0.112 ms |
| 唯一 DoH3 查询延迟 p50 / p95 | 8.72 / 9.92 ms |

二进制体积于 2026-11-09 在 Developer ID 签名前测量。其他数据来自 Apple Silicon、
macOS 27.0 开发机，测试包含 200 次缓存查询和 40 次
经公共 DoH3 端点的唯一查询。具体数值会随机器与网络路径变化。

## 构建与前台运行

需要 macOS 11 或更高版本以及稳定版 Rust：

```bash
mbx test --all-targets --all-features
mbx build --release
cp example.config.toml dnsrivet.toml
./target/release/dnsrivet run --config dnsrivet.toml
```

也可以完全用一行参数启动：

```bash
./target/release/dnsrivet run \
  --listen 127.0.0.1:5354 \
  --upstream 'doh3=https://resolver.example/profile'
```

每个上游使用 `TYPE=ENDPOINT` 格式；重复 `--upstream` 即可定义故障转移顺序。
如果希望保存为文件，可以使用同一组参数生成并验证 TOML：

```bash
./target/release/dnsrivet config init \
  --upstream 'doh3=https://resolver.example/profile'
./target/release/dnsrivet config check --config dnsrivet.toml
```

如果目标文件已存在，`config init` 默认拒绝覆盖，只有显式加入 `--force` 才会替换；
生成文件权限为 `0600`。

非 root 调试时，请先把监听端口改成 `5354`。`run` 不修改系统 DNS。默认配置
查找顺序为 `./dnsrivet.toml`，然后是
`/Library/Application Support/DNSRivet/config.toml`。

## 安装

DNSRivet 提供两种互斥的安装方式，请不要在同一台机器上混用。

### 签名 macOS 安装包

从 [最新版本](https://github.com/WenliangCao/DNSRivet/releases/latest) 下载
`DNSRivet-*.pkg`，在 Finder 中双击安装。安装包已经签名并通过 Apple 公证，包含
同时支持 Apple Silicon 与 Intel Mac 的 Universal 2 二进制。安装器不会擅自选择
上游或接管 DNS；安装完成后显式配置并启动：

```bash
sudo dnsrivet start \
  --upstream 'doh3=https://resolver.example/profile'
```

以后安装新版 PKG 时，如果 DNSRivet 已在运行，安装器会保留配置和 DNS 备份并
自动重启服务。重启或 DNS 探测失败（例如离线升级）时，安装仍成功，并提示恢复命令。

### Homebrew

```bash
brew install dnsrivet/tap/dnsrivet
sudo dnsrivet start \
  --upstream 'doh3=https://resolver.example/profile'
```

Homebrew 会安装 GitHub Release 中签名过的 Universal 2 二进制。如果 Homebrew 拒绝
加载非官方 tap，先执行 `brew trust --tap dnsrivet/tap` 信任它。

升级后需要显式让系统服务载入新版本：

```bash
brew upgrade dnsrivet
sudo dnsrivet restart
```

移除公式前，应先恢复系统 DNS 并卸载 launchd 服务：

```bash
sudo dnsrivet uninstall
brew uninstall dnsrivet
```

## macOS 服务模式

服务模式要求配置中存在 loopback 的 53 端口监听器。启动服务前，请先替换示例配置中
仅用于文档展示的上游端点：

```bash
sudo ./target/release/dnsrivet start \
  --upstream 'doh3=https://resolver.example/profile'
dnsrivet status
sudo dnsrivet restart
sudo dnsrivet stop
sudo dnsrivet uninstall
```

`start` 会验证配置和端口，安装二进制与配置，加载
`io.github.wenliangcao.dnsrivet`，探测本地 DNS，再逐项备份并替换活动网络服务的
DNS。中途失败会回滚已修改的服务。

如果 macOS 报告了启动后新出现的启用网络服务，看门狗会先记录该服务原有的 DNS，
再将它指向 DNSRivet；执行 `stop` 时会连同原有服务一起恢复。每次看门狗检查时，
DNSRivet 还会尝试从非 loopback 全局 resolver 刷新运行时回退列表。另有每秒一次的
轻量路由源地址检查；地址变化时，通过 `ipconfig` 读取对应接口的 DHCP DNS，因此
接管仍完好时也能刷新。读取不到可用地址则保留旧列表。同源地址换网、仅 DHCPv6
或 VPN scoped DNS 不保证能刷新，强制门户也不保证可用；必要时执行
`sudo dnsrivet stop` 恢复网络原解析器。

首次成功启动后会安装稳定入口 `/usr/local/bin/dnsrivet`；如果当前命令本身由
Homebrew 等包管理器持有，则保留包管理器入口。DNSRivet 不会覆盖无关路径，卸载时
也只删除仍由自己持有的链接。

安装状态位于 `/Library/Application Support/DNSRivet/`。DNS 备份以 `0600` 权限
原子写入；没有备份时，DNSRivet 不会猜测性改写原有 DNS。服务命令只使用已安装配置、
显式 `--config` 或命令行选项，不再隐式导入当前目录的 `dnsrivet.toml`。日志位于
`/var/log/dnsrivet.log`，权限为 `0640`；连接成功日志仅在 debug 级别输出，依赖库仅
输出 error。服务文件描述符软上限为 4096，客户端 TCP 连接上限为 64。

旧安装升级后，执行一次 `sudo dnsrivet stop` 再 `sudo dnsrivet start`，加载新的
launchd 限制、启动恢复环境及带网络位置信息的备份。日志不自动轮转；需要归档时，
先 stop，再把日志移动为 `/var/log/dnsrivet.log.previous`，最后 start，避免进程
继续向已改名的文件写入。

服务因配置、日志初始化或绑定失败而无法启动时，会尝试恢复原系统 DNS 后再退出。
二进制被删除、无法执行，或安全模式未加载服务时，这个恢复逻辑无法运行。优先执行
`sudo dnsrivet stop`；若程序无法执行，先用 `networksetup -listallnetworkservices`
列出服务。原本使用 DHCP DNS 的服务可用
`sudo networksetup -setdnsservers "Wi-Fi" Empty` 恢复自动 DNS；静态 DNS 则按备份
恢复原地址。

切换 macOS 网络位置前应先 stop。已经切换时，先回到备份所属位置再 stop；看门狗
和恢复操作会拒绝把原位置的 DNS 设置写到别的位置。旧备份仍可读取，但需重新接管
后才具备位置校验。

`start`、`stop`、`restart` 和 `uninstall` 使用跨进程锁串行执行。
`stop` 恢复 DNS 并禁用服务，但保留已安装的二进制、配置和 plist。如果改名或未记录的
网络服务仍指向 DNSRivet，会保留备份并拒绝停止；请先恢复该服务已知正确的 DNS
或原名称后重试，避免留下失效的本地 resolver。`uninstall` 还会删除已安装二进制与
`/Library/LaunchDaemons/io.github.wenliangcao.dnsrivet.plist`，用户配置仍保留。

可以在一次命令中安装新配置并重启：

```bash
sudo dnsrivet restart --config dnsrivet.toml
```

如果新服务未通过 DNS 探活，或无法验证活动的系统 DNS 接管，DNSRivet 会恢复旧配置
并重新启动。

接管 macOS DNS 前，DNSRivet 会记录当时实际生效的系统 DNS。所有配置上游均未返回
DNS 应答时，才直接查询这些服务器，每台最多等待两秒。配置上游的 SERVFAIL 会在
其他配置上游均未成功时返回给客户端，不触发系统回退；回退得到的答案不进缓存。
loopback 和自身监听地址会被过滤，避免形成递归自环。如果没有可用的接管前服务器，
最终仍返回 `SERVFAIL`。

服务运行期间，接管看门狗每两分钟（守护进程启动时立即执行一次）核对备份内每个
网络服务是否仍严格指向接管地址。macOS 更新可能重写网络偏好、静默清除接管；
看门狗检测到后，会先把当前网络的 DNS 捕获为新的运行时回退列表，再重新接管。
原有服务的恢复 DNS 不会被替换；新服务和接管地址历史会在修改 DNS 前保存。
网络偏好及接管标记未变化时，会跳过本轮子进程检查。新服务若已经列出接管地址，
只告警并跳过该服务，其他服务仍继续修复。若有外部工具持续改写 DNS，看门狗会
退避到 30 分钟周期并在日志中说明。

## 配置与缓存

完整配置见 [`example.config.toml`](example.config.toml)。DoH/DoH3 默认端口为
443，DoT/DoQ 为 853，传统 DNS 为 53。

前台模式若需向其他主机提供 DNS，应绑定具体接口地址，避免 `0.0.0.0` 或 `::`
通配监听在多接口环境中用错误的源地址应答。配置校验会对非 loopback 监听发出警告。

`timeout` 省略时默认 5000 毫秒。显式写 `timeout = 0` 表示完全禁用超时，属于
危险的高级选项：第一上游黑洞（丢包不拒绝）时，该查询不会进入后续上游或系统
回退，持续请求会逐个挂起并最终耗尽 512 项并发额度，导致后续 UDP 查询被丢弃。
仅在完全信任首上游可达性时使用。

故障转移带对冲：某个上游 300 毫秒内未应答时，会并发查询下一个上游，取先到的
合法且非 `SERVFAIL` 的应答。落败的 legacy 请求会取消；加密请求继续运行至自身
超时，让卡住的连接仍能断开并退避。包括后台落败请求和系统回退在内的所有尝试
共用 512 项预算。`timeout = 0` 的上游不参与对冲。对冲意味着
后续上游可能收到首上游本可以慢速应答的查询，因此只把同样愿意发送查询的上游
排在后面。不做 keep-alive 时，建议把 `doh` 放在 `doh3` 前面，让空闲后的首个
查询延迟更稳定；DoH3 对端可能在空闲 30 秒后关闭 QUIC 连接。不启用 QUIC 0-RTT。

缓存仅处理标准单问题递归查询，并还原每个客户端的问题段大小写。应答超过 4096
字节不缓存，`cache_size` 最大为 16384。带 EDNS option、非零 EDNS 版本、`RD=0`
或应答/授权记录的查询绕过缓存；不支持的加密查询形态在本地拒绝。缓存键包含规范化域名、记录类型、类别、
是否使用 EDNS 和 DNSSEC 请求位。负缓存使用 SOA TTL 与 SOA.MINIMUM 中较小的值，
最多缓存 600 秒，不延长短 TTL；TTL 为零时不缓存。

携带多个 question 的查询会在本地直接返回仅含报文头的 FORMERR，不会被转发
（RFC 9619）。仅配置 `legacy` 上游时，不含 question 的查询仍可转发。配置含加密
上游时，格式错误返回 FORMERR；不含 question、非 QUERY opcode、含非 OPT 记录
或签名等不支持的形态在本地返回 NOTIMP。QR=1 报文直接丢弃。所有上游与回退响应必须与请求的
question 一致，才会被返回或写入缓存（RFC 5452）。

## 安全边界

- DNSRivet 加密到兼容上游的传输，但不在本机执行 DNSSEC 验证。
- 系统 DNS 回退是否加密取决于接管前的 macOS 配置，可能使用传统明文 DNS。
- 接管由周期性看门狗守护；两次检查之间存在窗口（最长一个检查周期），期间被
  外部清除的接管会让查询走系统自身 DNS。
- VPN 与 Network Extension 的 scoped resolver 不在接管范围内，也不会被用作
  回退服务器。
- DHCP 回退刷新依赖路由源地址变化和接口可读的 DHCP DNS；否则可能继续使用旧列表。
- 没有针对局域网名字的分流；`.lan` 和以单播送来的 `.local` 等名字仍发往配置上游，
  公共上游可能获知这些名字却无法解析。需要局域网解析时应配置合适的 resolver。
- 守护进程仍以 root 运行，以绑定 53 端口并管理系统 DNS。
- debug 日志可能包含查询域名和完整上游 URL。
- 服务命令修改系统级 `launchd` 和网络 DNS，因此需要 `sudo`。
- 源码会主动拒绝在非 macOS 目标上编译。
- 依赖公告、输入约束和审计例外见 [`SECURITY.md`](SECURITY.md)。

## 许可证

MIT，见 [`LICENSE`](LICENSE)。
