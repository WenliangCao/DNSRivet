# DNSRivet

> Compact encrypted DNS forwarding for macOS.

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
- Ordered failover, per-upstream timeouts, and exponential reconnect backoff
- Direct fallback to the pre-takeover system DNS after all configured upstreams fail
- Bootstrap resolution that bypasses the system resolver to prevent loops
- Local UDP and TCP listeners with bounded concurrency
- 4,096-entry LRU cache by default, with wire-level TTL aging
- RFC 2308 negative caching and EDNS-aware UDP truncation
- Transactional system DNS takeover and restoration
- Native `launchd` service management
- One-line CLI configuration backed by the same TOML validation path

## Runtime profile

The release profile is optimized for size with LTO, a single codegen unit,
symbol stripping, and abort-on-panic behavior.

| Measurement | Observed value |
| --- | ---: |
| Release binary | 2,506,016 bytes (2.39 MiB) |
| RSS after a fresh DoH3 connection | 4,656 KiB |
| RSS after load and about four minutes | 4,912 KiB |
| Tokio runtime threads | 1 |
| Cached UDP latency, p50 / p95 | 0.087 / 0.112 ms |
| Unique DoH3 latency, p50 / p95 | 8.72 / 9.92 ms |

Measured on Apple Silicon with macOS 27.0 using 200 cached queries and 40
unique queries against a public DoH3 endpoint. These numbers describe one
development machine and network path; they are not universal guarantees.

## Build

Requirements: macOS and stable Rust.

```bash
git clone https://github.com/WenliangCao/DNSRivet.git
cd DNSRivet
cargo test --all-targets --all-features
cargo build --release
./target/release/dnsrivet version
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
`/usr/local/bin/dnsrivet`. It is an ownership-checked symbolic link to the
installed binary: DNSRivet refuses to replace an unrelated path and removes
the link only if it still owns it.

Installed state lives under `/Library/Application Support/DNSRivet/`. The DNS
backup is written atomically with mode `0600`; without that backup, DNSRivet
will not guess how to rewrite existing DNS settings. Logs are written to
`/var/log/dnsrivet.log`.

`stop` restores DNS and disables the job while preserving the installed binary,
configuration, and property list. `uninstall` also removes the installed binary
and `/Library/LaunchDaemons/io.github.wenliangcao.dnsrivet.plist`. User
configuration remains intact.

Install a replacement TOML atomically with:

```bash
sudo dnsrivet restart --config dnsrivet.toml
```

If the new service fails its DNS probe, DNSRivet restores the previous config
and restarts it.

Before taking over macOS DNS, DNSRivet snapshots the effective system DNS
servers. If every configured upstream fails, it queries those servers directly
with a two-second bound per server. Loopback and self-listener addresses are
discarded, so the fallback cannot recurse through DNSRivet. If no usable
pre-takeover server exists, exhaustion still returns `SERVFAIL`.

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

An explicit `timeout = 0` disables the timeout and is a dangerous advanced
option: when the first upstream black-holes traffic (drops packets without
refusing), that query never reaches later upstreams or the system fallback,
and sustained load hangs queries one by one until the in-flight budget of 512
is exhausted and further UDP queries are dropped. Use it only when the first
upstream's reachability is fully trusted.

See [`example.config.toml`](example.config.toml) for the complete annotated
example. DoH and DoH3 default to port 443; DoT and DoQ default to 853;
conventional DNS defaults to 53.

The cache accepts standard single-question recursive queries. Queries with
EDNS options, TSIG, a non-zero EDNS version, or `RD=0` bypass the cache and
are still forwarded normally. Cache keys include the canonical name, record
type, class, and DNSSEC request bit.

A QUERY carrying more than one question is answered locally with a
header-only FORMERR and never forwarded (RFC 9619). Question-less queries
such as RFC 7873 cookie probes are forwarded to `legacy` upstreams only;
encrypted transports require exactly one question. Every upstream and
fallback response must echo the query's question before it is returned or
cached (RFC 5452).

## Security boundary

- DNSRivet encrypts transport to compatible upstreams; it does not perform
  local DNSSEC validation.
- System fallback may use conventional unencrypted DNS, depending on the
  pre-takeover macOS configuration.
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

> 面向 macOS 的紧凑型加密 DNS 转发器。

DNSRivet 是一个以 Rust 编写的小型单进程 DNS 守护程序。它接收本机 UDP/TCP
查询，通过加密传输转发，并尽量缩短高频路径。

**平台状态：目前仅支持 macOS。** DNSRivet 不是跨平台 DNS 客户端；服务生命周期、
系统 DNS 接管和恢复均针对 macOS 与 `launchd` 实现。

单一二进制。单运行时线程。无遥测。无控制平面。

## 核心能力

- 支持 DoH、DoH3、DoT、DoQ 和传统 UDP/TCP 上游
- 加密连接持久化并复用
- 顺序故障转移、独立超时和指数退避重连
- 所有配置上游失败后，直接回退到接管前的系统 DNS
- bootstrap 解析绕过系统 resolver，避免 DNS 自环
- UDP/TCP 本地监听与有界并发
- 默认 4,096 项 LRU 缓存，直接在 DNS wire 层递减 TTL
- RFC 2308 负缓存和 EDNS 感知的 UDP 截断
- 事务式接管和恢复系统 DNS
- 原生 `launchd` 服务管理
- 一行终端参数配置，并与 TOML 共用同一套校验逻辑

## 运行开销

release 配置启用 LTO、单 codegen unit、符号剥离和 panic abort，以控制体积。

| 测量项 | 实测值 |
| --- | ---: |
| release 二进制 | 2,506,016 bytes（2.39 MiB） |
| 新建 DoH3 连接后的 RSS | 4,656 KiB |
| 负载结束约四分钟后的 RSS | 4,912 KiB |
| Tokio 运行时线程 | 1 |
| UDP 缓存命中延迟 p50 / p95 | 0.087 / 0.112 ms |
| 唯一 DoH3 查询延迟 p50 / p95 | 8.72 / 9.92 ms |

数据来自 Apple Silicon、macOS 27.0 开发机，测试包含 200 次缓存查询和 40 次
经公共 DoH3 端点的唯一查询。具体数值会随机器与网络路径变化。

## 构建与前台运行

需要 macOS 和稳定版 Rust：

```bash
cargo test --all-targets --all-features
cargo build --release
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

首次成功启动后会安装稳定入口 `/usr/local/bin/dnsrivet`。它是指向已安装二进制的
符号链接；如果路径已被其他文件占用，DNSRivet 会拒绝覆盖。卸载时也只删除仍由
DNSRivet 持有的链接。

安装状态位于 `/Library/Application Support/DNSRivet/`。DNS 备份以 `0600` 权限
原子写入；没有备份时，DNSRivet 不会猜测性改写原有 DNS。日志位于
`/var/log/dnsrivet.log`。

`stop` 恢复 DNS 并禁用服务，但保留已安装的二进制、配置和 plist；`uninstall`
还会删除已安装二进制与
`/Library/LaunchDaemons/io.github.wenliangcao.dnsrivet.plist`，用户配置仍保留。

可以在一次命令中安装新配置并重启：

```bash
sudo dnsrivet restart --config dnsrivet.toml
```

如果新服务未通过 DNS 探活，DNSRivet 会恢复旧配置并重新启动。

接管 macOS DNS 前，DNSRivet 会记录当时实际生效的系统 DNS。所有配置上游都失败时，
它会绕过已经指向自身的系统 resolver，直接查询这些服务器，每台最多等待两秒。
loopback 和自身监听地址会被过滤，避免形成递归自环。如果没有可用的接管前服务器，
最终仍返回 `SERVFAIL`。

## 配置与缓存

完整配置见 [`example.config.toml`](example.config.toml)。DoH/DoH3 默认端口为
443，DoT/DoQ 为 853，传统 DNS 为 53。

`timeout` 省略时默认 5000 毫秒。显式写 `timeout = 0` 表示完全禁用超时，属于
危险的高级选项：第一上游黑洞（丢包不拒绝）时，该查询不会进入后续上游或系统
回退，持续请求会逐个挂起并最终耗尽 512 项并发额度，导致后续 UDP 查询被丢弃。
仅在完全信任首上游可达性时使用。

缓存仅处理标准单问题递归查询。带 EDNS option、TSIG、非零 EDNS 版本或
`RD=0` 的查询会绕过缓存，但仍正常转发。缓存键包含规范化域名、记录类型、类别和
DNSSEC 请求位。

携带多个 question 的查询会在本地直接返回仅含报文头的 FORMERR，不会被转发
（RFC 9619）。不含 question 的查询（如 RFC 7873 Cookie 探询）只会转发给
`legacy` 上游；加密传输要求恰好一个 question。所有上游与回退响应必须与请求的
question 一致，才会被返回或写入缓存（RFC 5452）。

## 安全边界

- DNSRivet 加密到兼容上游的传输，但不在本机执行 DNSSEC 验证。
- 系统 DNS 回退是否加密取决于接管前的 macOS 配置，可能使用传统明文 DNS。
- debug 日志可能包含查询域名和完整上游 URL。
- 服务命令修改系统级 `launchd` 和网络 DNS，因此需要 `sudo`。
- 源码会主动拒绝在非 macOS 目标上编译。
- 依赖公告、输入约束和审计例外见 [`SECURITY.md`](SECURITY.md)。

## 许可证

MIT，见 [`LICENSE`](LICENSE)。
