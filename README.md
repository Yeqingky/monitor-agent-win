# monitor-agent

[monitor](https://github.com/monitor-probe/monitor) 的 Linux agent。采集本机指标，经 WebSocket 上报 hub。

静态链接单文件，无运行时依赖，常驻内存数 MB。

## 特性

- 直接读 `/proc` 与 `statvfs`，不依赖 sysinfo
- 内存对齐 `free(1)` 的 used 列，磁盘对齐 `df(1)` 的 Used 列
- 无状态：不写文件，不保存跨重启的数据，流量累加由 hub 负责
- token 走 `Authorization` 头，不进反向代理的 access log
- 非回环地址拒绝明文 `ws://`

## 安装

在 hub 的面板添加节点，复制生成的命令在目标主机执行：

```bash
curl -fsSL https://your-hub/install.sh | sh -s -- --server https://your-hub --token <token>
```

安装脚本识别 systemd 与 OpenRC，二进制装到 `/opt/monitor/monitor-agent`，token 写入
`/opt/monitor/agent.env`（0600）——和 hub 同一个目录，那台机器上只有这一处要看。

## 运行

```bash
monitor-agent --server https://your-hub --token <token>
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--server` | 必填 | hub 地址，也可用 `MONITOR_SERVER` |
| `--token` | 必填 | 节点 token，也可用 `MONITOR_TOKEN` |
| `--interval` | 1 | 上报间隔（秒），1–3600 |
| `--nics` | 空 | 只统计这些网卡，逗号分隔，如 `eth0,eth1`；也可写作 `-nics` |

## 上报字段

`src/collect.rs` 中的 `Facts` 与 `Metrics` 两个 struct 直接序列化为线上 JSON，是字段的权威定义。

- **`Facts`** 连接时上报一次：主机名、系统、内核、架构、虚拟化类型、CPU 型号与核数、内存与磁盘总量、本机 IPv4 / IPv6
- **`Metrics`** 每 `--interval` 秒上报：CPU、负载、内存、swap、磁盘、网卡收发速率与内核累计计数器、TCP / UDP 连接数、进程数、运行时间

`net_rx_total` / `net_tx_total` 为内核 lifetime 计数器，原样上报；`boot_id` 取自
`/proc/sys/kernel/random/boot_id`，是 hub 判定主机重启的唯一依据，**不要删**。

### 网卡选择

默认按内置名称表求和：跳过 `lo`、容器网络与隧道，并排除 `is_stacked` 的网卡（bond、
bridge、VLAN），因为这些设备的字节在内层已经被计过一次。

名称表只能靠名字猜，而 PVE、iStoreOS 这类主机上同一个包会被计多次——例如客户机的流量
同时记在物理口、`vmbr0` 和 `tap` 上，只有操作者知道 hub 该按哪个口径计费。`--nics`
用于这种情况：

```bash
monitor-agent --server https://your-hub --token <token> --nics eth0,eth1
```

- 给出 `--nics` 后，列表**替换**上面两张名称表，不再叠加。因此列出的 bridge 或隧道会被
  统计，未列出的 `eth0` 也不会被统计。
- 名称精确匹配（`eth` 不是 `eth0` 的前缀匹配），重复列出的名称仍只计一次。
- 列表为空（不传或传空串）等同于默认行为，不是“统计为零”。
- 名称不在 `/proc/net/dev` 中时启动会打印一行提示，避免把拼错的名字当成空闲主机。

`--nics` 只影响流量统计。`Facts` 里的本机 IPv4 / IPv6 仍按 `SKIP_IFACES` 选取，否则在
PVE 上地址位于 `vmbr0`，而该口通常不会出现在列表里。

协议说明见 [hub 仓库](https://github.com/monitor-probe/monitor)。

## 构建

需要 Rust stable。

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

发布产物为 musl 静态链接二进制，推送 `v*` tag 由 `.github/workflows/release.yml` 构建。

## 许可

MIT
