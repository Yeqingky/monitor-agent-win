> **免责声明**: 本项目完全由 AI 生成。使用本项目产生的一切后果由使用者自行承担，项目作者不对任何直接或间接损失负责。

# monitor-agent

`monitor-agent` 是 monitor hub 的 Windows 主机 agent, 使用 WebSocket 上报本机指标并执行 hub 下发的 TCP 探测任务.

## 版本兼容性

尽量与官方agent版本号对应.

| 官方 agent | agent-win (当前项目) |
|:---:|:---:|
| [v1.1.0](https://github.com/monitor-probe/agent/releases/tag/v1.1.0) | [v1.1.0](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.1.0) |
| [v1.0.0](https://github.com/monitor-probe/agent/releases/tag/v1.0.0) | [v1.0.0](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.0.0) , [v1.0.1](https://github.com/Yeqingky/monitor-agent-win/releases/tag/v1.0.1) |


## 架构

- `src/main.rs`: 参数解析, 配置文件, Windows Service 生命周期, WebSocket 会话, 重连退避和 TCP 探测任务.
- `src/collect.rs`: 使用 Win32 system information, IP Helper, registry 和文件系统 API 采集指标.
- `.github/workflows/ci.yml`: Windows GNU target 的格式检查, 类型检查和 Clippy.
- `.github/workflows/release.yml`: Windows 静态 release 产物.

不调用 PowerShell, 不依赖本地化命令输出.

## 安装和运行

所有服务管理命令都需要以管理员身份运行 PowerShell:

```powershell
.\monitor-agent.exe install --server https://example.com --token <token>
```

`install` 会执行以下操作:

- 将当前 exe 复制到 `%ProgramData%\monitor-agent\monitor-agent.exe`, Windows Service 始终使用这个副本.
- 更新共享 exe 时会暂时停止已配置的 agent 实例, 完成后恢复.
- 默认配置写入 `%ProgramData%\monitor-agent\agent.env`, 其他服务名写入 `%ProgramData%\monitor-agent\<service-name>.env`.
- 使用 `icacls` 移除继承权限, 只允许 `SYSTEM` 和本机 Administrators 读取配置.
- 注册名为 `monitor-agent` 的 Windows Service.
- 配置 delayed auto-start.
- 配置服务失败后 5 / 30 / 60 秒自动重启.
- 启动服务.

服务管理:

```powershell
.\monitor-agent.exe status
.\monitor-agent.exe start
.\monitor-agent.exe stop
.\monitor-agent.exe uninstall

# Manage another independent agent instance.
.\monitor-agent.exe install --service-name monitor-agent-backup --server https://example.com --token <token>
.\monitor-agent.exe status --service-name monitor-agent-backup
.\monitor-agent.exe start --service-name monitor-agent-backup
.\monitor-agent.exe stop --service-name monitor-agent-backup
.\monitor-agent.exe uninstall --service-name monitor-agent-backup
```

`uninstall` 只删除指定服务, 保留对应配置文件, 便于重新安装. 如需删除 token, 请在确认后手动删除 `%ProgramData%\monitor-agent`.

也可以以前台进程运行, 便于调试:

```powershell
.\monitor-agent.exe --server https://example.com --token <token>
```

支持环境变量 `MONITOR_SERVICE_NAME`, `MONITOR_SERVER`, `MONITOR_TOKEN`, `MONITOR_INTERVAL`, `MONITOR_IFACE` 和 `MONITOR_INSECURE`. 配置文件优先于环境变量, 命令行参数优先于配置文件. `MONITOR_NICS` 与 `--nics` 保留为旧配置兼容入口. 重复执行 `install` 且服务名相同会更新该服务和配置; 使用不同服务名即可共存多个 agent.

| 参数 | 默认 | 说明 |
|---|---:|---|
| `--server` | 必填 | hub 地址, 也可用配置文件或 `MONITOR_SERVER` |
| `--token` | 必填 | 节点 token, 也可用配置文件或 `MONITOR_TOKEN` |
| `--service-name` | `monitor-agent` | Windows Service 名称 |
| `--config` | `%ProgramData%\monitor-agent\agent.env` | 配置文件路径, 默认按服务名区分 |
| `--interval` | 1 | 上报间隔, 1-3600 秒 |
| `--iface` | 空 | 网卡选择, adapter alias 逗号分隔; 正向列表只统计列出的网卡, `-名称` 从默认统计集合中排除, 排除优先 |
| `--nics` | 空 | 旧参数, 等价于只统计列出的 adapter alias |
| `--insecure` | 关闭 | 允许远端使用明文 `ws://`, token 会以明文传输 |

## 上报字段

- `Facts`: 主机名, Windows 版本, 架构, 虚拟化类型, CPU 型号和核数, 内存, page file, 磁盘总量, IPv4 / IPv6.
- `Metrics`: CPU, load, 内存, page file, 磁盘, 网卡收发速率和累计计数器, TCP / UDP 数量, 进程数, uptime.
- `boot_id`: hub 判断主机重启和网卡计数集合变化的依据.
- `iface`: 当前 `--iface` 选择, 空值代表默认过滤规则, hub 可据此展示当前设置.
- `net_rx_total` / `net_tx_total`: 所选网卡的系统累计字节计数器, hub 负责跨上报累加.

Windows 没有等价的内核 load-average 计数器, `load` 是按 1 / 5 / 15 分钟窗口平滑后的 CPU demand, 单位为逻辑 CPU 数. 磁盘统计 fixed logical drives, 不统计网络盘、光盘和可移动盘.

### 网卡选择

默认过滤 loopback、容器、隧道和常见虚拟网卡. `--iface` 的正向列表替换默认过滤规则, `-alias` 从默认集合中排除网卡, 排除优先于列出. 名称精确匹配 Windows adapter alias; 多个名称用逗号分隔, alias 含空格时请给整个参数加引号. 不存在的正向名称会在启动时提示, 并按 0 字节统计. 空 `--iface` 恢复默认规则.

```powershell
.\monitor-agent.exe install --server https://example.com --token <token> --iface "Ethernet,-vEthernet (WSL)"
```

旧版 `--nics` / `MONITOR_NICS` 仍可读取, 语义为只统计所列网卡, 新安装配置统一写入 `MONITOR_IFACE`.

## 构建和验证

需要 Rust stable 和 `x86_64-w64-mingw32-gcc`:

```bash
cargo fmt --all --check
cargo check --locked --target x86_64-pc-windows-gnu
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --locked --target x86_64-pc-windows-gnu
```

release 产物为 `monitor-agent-x86_64-pc-windows-gnu.exe`.

## 许可

MIT
