# monitor-agent 开发规则

## 仓库职责

本仓库负责构建 monitor hub 的 Windows 主机监控 agent. Agent 通过 WebSocket 发送 `Facts` 和 `Metrics`, 执行 hub 下发的 TCP 探测任务, 并作为 Windows Service 自启动. 发布版本与 Linux `monitor-probe/agent` 同步.

## 代码导航

- `src/main.rs`: 参数解析, ACL 配置文件, Windows Service 生命周期, WebSocket 会话, 重连退避和探测任务.
- `src/collect.rs`: Win32 API 指标采集.
- `.github/workflows/ci.yml`: Windows GNU target 的格式检查, 类型检查和 Clippy.
- `.github/workflows/release.yml`: Windows GNU release 产物.

## 开发和验证

```bash
cargo fmt --all --check
cargo check --locked --target x86_64-pc-windows-gnu
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --locked --target x86_64-pc-windows-gnu
```

Windows 交叉编译需要 `x86_64-w64-mingw32-gcc`. 本机没有 Windows runtime 时, 至少执行 Windows target 的 `cargo check`.

## 版本控制和发布

- 不提交 `target/`, 本地 token 或运行日志.
- release 使用 `v*` tag, tag 与 `Cargo.toml` 版本必须一致; Windows agent 版本须与 Linux `monitor-probe/agent` 对齐.
- Windows 产物名称必须保持 `monitor-agent-x86_64-pc-windows-gnu.exe`.
- 改变产物名称或服务名称时必须同步 release workflow 和安装说明.

## 必须保持的业务规则

- token 只放在 `Authorization: Bearer ...` header, 不放入 WebSocket URL.
- 远端 hub 默认拒绝明文 `ws://`; 只有显式 `--insecure` 才允许.
- `Facts` 和 `Metrics` 的既有 JSON 字段名称、类型和含义不得改变; 新字段只能以 hub 可兼容的增量方式添加.
- `boot_id` 必须在同一次系统启动期间稳定, hub 依赖它识别重启; 优先使用内核 BootIdentifier GUID, 不得用分别采样墙钟和 uptime 的估算值作为常规来源.
- `net_rx_total` 和 `net_tx_total` 是系统累计字节计数器. Agent 不持久化计数, hub 负责处理重启和回退.
- `--iface` 使用精确 adapter alias 名称, 支持只统计列表和 `-名称` 排除; 排除优先, 空值使用默认虚拟接口过滤规则, 拒绝控制字符. `--nics` / `MONITOR_NICS` 只作为旧配置兼容入口.
- `Metrics.iface` 必须报告当前选择; `boot_id` 在系统启动标识后附加按排序后统计网卡集合计算的稳定摘要, 集合变化时 hub 必须重新设基线.
- 每个地址族优先报告可公网路由的本机地址. 当报告的 IPv4 地址不是公网地址时, 连接 hub 优先尝试 IPv4 地址, 使 NAT 后的 hub 能识别公网出口.
- `--service-name` 默认为 `monitor-agent`. 相同服务名的 `install` 是升级和配置修改, 不同服务名必须使用独立配置目录并允许共存.
- `install` 必须将当前 exe 复制到 `%ProgramData%\monitor-agent\monitor-agent.exe`, Service 不得依赖临时目录中的 exe. 替换共享副本前必须停止已配置的 agent 实例, 完成后恢复.
- 默认配置文件位于 `%ProgramData%\monitor-agent\agent.env`, 其他服务名使用 `%ProgramData%\monitor-agent\<service-name>.env`, 安装时必须移除继承权限, 只允许 `SYSTEM` 和 Administrators 访问.
- 配置文件 ACL 加固必须使用 Win32 API 获取的 `%SystemRoot%\System32\icacls.exe` 绝对路径, 禁止依赖 `PATH` 搜索可执行文件.
- Windows Service 必须支持 Stop 和 Shutdown, 正常退出时报告 `Stopped`, 异常退出时由 SCM failure actions 自动重启.
- hub 下发的 ping task 必须有并发上限, 不能信任 hub 提供的任务数量.
- 采集失败时优先返回 0 或空值并继续上报, 不得因为单个可选指标让 WebSocket 主循环退出.
