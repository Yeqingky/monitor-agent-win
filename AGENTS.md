# monitor-agent 开发规则

## 仓库职责

本仓库负责构建 monitor hub 的 Windows 主机监控 agent. Agent 通过 WebSocket 发送 `Facts` 和 `Metrics`, 执行 hub 下发的 TCP 探测任务, 并作为 Windows Service 自启动.

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
- release 使用 `v*` tag.
- Windows 产物名称必须保持 `monitor-agent-x86_64-pc-windows-gnu.exe`.
- 改变产物名称或服务名称时必须同步 release workflow 和安装说明.

## 必须保持的业务规则

- token 只放在 `Authorization: Bearer ...` header, 不放入 WebSocket URL.
- 远端 hub 默认拒绝明文 `ws://`; 只有显式 `--insecure` 才允许.
- `Facts` 和 `Metrics` 的 JSON 字段不得改变, hub 依赖现有协议.
- `boot_id` 必须在同一次系统启动期间稳定, hub 依赖它识别重启.
- `net_rx_total` 和 `net_tx_total` 是系统累计字节计数器. Agent 不持久化计数, hub 负责处理重启和回退.
- `--nics` 是精确 adapter alias 列表. 传入非空列表后替换默认虚拟接口过滤规则, 重复名称只能计数一次.
- `--service-name` 默认为 `monitor-agent`. 相同服务名的 `install` 是升级和配置修改, 不同服务名必须使用独立配置目录并允许共存.
- `install` 必须将当前 exe 复制到 `%ProgramData%\monitor-agent\monitor-agent.exe`, Service 不得依赖临时目录中的 exe. 替换共享副本前必须停止已配置的 agent 实例, 完成后恢复.
- 默认配置文件位于 `%ProgramData%\monitor-agent\agent.env`, 其他服务名使用 `%ProgramData%\monitor-agent\<service-name>.env`, 安装时必须移除继承权限, 只允许 `SYSTEM` 和 Administrators 访问.
- Windows Service 必须支持 Stop 和 Shutdown, 正常退出时报告 `Stopped`, 异常退出时由 SCM failure actions 自动重启.
- hub 下发的 ping task 必须有并发上限, 不能信任 hub 提供的任务数量.
- 采集失败时优先返回 0 或空值并继续上报, 不得因为单个可选指标让 WebSocket 主循环退出.
