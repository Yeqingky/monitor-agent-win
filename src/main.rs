//! monitor-agent: reports one host to a monitor hub over WebSocket.

mod collect;

use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

// Shares the clock `tokio::time::timeout` and `sleep` read, so deadline
// arithmetic cannot drift from the timers enforcing it, and tests can advance
// it. Outside a paused runtime this is the monotonic clock.
use tokio::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{Sink, SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use collect::Collector;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

#[derive(Clone)]
struct Args {
    server: String,
    token: String,
    interval: u64,
    /// Adapter aliases whose traffic is billed. Empty means the default
    /// physical-interface filter is used.
    nics: Vec<String>,
    service_name: String,
    /// Permits plain HTTP to a hub reached at ip:port with no TLS in front.
    /// Off by default: the token would otherwise travel in the clear.
    insecure: bool,
    config_path: PathBuf,
}

const DEFAULT_SERVICE_NAME: &str = "monitor-agent";
const SERVICE_DISPLAY_NAME: &str = "Monitor Agent";
const SERVICE_DESCRIPTION: &str = "Reports Windows host metrics to a monitor hub.";
const CONFIG_DIR_NAME: &str = "monitor-agent";
const CONFIG_FILE_NAME: &str = "agent.env";
const LOG_FILE_NAME: &str = "agent.log";

/// Printed on `--help` and on any argument error. A raw literal rather than
/// line continuations: `\`-continuations strip the leading whitespace of the
/// next source line, which silently flattened every description's second line.
const USAGE: &str = r#"Usage: monitor-agent [command] [options]

Commands:
  install              Write config, install and start the Windows service
  uninstall            Stop and remove the Windows service
  start                Start the Windows service
  stop                 Stop the Windows service
  status               Show the Windows service status
  service              Internal service entry point

Options:
  --server <url>       Hub base URL, e.g. https://hub.example.com
  --token <token>      Node token from the hub panel
  --config <path>      Config file (default: per-service ProgramData path)
  --service-name <name> Service name (default: monitor-agent)
  --interval <secs>    Report interval (default 1)
  --nics <list>        Count only these adapter aliases, comma separated
                       (e.g. Ethernet,Wi-Fi)
  --insecure           Allow plain ws:// to a remote hub; the token travels
                       in the clear. Only for a hub reached at ip:port with
                       no TLS in front."#;

fn usage() -> ! {
    eprintln!("monitor-agent {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
    std::process::exit(2)
}

fn parse_args() -> Result<Args> {
    parse_options(std::env::args().skip(1))
}

fn parse_options<I>(args: I) -> Result<Args>
where
    I: IntoIterator<Item = String>,
{
    let (mut server, mut token, mut interval, mut nics, mut insecure) = (None, None, None, None, None);
    let mut config_path = None;
    let mut explicit_config = false;
    let mut service_name = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| anyhow!("missing value for {arg}"));
        match arg.as_str() {
            "--server" => server = Some(value()?),
            "--token" => token = Some(value()?),
            "--config" => {
                config_path = Some(PathBuf::from(value()?));
                explicit_config = true;
            }
            "--service-name" => service_name = Some(value()?),
            "--interval" => {
                interval = Some(value()?.parse().context("--interval must be an integer")?);
            }
            "-nics" | "--nics" => nics = Some(parse_nics(&value()?)),
            "--insecure" => insecure = Some(true),
            "-h" | "--help" => usage(),
            other => bail!("unknown argument: {other}"),
        }
    }
    let service_name = service_name
        .or_else(|| std::env::var("MONITOR_SERVICE_NAME").ok())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_owned());
    validate_service_name(&service_name)?;
    let config_path = absolute_path(&config_path.unwrap_or_else(|| default_config_path(&service_name)))?;
    let config = if config_path.exists() {
        read_config(&config_path)?
    } else if explicit_config {
        bail!("config file does not exist: {}", config_path.display())
    } else {
        HashMap::new()
    };
    let config_value = |name: &str| config.get(name).map(String::as_str);

    let server = server
        .or_else(|| config_value("MONITOR_SERVER").map(str::to_owned))
        .or_else(|| std::env::var("MONITOR_SERVER").ok())
        .ok_or_else(|| anyhow!("missing --server or MONITOR_SERVER"))?;
    let token = token
        .or_else(|| config_value("MONITOR_TOKEN").map(str::to_owned))
        .or_else(|| std::env::var("MONITOR_TOKEN").ok())
        .ok_or_else(|| anyhow!("missing --token or MONITOR_TOKEN"))?;
    let interval = interval
        .or_else(|| config_value("MONITOR_INTERVAL").and_then(|v| v.parse().ok()))
        .or_else(|| std::env::var("MONITOR_INTERVAL").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(1);
    let nics = nics
        .or_else(|| config_value("MONITOR_NICS").map(parse_nics))
        .or_else(|| std::env::var("MONITOR_NICS").ok().map(|v| parse_nics(&v)))
        .unwrap_or_default();
    let insecure = match insecure {
        Some(value) => value,
        None => match config_value("MONITOR_INSECURE") {
            Some(value) => parse_bool(value)?,
            None => match std::env::var("MONITOR_INSECURE") {
                Ok(value) => parse_bool(&value)?,
                Err(_) => false,
            },
        },
    };
    Ok(Args { server, token, interval: interval.clamp(1, 3600), nics, service_name, insecure, config_path })
}

fn default_config_path(service_name: &str) -> PathBuf {
    let root = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(CONFIG_DIR_NAME);
    if service_name == DEFAULT_SERVICE_NAME {
        root.join(CONFIG_FILE_NAME)
    } else {
        root.join(format!("{service_name}.env"))
    }
}

fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 80
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid service name: use 1-80 ASCII letters, digits, '-', '_' or '.'");
    }
    Ok(())
}

fn parse_service_name<I>(args: I) -> Result<String>
where
    I: IntoIterator<Item = String>,
{
    let mut name = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "service" => {}
            "--service-name" => {
                name = Some(it.next().ok_or_else(|| anyhow!("missing value for --service-name"))?);
            }
            "--config" => {
                it.next().ok_or_else(|| anyhow!("missing value for --config"))?;
            }
            other => bail!("unknown service option: {other}"),
        }
    }
    let name = name.unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_owned());
    validate_service_name(&name)?;
    Ok(name)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn read_config(path: &Path) -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("invalid config line in {}", path.display());
        };
        values.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    Ok(values)
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("invalid boolean value: {value}"),
    }
}

fn validate_config_value(name: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        bail!("{name} contains a line break");
    }
    Ok(())
}

fn write_config(args: &Args) -> Result<()> {
    validate_config_value("server", &args.server)?;
    validate_config_value("token", &args.token)?;
    if let Some(parent) = args.config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = format!(
        "MONITOR_SERVICE_NAME={}\nMONITOR_SERVER={}\nMONITOR_TOKEN={}\nMONITOR_INTERVAL={}\nMONITOR_NICS={}\nMONITOR_INSECURE={}\n",
        args.service_name,
        args.server,
        args.token,
        args.interval,
        args.nics.join(","),
        if args.insecure { 1 } else { 0 },
    );
    fs::write(&args.config_path, content)?;
    harden_config(&args.config_path)
}

fn harden_config(path: &Path) -> Result<()> {
    let output = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
        .output()
        .context("run icacls")?;
    if !output.status.success() {
        bail!("icacls failed for {}: {}", path.display(), String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

fn current_service_name() -> String {
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--service-name" {
            if let Some(name) = it.next() {
                if validate_service_name(&name).is_ok() {
                    return name;
                }
            }
        }
    }
    DEFAULT_SERVICE_NAME.to_owned()
}

fn log_path() -> PathBuf {
    let service_name = current_service_name();
    let filename = if service_name == DEFAULT_SERVICE_NAME {
        LOG_FILE_NAME.to_owned()
    } else {
        format!("{service_name}.log")
    };
    default_config_path(&service_name).with_file_name(filename)
}

fn log_line(line: &str) {
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
    eprintln!("{line}");
}

macro_rules! agent_log {
    ($($arg:tt)*) => {{
        log_line(&format!($($arg)*));
    }};
}

fn service_display_name(service_name: &str) -> String {
    if service_name == DEFAULT_SERVICE_NAME {
        SERVICE_DISPLAY_NAME.to_owned()
    } else {
        format!("{SERVICE_DISPLAY_NAME} ({service_name})")
    }
}

fn installed_binary_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(CONFIG_DIR_NAME)
        .join("monitor-agent.exe")
}

fn prepare_binary_copy() -> Result<(PathBuf, Option<PathBuf>)> {
    let source = std::env::current_exe()?;
    let target = installed_binary_path();
    if source.to_string_lossy().eq_ignore_ascii_case(&target.to_string_lossy()) {
        return Ok((target, None));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let pending = target.with_extension("exe.new");
    if pending.exists() {
        fs::remove_file(&pending)?;
    }
    fs::copy(&source, &pending)
        .with_context(|| format!("copy current executable to {}", pending.display()))?;
    Ok((target, Some(pending)))
}

fn commit_binary_copy(pending: Option<&Path>, target: &Path) -> Result<()> {
    let Some(pending) = pending else { return Ok(()) };
    fs::copy(pending, target).with_context(|| {
        format!(
            "copy installed executable to {}; another monitor-agent service may still be running",
            target.display()
        )
    })?;
    fs::remove_file(pending)?;
    Ok(())
}

fn service_info(args: &Args, binary_path: &Path) -> Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: OsString::from(&args.service_name),
        display_name: OsString::from(service_display_name(&args.service_name)),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path.to_owned(),
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--config"),
            args.config_path.as_os_str().to_owned(),
            OsString::from("--service-name"),
            OsString::from(&args.service_name),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    })
}

fn open_service(service_name: &str, access: ServiceAccess) -> Result<windows_service::service::Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    Ok(manager.open_service(service_name, access)?)
}

fn configured_service_names() -> Result<Vec<String>> {
    let installed_path = installed_binary_path();
    let root = installed_path.parent().unwrap_or_else(|| Path::new("."));
    let mut names = HashSet::new();
    let Ok(entries) = fs::read_dir(root) else { return Ok(Vec::new()) };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("env") {
            continue;
        }
        let fallback = if path.file_name().and_then(|name| name.to_str()) == Some(CONFIG_FILE_NAME) {
            DEFAULT_SERVICE_NAME.to_owned()
        } else {
            path.file_stem().and_then(|name| name.to_str()).unwrap_or_default().to_owned()
        };
        let name = read_config(&path)
            .ok()
            .and_then(|values| values.get("MONITOR_SERVICE_NAME").cloned())
            .unwrap_or(fallback);
        if validate_service_name(&name).is_ok() {
            names.insert(name);
        }
    }
    Ok(names.into_iter().collect())
}

fn stop_running_services() -> Result<Vec<String>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP;
    let mut stopped = Vec::new();
    for name in configured_service_names()? {
        let Ok(service) = manager.open_service(&name, access) else { continue };
        if service.query_status()?.current_state != ServiceState::Stopped {
            stop_and_wait(&service, &name)?;
            stopped.push(name);
        }
    }
    Ok(stopped)
}

fn restart_services(names: &[String]) -> Result<()> {
    for name in names {
        let service = open_service(name, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&OsStr>(&[])?;
        }
    }
    Ok(())
}

fn stop_and_wait(service: &windows_service::service::Service, service_name: &str) -> Result<()> {
    if service.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    let _ = service.stop()?;
    for _ in 0..30 {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    bail!("service {service_name} did not stop within 30 seconds")
}

fn install_service(args: Args) -> Result<()> {
    write_config(&args)?;
    let (binary_path, pending_binary) = prepare_binary_copy()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = service_info(&args, &binary_path)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE;
    let mut stopped_services = if pending_binary.is_some() { stop_running_services()? } else { Vec::new() };
    let service = match manager.open_service(&args.service_name, access) {
        Ok(service) => {
            let was_running = service.query_status()?.current_state != ServiceState::Stopped;
            stop_and_wait(&service, &args.service_name)?;
            if was_running && !stopped_services.iter().any(|name| name == &args.service_name) {
                stopped_services.push(args.service_name.clone());
            }
            commit_binary_copy(pending_binary.as_deref(), &binary_path)?;
            service
        }
        Err(_) => {
            commit_binary_copy(pending_binary.as_deref(), &binary_path)?;
            manager.create_service(&info, access)?
        }
    };
    service.change_config(&info)?;
    service.set_description(SERVICE_DESCRIPTION)?;
    service.set_delayed_auto_start(true)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
            ServiceAction { action_type: ServiceActionType::None, delay: Duration::ZERO },
        ]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&OsStr>(&[])?;
    }
    restart_services(&stopped_services)?;
    println!("installed and started {}", args.service_name);
    println!("binary: {}", binary_path.display());
    println!("config: {}", args.config_path.display());
    Ok(())
}

fn stop_service(service_name: &str) -> Result<()> {
    let service = open_service(service_name, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    stop_and_wait(&service, service_name)?;
    println!("stopped {service_name}");
    Ok(())
}

fn start_service(service_name: &str) -> Result<()> {
    let service = open_service(service_name, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&OsStr>(&[])?;
    }
    println!("started {service_name}");
    Ok(())
}

fn uninstall_service(service_name: &str) -> Result<()> {
    let service = open_service(
        service_name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    stop_and_wait(&service, service_name)?;
    service.delete()?;
    println!("removed {service_name}; config was kept");
    Ok(())
}

fn status_service(service_name: &str) -> Result<()> {
    let service = open_service(service_name, ServiceAccess::QUERY_STATUS)?;
    println!("{service_name}: {:?}", service.query_status()?.current_state);
    Ok(())
}

fn run_foreground(args: Args) -> Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run_agent(args, shutdown_rx))
}

fn run_service(arguments: Vec<OsString>) -> Result<()> {
    let mut raw: Vec<String> = arguments.into_iter().map(|arg| arg.to_string_lossy().into_owned()).collect();
    // SCM may include the registered service name as argv[0] for ServiceMain.
    if raw.first().is_some_and(|arg| arg != "service" && !arg.starts_with('-')) {
        raw.remove(0);
    }
    let service_name = parse_service_name(raw.iter().cloned())?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            let _ = shutdown_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(&service_name, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 1,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    })?;

    let options = raw.into_iter().filter(|arg| arg != "service");
    let args = match parse_options(options) {
        Ok(args) => args,
        Err(error) => {
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::ZERO,
                process_id: None,
            });
            return Err(error);
        }
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: Some(std::process::id()),
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(run_agent(args, shutdown_rx));
    let exit_code = if result.is_ok() { ServiceExitCode::NO_ERROR } else { ServiceExitCode::Win32(1) };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    });
    result
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<OsString>) {
    if let Err(error) = run_service(arguments) {
        agent_log!("service failed: {error:#}");
    }
}

fn start_service_dispatcher(service_name: &str) -> Result<()> {
    service_dispatcher::start(service_name, ffi_service_main).context("start service dispatcher")
}

/// `--nics Ethernet,Wi-Fi` -> `["Ethernet", "Wi-Fi"]`. Whitespace around a name is
/// trimmed because a value arriving from a shell variable or a unit file
/// often carries it, and an interface name never contains a space.
///
/// Duplicates are kept: they cost nothing, because each operating-system
/// interface row is summed once rather than once per list entry.
fn parse_nics(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned).collect()
}

/// `https://host/path` -> `wss://host/path/api/agent/ws`. The token travels in
/// an Authorization header rather than the query string, keeping it out of
/// reverse-proxy access logs.
///
/// `insecure` declares that the hub has no TLS. It permits plain ws:// to a
/// remote hub and suppresses the bare-host upgrade to TLS; without the latter
/// the flag would dial a port that cannot complete a TLS handshake.
fn ws_url(server: &str, insecure: bool) -> Result<String> {
    let base = server.trim_end_matches('/');
    let scheme = if insecure { "ws" } else { "wss" };
    let base = match base.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}"),
        Some(("http", rest)) => format!("ws://{rest}"),
        Some(("wss" | "ws", _)) => base.to_owned(),
        _ => format!("{scheme}://{base}"),
    };
    // RFC 3986 places userinfo before the host, so `127.0.0.1:28080@evil.example.com`
    // reads as loopback to any check that splits at the first colon while the
    // connection goes to the name following it -- bypassing both the refusal below
    // and `--insecure`. A hub address never needs userinfo, so it is rejected.
    let authority = base.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    if authority.contains('@') {
        bail!("server URL must not contain '@': the host is whatever follows it, not what precedes it");
    }
    if base.starts_with("ws://") && !insecure && !is_loopback(&base) {
        bail!(
            "refusing plaintext ws:// to a remote hub; the token would travel in the clear. \
             Pass --insecure if that hub really has no TLS"
        );
    }
    Ok(format!("{base}/api/agent/ws"))
}

/// Parses the host rather than prefix-matching it: `127.attacker.example`
/// begins with the loopback net but resolves elsewhere. IPv6 literals are
/// bracketed, so the port is not split off at the first colon. Anything that is
/// not a literal loopback address falls to the plaintext refusal, including
/// `::ffff:127.0.0.1`.
///
/// `ws_url` has already rejected an authority containing `@`, so the first
/// colon here is the port separator.
fn is_loopback(url: &str) -> bool {
    let authority = url.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    host.parse::<std::net::IpAddr>().map_or(host == "localhost", |ip| ip.is_loopback())
}

#[derive(Deserialize)]
struct Rpc {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Deserialize, Clone, Debug)]
struct PingTask {
    id: i64,
    target: String,
    interval: u64,
}

fn notify(method: &str, params: serde_json::Value) -> Message {
    Message::Text(
        serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params}).to_string().into(),
    )
}

/// Writes under a deadline drawn from the remaining silence budget.
///
/// Reads and writes share one `select!` loop, so a socket that never drains
/// also stalls the watchdog; the kernel abandons such a socket only after
/// tcp_retries2, roughly fifteen minutes.
///
/// Charging the write against the remaining budget rather than a fresh
/// [`HUB_SILENCE`] bounds a stall at the end of a quiet stretch: two full
/// budgets would exceed the 120s after which the hub drops the node. An
/// exhausted budget fails the write and ends the session, as the watchdog
/// would have.
///
/// A timed-out write leaves a partial frame in the stream; every caller ends
/// the session on the error, discarding it with the socket.
async fn send(
    ws: &mut (impl Sink<Message, Error = WsError> + Unpin),
    m: Message,
    budget: Duration,
) -> Result<()> {
    tokio::time::timeout(budget, ws.send(m))
        .await
        .map_err(|_| anyhow!("write stalled for {}s", budget.as_secs()))?
        .context("write")
}

async fn send_or_stop(
    ws: &mut (impl Sink<Message, Error = WsError> + Unpin),
    message: Message,
    budget: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Option<Result<()>> {
    tokio::select! {
        result = send(ws, message, budget) => Some(result),
        _ = shutdown.changed() => None,
    }
}

/// Remaining silence budget, measured from the last sign of life.
///
/// Every write draws from this single window, so no sequence of writes can
/// push the give-up point beyond one [`HUB_SILENCE`] past the last frame.
fn remaining(last_frame: Instant) -> Duration {
    HUB_SILENCE.saturating_sub(last_frame.elapsed())
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1);
    let result = match command.as_deref() {
        Some("install") => install_service(parse_options(std::env::args().skip(2))?),
        Some("uninstall") => uninstall_service(&parse_service_name(std::env::args().skip(2))?),
        Some("start") => start_service(&parse_service_name(std::env::args().skip(2))?),
        Some("stop") => stop_service(&parse_service_name(std::env::args().skip(2))?),
        Some("status") => status_service(&parse_service_name(std::env::args().skip(2))?),
        Some("service") => start_service_dispatcher(&parse_service_name(std::env::args().skip(2))?),
        _ => run_foreground(parse_args()?),
    };
    if let Err(error) = &result {
        agent_log!("command failed: {error:#}");
    }
    result
}

async fn run_agent(args: Args, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let url = ws_url(&args.server, args.insecure)?;
    let mut collector = Collector::new(args.nics.clone());
    for nic in collect::missing_nics(&args.nics) {
        agent_log!("interface {nic} is not listed by the operating system; it is counted as 0 bytes");
    }
    let mut wait = 0u64;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let mut connected = None;
        let result =
            session(&url, &args.token, &mut collector, args.interval, &mut connected, &mut shutdown).await;
        if *shutdown.borrow() {
            return Ok(());
        }
        if let Err(error) = result {
            agent_log!("session ended: {error:#}");
        }
        wait = reconnect_wait(wait, connected.map_or(Duration::ZERO, |t: Instant| t.elapsed()));
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
            _ = shutdown.changed() => return Ok(()),
        }
    }
}

/// Backoff before the next connection attempt, derived from the previous wait
/// and the duration of the session that just ended -- measured from the
/// handshake, so a peer that swallows a connect for the whole
/// [`CONNECT_DEADLINE`] earns no credit.
///
/// A session that reported for a while proves the hub reachable and the token
/// valid, so the wait resets to one second. Only short-lived sessions keep
/// doubling, which keeps an agent off a hub in a crash loop.
fn reconnect_wait(previous: u64, lasted: Duration) -> u64 {
    if lasted >= Duration::from_secs(30) {
        1
    } else {
        (previous * 2).clamp(1, 60)
    }
}

/// Deadline covering all three stages of establishing a connection.
///
/// Only the TCP handshake has a deadline of its own; the TLS exchange and the
/// HTTP upgrade have none, so a peer that accepts and then goes silent would
/// leave `connect_async` pending indefinitely, and the agent running without
/// reporting or logging.
///
/// Deliberately generous: a healthy connect takes a quarter of a second, the
/// slowest measured sixty. This is not a latency budget but the point past
/// which nothing is expected to arrive.
const CONNECT_DEADLINE: Duration = Duration::from_secs(120);

/// The hub sends one kind of message, a probe list a few hundred bytes long.
/// Tungstenite's 64 MiB default would hand the peer this process's entire
/// memory budget.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long the agent waits for any frame from the hub before giving up.
///
/// The hub pings every 30 seconds and drops an agent silent for 120. Without a
/// matching watchdog, a one-way path failure -- an expired NAT entry, a route
/// gone dark -- leaves the agent writing into a socket the kernel retransmits
/// on for fifteen minutes, long after the panel has marked the node offline.
///
/// Staying under the hub's own timeout makes the agent give up first, bounding
/// recovery at this constant rather than at tcp_retries2.
const HUB_SILENCE: Duration = Duration::from_secs(90);

/// One connection: handshake, then report until the socket closes.
async fn session(
    url: &str,
    token: &str,
    collector: &mut Collector,
    interval: u64,
    connected: &mut Option<Instant>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    let mut request = url.into_client_request()?;
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().context("token is not header-safe")?);
    let config =
        WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let connect = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
    let connect_result = tokio::select! {
        result = tokio::time::timeout(CONNECT_DEADLINE, connect) => result,
        _ = shutdown.changed() => return Ok(()),
    };
    let (mut ws, _) = connect_result
        .with_context(|| format!("no connection after {}s", CONNECT_DEADLINE.as_secs()))?
        .context("connect")?;
    agent_log!("connected");
    *connected = Some(Instant::now());
    // The clock starts at the handshake and the hello below draws from it like
    // every other write, so no two writes can each claim a full HUB_SILENCE.
    let mut last_frame = Instant::now();

    let Some(result) = send_or_stop(
        &mut ws,
        notify("hello", serde_json::to_value(collector.facts())?),
        remaining(last_frame),
        shutdown.clone(),
    )
    .await
    else {
        return Ok(());
    };
    result?;

    let (result_tx, mut result_rx) = mpsc::channel::<Message>(64);
    let mut ping_tasks: Vec<(PingTask, tokio::task::JoinHandle<()>)> = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            _ = ticker.tick() => {
                let m = serde_json::to_value(collector.collect())?;
                let Some(result) = send_or_stop(&mut ws, notify("report", m), remaining(last_frame), shutdown.clone()).await else {
                    break Ok(())
                };
                if let Err(error) = result { break Err(error); }
            }
            // Rebuilt each pass from the last frame, so silence costs exactly
            // HUB_SILENCE rather than a polling interval more. Kept separate
            // from the report tick, which --interval can stretch to an hour.
            _ = tokio::time::sleep(remaining(last_frame)) => {
                break Err(anyhow!("no frame from the hub in {}s", HUB_SILENCE.as_secs()));
            }
            Some(msg) = result_rx.recv() => {
                let Some(result) = send_or_stop(&mut ws, msg, remaining(last_frame), shutdown.clone()).await else {
                    break Ok(())
                };
                if let Err(error) = result { break Err(error); }
            }
            _ = shutdown.changed() => {
                break Ok(())
            }
            incoming = ws.next() => {
                // Any frame proves the path alive, including the hub's
                // heartbeat ping -- the only one on an otherwise idle link.
                last_frame = Instant::now();
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(rpc) = serde_json::from_str::<Rpc>(&text) {
                            if rpc.method == "ping.tasks" {
                                if let Ok(tasks) = serde_json::from_value::<Vec<PingTask>>(rpc.params) {
                                    respawn_ping_tasks(&mut ping_tasks, tasks, &result_tx);
                                }
                            }
                        }
                    }
                    // Ping included: tungstenite queues the pong itself and
                    // sends it on the next read; a manual reply would duplicate it.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => break Err(e.into()),
                    None => break Ok(()),
                }
            }
        }
    };

    for (_, handle) in ping_tasks {
        handle.abort();
    }
    result
}

/// Ceiling on concurrent probe loops.
///
/// A task serialises to about forty bytes, so one [`MAX_MESSAGE`] frame could
/// request some fifteen hundred; at the five-second interval floor that is
/// hundreds of outbound connects per second to hub-chosen addresses, which on
/// a shared VPS reads as a port scan and acts as an amplifier. A compromised
/// or merely buggy hub is within the threat model, so the list is bounded
/// rather than trusted.
const MAX_PING_TASKS: usize = 64;

/// Replaces the running probe loops with the hub's current task list, leaving
/// unchanged tasks in place so their timers survive a push.
fn respawn_ping_tasks(
    running: &mut Vec<(PingTask, tokio::task::JoinHandle<()>)>,
    mut wanted: Vec<PingTask>,
    tx: &mpsc::Sender<Message>,
) {
    if wanted.len() > MAX_PING_TASKS {
        // Silent truncation would leave no record of which probes run.
        agent_log!("hub asked for {} ping tasks, running {MAX_PING_TASKS}", wanted.len());
        wanted.truncate(MAX_PING_TASKS);
    }
    running.retain(|(task, handle)| {
        let keep =
            wanted.iter().any(|w| w.id == task.id && w.target == task.target && w.interval == task.interval);
        if !keep {
            handle.abort();
        }
        keep
    });
    for task in wanted {
        if running.iter().any(|(t, _)| t.id == task.id) {
            continue;
        }
        let (tx, spawned) = (tx.clone(), task.clone());
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(spawned.interval.clamp(5, 3600)));
            // As with the report ticker, missed ticks must not fire back to
            // back: the default burst behaviour would turn one stalled
            // resolution into a rapid series of connects.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Logged once per probe per session: a resolver that overruns does
            // so every round, and the resulting gap would otherwise be
            // unexplained.
            let mut said = false;
            loop {
                ticker.tick().await;
                let Some(latency) = tcp_ping(&spawned.target).await else {
                    if !std::mem::replace(&mut said, true) {
                        agent_log!(
                            "{}: name resolution runs past {}ms, so these rounds report no sample \
                             rather than a loss",
                            spawned.target,
                            HANDSHAKE_DEADLINE.as_millis()
                        );
                    }
                    continue;
                };
                let msg =
                    notify("ping.result", serde_json::json!({"task_id": spawned.id, "latency_ms": latency}));
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        });
        running.push((task, handle));
    }
}

/// Deadline for one handshake, deliberately under the kernel's first SYN
/// retransmit.
///
/// A TCP SYN retransmission turns a dropped packet into a late success,
/// reporting the retransmit timer plus the round trip as latency.
///
/// Cutting it short guarantees that every reading belongs to a handshake
/// completed on the first SYN, and that a dropped one becomes -1. The cost is
/// that a link whose genuine round trip exceeds this reads as unreachable.
const HANDSHAKE_DEADLINE: Duration = Duration::from_millis(900);

/// How many of a name's addresses one probe attempts.
///
/// Each dead address costs a [`HANDSHAKE_DEADLINE`], and a probe must not
/// outlast the five-second floor on its own interval.
const MAX_PING_ADDRS: usize = 3;

/// Round-trip time of a TCP handshake in milliseconds; -1 when no address
/// answered within [`HANDSHAKE_DEADLINE`], `None` when the name could not be
/// resolved in that time.
///
/// The two failure modes must stay distinct. -1 is the protocol's word for a
/// target that did not answer, and the hub folds every negative reading into a
/// bucket's packet loss, so returning it for a slow resolver would draw loss on
/// a link that dropped nothing. An overrun resolution is a sample not taken,
/// which is not a reading of zero.
///
/// The name is resolved before the clock starts: `TcpStream::connect` on a
/// hostname resolves first and connects second, which would fold resolver
/// latency into every sample. Resolution is repeated each round.
///
/// ponytail: the `None` arm has no runtime reproduction; forcing it would
/// require either a genuinely overrunning resolver or a test-only deadline
/// parameter. The assertions below spell `Some(-1)`, so collapsing the two
/// answers back into one `i32` fails to compile.
async fn tcp_ping(target: &str) -> Option<i32> {
    // Bounded by the handshake deadline: a resolution slower than a connect is
    // useless as a latency sample, and `lookup_host` has no deadline of its own
    // -- a blocked system resolver can take tens of seconds.
    //
    // This does not cancel the underlying `getaddrinfo`, which runs to
    // completion on a blocking thread; it only keeps this probe on cadence.
    let Ok(resolved) = tokio::time::timeout(HANDSHAKE_DEADLINE, tokio::net::lookup_host(target)).await else {
        return None;
    };
    // A resolution error is an unreachable target, which is what -1 reports.
    // Only the deadline above is ambiguous.
    let Ok(addresses) = resolved else { return Some(-1) };
    Some(handshake(addresses).await)
}

/// Round-trip time of the first address that completes a handshake.
///
/// The clock restarts on each address, so a dead one contributes nothing;
/// summing them would report the accumulated wait as latency.
///
/// Every failure advances to the next address, refusals included. The
/// operating system may return the v6 address first; trying several
/// addresses prevents an unusable v6 route from hiding a reachable v4 target.
async fn handshake(addresses: impl Iterator<Item = std::net::SocketAddr>) -> i32 {
    for address in addresses.take(MAX_PING_ADDRS) {
        let started = std::time::Instant::now();
        if let Ok(Ok(_)) = tokio::time::timeout(HANDSHAKE_DEADLINE, TcpStream::connect(address)).await {
            return started.elapsed().as_millis().min(i32::MAX as u128) as i32;
        }
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hub_restart_costs_a_second_while_an_unreachable_one_still_backs_off() {
        // Nothing on the other end: double to the ceiling and hold. Zero is
        // what the caller passes for a connect that never completed, so a
        // stalled attempt cannot be credited as a session that ran.
        let mut wait = 0;
        let climb: Vec<u64> = (0..8)
            .map(|_| {
                wait = reconnect_wait(wait, Duration::ZERO);
                wait
            })
            .collect();
        assert_eq!(climb, [1, 2, 4, 8, 16, 32, 60, 60]);

        // A session that ran resets the wait however high it had climbed:
        // the hub-restart case.
        assert_eq!(reconnect_wait(60, Duration::from_secs(3600)), 1);
        // Connected but dropped too early to prove anything: still a retreat.
        assert_eq!(reconnect_wait(4, Duration::from_secs(29)), 8);
    }

    #[test]
    fn nics_accepts_both_spellings_and_ignores_padding() {
        assert_eq!(parse_nics("Ethernet,Wi-Fi"), ["Ethernet", "Wi-Fi"]);
        // A value from a unit file or a shell variable arrives with spaces.
        assert_eq!(parse_nics(" Ethernet , Wi-Fi "), ["Ethernet", "Wi-Fi"]);
        // A single interface is the common case, and a trailing comma from a
        // generated list is not an interface name.
        assert_eq!(parse_nics("Ethernet"), ["Ethernet"]);
        assert_eq!(parse_nics("Ethernet,"), ["Ethernet"]);
        // `--nics ""` is not a way to count nothing; it is no list at all.
        assert!(parse_nics("  ,  ").is_empty());
    }

    #[test]
    fn service_name_defaults_and_allows_independent_instances() {
        assert_eq!(parse_service_name(std::iter::empty::<String>()).unwrap(), DEFAULT_SERVICE_NAME);
        assert_eq!(
            parse_service_name(["--service-name".into(), "monitor-agent-backup".into()]).unwrap(),
            "monitor-agent-backup"
        );
        assert!(parse_service_name(["--service-name".into(), "bad/name".into()]).is_err());
    }

    #[test]
    fn ws_url_upgrades_scheme_and_refuses_plaintext_to_remote() {
        assert_eq!(ws_url("https://hub.example.com/", false).unwrap(), "wss://hub.example.com/api/agent/ws");
        assert_eq!(ws_url("http://127.0.0.1:28080", false).unwrap(), "ws://127.0.0.1:28080/api/agent/ws");
        // A bare host defaults to TLS rather than leaking the token.
        assert!(ws_url("hub.example.com", false).unwrap().starts_with("wss://"));
        assert!(ws_url("http://hub.example.com", false).is_err());
        // Bracketed IPv6 loopback is not remote.
        assert_eq!(ws_url("http://[::1]:28080", false).unwrap(), "ws://[::1]:28080/api/agent/ws");
        assert_eq!(ws_url("http://localhost:28080", false).unwrap(), "ws://localhost:28080/api/agent/ws");
        // A name that merely begins like the loopback net belongs to someone
        // else: the host is parsed, not prefix-matched.
        assert!(ws_url("http://127.attacker.example/", false).is_err());
        // Fail closed: a mapped literal is not read as loopback either.
        assert!(ws_url("http://[::ffff:127.0.0.1]:28080", false).is_err());
        // Userinfo places a loopback address where the host check looks and
        // another name where the socket goes; http::Uri resolves this authority's
        // host to evil.example.com. --insecure skips the plaintext refusal, so the
        // check cannot live inside it.
        assert!(ws_url("http://127.0.0.1:28080@evil.example.com/", false).is_err());
        assert!(ws_url("http://127.0.0.1:28080@evil.example.com/", true).is_err());
        assert!(ws_url("https://hub.example.com@evil.example.com/", false).is_err());
        // No token anywhere in the URL; it travels in a header.
        assert!(!ws_url("https://hub.example.com", false).unwrap().contains("token"));
    }

    /// `--insecure` covers a hub reached at ip:port with no TLS: it permits the
    /// plaintext hop and suppresses the bare-host TLS upgrade, which would
    /// otherwise dial wss:// at a port that cannot answer.
    #[test]
    fn insecure_allows_plaintext_to_a_remote_hub_and_stops_upgrading_bare_hosts() {
        assert_eq!(
            ws_url("http://203.0.113.10:28080", true).unwrap(),
            "ws://203.0.113.10:28080/api/agent/ws"
        );
        assert_eq!(ws_url("203.0.113.10:28080", true).unwrap(), "ws://203.0.113.10:28080/api/agent/ws");
        // An explicit https:// hub stays on TLS: the flag permits plaintext
        // rather than forcing it.
        assert_eq!(ws_url("https://hub.example.com", true).unwrap(), "wss://hub.example.com/api/agent/ws");
    }

    #[tokio::test]
    async fn tcp_ping_measures_success_and_reports_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        // A loopback handshake completes within a millisecond, so this reads 0
        // either way; what it pins is the contract that reachable is
        // non-negative and unreachable is -1.
        assert!(tcp_ping(&addr.to_string()).await.unwrap() >= 0);
        assert_eq!(tcp_ping("127.0.0.1:1").await, Some(-1), "nothing is listening there");
        // A failed resolution is an unreachable target, not a missing sample.
        // std rejects this port before the resolver is reached, so the
        // assertion needs no network.
        assert_eq!(tcp_ping("127.0.0.1:99999").await, Some(-1), "an unresolvable target is unreachable");

        // First address dead: a dual-stack target on a host whose v6 goes
        // nowhere. The probe advances rather than reporting it unreachable.
        let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(handshake([dead, addr].into_iter()).await >= 0, "a dead address must not end the probe");
        assert_eq!(handshake([dead, dead].into_iter()).await, -1, "every address failed");
        // Past the ceiling the remainder are skipped; a long address list
        // would otherwise hold a probe past its own interval.
        assert_eq!(
            handshake([dead, dead, dead, addr].into_iter()).await,
            -1,
            "a fourth address is not tried"
        );
    }

    /// The deadline must stay below a normal SYN retransmission window, or a
    /// dropped SYN is reported as latency instead of loss.
    #[test]
    fn the_handshake_deadline_stays_under_the_kernels_syn_timer() {
        assert!(
            HANDSHAKE_DEADLINE < Duration::from_secs(1),
            "a deadline at or past the 1s initial RTO lets retransmits be reported as latency"
        );
    }

    /// The hub pings every 30s and drops an agent silent for 120s. Both ends of
    /// this window are load-bearing and neither is visible from this file.
    ///
    /// The bound holds only because the watchdog sleeps to a deadline and each
    /// write draws from what remains of that same deadline; the two structures
    /// enforcing that are asserted separately below.
    #[test]
    fn the_agent_gives_up_on_a_silent_hub_before_the_hub_gives_up_on_it() {
        assert!(
            HUB_SILENCE < Duration::from_secs(120),
            "past the hub's own timeout the agent stops being what recovers the connection"
        );
        assert!(HUB_SILENCE > Duration::from_secs(60), "two lost heartbeats are a blip, not a dead link");
    }

    /// A sink that never accepts: the socket whose peer has stopped reading,
    /// which is the case the write deadline exists for.
    struct NeverDrains;

    impl Sink<Message> for NeverDrains {
        type Error = WsError;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }

        fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), WsError> {
            unreachable!("never ready")
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), WsError>> {
            std::task::Poll::Pending
        }
    }

    /// Every write draws from one clock started at the handshake, so a session
    /// gives up exactly HUB_SILENCE after its last sign of life regardless of
    /// how many writes stalled in between. The hello is the first such write.
    #[tokio::test(start_paused = true)]
    async fn a_slow_hello_cannot_push_the_give_up_point_past_the_hubs_own_timeout() {
        let handshake = Instant::now();
        assert_eq!(remaining(handshake), HUB_SILENCE, "the first write gets the whole budget");

        // A stalled hello must fail at the budget it was handed, not one of
        // its own.
        assert!(send(&mut NeverDrains, notify("hello", serde_json::json!({})), remaining(handshake))
            .await
            .is_err());
        assert_eq!(handshake.elapsed(), HUB_SILENCE, "the stall costs the budget, no more");

        // Afterwards the give-up moment stays at last_frame + HUB_SILENCE:
        // spent plus remaining is always that one window.
        for spent in [0, 30, 89, 90, 200] {
            let last_frame = Instant::now();
            tokio::time::advance(Duration::from_secs(spent)).await;
            assert_eq!(
                last_frame.elapsed() + remaining(last_frame),
                HUB_SILENCE.max(last_frame.elapsed()),
                "{spent}s in, the budget must not push the deadline out"
            );
        }
    }

    #[test]
    fn ping_tasks_keep_their_timers_unless_the_task_changed() {
        // The runtime flavour the binary uses.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _g = rt.enter();
        let (tx, _rx) = mpsc::channel(8);
        let mut running = Vec::new();
        let task = |id, target: &str, interval| PingTask { id, target: target.into(), interval };

        respawn_ping_tasks(&mut running, vec![task(1, "a:1", 60), task(2, "b:2", 60)], &tx);
        assert_eq!(running.len(), 2);
        let (first, second) = (running[0].1.id(), running[1].1.id());

        // Task 1 unchanged, task 2 retargeted, task 3 added.
        respawn_ping_tasks(
            &mut running,
            vec![task(1, "a:1", 60), task(2, "c:3", 60), task(3, "d:4", 60)],
            &tx,
        );
        assert_eq!(running.len(), 3);
        assert_eq!(running[0].1.id(), first, "unchanged task must not be restarted");
        // A task whose target changed must be torn down, or it keeps probing
        // the old address.
        assert_ne!(running[1].1.id(), second, "a retargeted task must be restarted");

        // Interval 0 must not take the probe down: tokio's interval panics on
        // a zero period, and a panicked task stops reporting silently.
        respawn_ping_tasks(&mut running, vec![task(9, "e:5", 0)], &tx);
        rt.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });
        assert!(!running[0].1.is_finished(), "a zero interval must be clamped, not panic the probe");

        // One 64 KiB frame could carry some fifteen hundred of these; the
        // agent enforces its own ceiling rather than trusting the count.
        let flood = (0..500).map(|id| task(id, "f:6", 60)).collect();
        respawn_ping_tasks(&mut running, flood, &tx);
        assert_eq!(running.len(), MAX_PING_TASKS, "the hub does not choose how many probes run");
    }
}
