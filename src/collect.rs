//! Windows metric collection through the native Win32 APIs.
//!
//! This module uses system-information, IP Helper, registry and file-system
//! APIs instead of shelling out to PowerShell or depending on localized output.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::slice;
use std::time::Instant;

use serde::Serialize;
use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Foundation::{FILETIME, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetTcpStatisticsEx, GetUdpStatisticsEx, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_TCPSTATS_LH, MIB_UDPSTATS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives};
use windows_sys::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNamePhysicalDnsHostname, GetComputerNameExW, GetSystemTimeAsFileTime, GetTickCount64,
    GlobalMemoryStatusEx, MEMORYSTATUSEX, OSVERSIONINFOW,
};
use windows_sys::Win32::System::Threading::GetSystemTimes;

const DRIVE_FIXED: u32 = 3;
const WINDOWS_FILETIME_UNIX_OFFSET: u64 = 11644473600 * 10_000_000;
const LOAD_WINDOWS: [f32; 3] = [60.0, 300.0, 900.0];

const VIRTUAL_INTERFACE_WORDS: &[&str] = &[
    "loopback",
    "teredo",
    "isatap",
    "6to4",
    "wsl",
    "veth",
    "vethernet",
    "docker",
    "virtualbox",
    "vmware",
    "wireguard",
    "tailscale",
    "zerotier",
    "tap-windows",
    "hyper-v",
    "default switch",
];

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Facts {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub virt: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub mem_total: u64,
    pub swap_total: u64,
    pub disk_total: u64,
    pub agent_version: String,
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    pub boot_id: String,
    pub uptime: u64,
    pub cpu: f32,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub tcp: u32,
    pub udp: u32,
    pub procs: u32,
}

pub struct Collector {
    nics: Vec<String>,
    prev_cpu: Option<(u64, u64)>,
    prev_net: Option<(Instant, u64, u64)>,
    boot_id: String,
    load: [f32; 3],
    load_at: Option<Instant>,
}

impl Collector {
    pub fn new(nics: Vec<String>) -> Self {
        Self { nics, prev_cpu: None, prev_net: None, boot_id: boot_id(), load: [0.0; 3], load_at: None }
    }

    pub fn facts(&self) -> Facts {
        let (ipv4, ipv6) = addresses();
        let (mem_total, _, swap_total, _) = memory();
        let (disk_total, _) = disk_usage();
        let (cpu_name, cpu_cores) = cpuinfo();
        let version = windows_version();
        Facts {
            hostname: hostname(),
            os: "Windows".into(),
            kernel: version,
            arch: std::env::consts::ARCH.into(),
            virt: virtualization(),
            cpu_name,
            cpu_cores,
            mem_total,
            swap_total,
            disk_total,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            ipv4,
            ipv6,
        }
    }

    pub fn collect(&mut self) -> Metrics {
        let (mem_total, mem_used, swap_total, swap_used) = memory();
        let (disk_total, disk_used) = disk_usage();
        let (rx_total, tx_total) = net_totals(&self.nics);
        let now = Instant::now();
        let (net_rx, net_tx) = self.net_rate(rx_total, tx_total, now);
        let cpu = self.cpu_percent();
        self.update_load(cpu, now);
        let (tcp, udp) = conn_counts();
        Metrics {
            boot_id: self.boot_id.clone(),
            uptime: uptime(),
            cpu,
            load: self.load,
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            disk_total,
            disk_used,
            net_rx_total: rx_total,
            net_tx_total: tx_total,
            net_rx,
            net_tx,
            tcp,
            udp,
            procs: proc_count(),
        }
    }

    fn cpu_percent(&mut self) -> f32 {
        let Some(now) = system_times() else { return 0.0 };
        let pct = self.prev_cpu.map_or(0.0, |prev| busy_percent(prev, now));
        self.prev_cpu = Some(now);
        pct
    }

    fn update_load(&mut self, cpu: f32, now: Instant) {
        let target = cpu * cpuinfo().1 as f32 / 100.0;
        let Some(previous) = self.load_at.replace(now) else {
            self.load = [target; 3];
            return;
        };
        let elapsed = now.saturating_duration_since(previous).as_secs_f32();
        for (load, window) in self.load.iter_mut().zip(LOAD_WINDOWS) {
            let alpha = 1.0 - (-elapsed / window).exp();
            *load += (target - *load) * alpha;
        }
    }

    fn net_rate(&mut self, rx: u64, tx: u64, now: Instant) -> (u64, u64) {
        let rate = match self.prev_net {
            Some((previous, previous_rx, previous_tx)) => {
                let secs = now.saturating_duration_since(previous).as_secs_f64();
                if secs <= 0.0 {
                    (0, 0)
                } else {
                    (
                        (rx.saturating_sub(previous_rx) as f64 / secs) as u64,
                        (tx.saturating_sub(previous_tx) as f64 / secs) as u64,
                    )
                }
            }
            None => (0, 0),
        };
        self.prev_net = Some((now, rx, tx));
        rate
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_string(value: &[u16]) -> String {
    let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn hostname() -> String {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    let ok = unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buffer.as_mut_ptr(), &mut size) };
    if ok != 0 && size > 0 {
        String::from_utf16_lossy(&buffer[..size as usize])
    } else {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    }
}

fn windows_version() -> String {
    let mut info =
        OSVERSIONINFOW { dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32, ..Default::default() };
    let status = unsafe { RtlGetVersion(&mut info) };
    if status == 0 {
        format!("{}.{}.{}", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
    } else {
        "unknown".into()
    }
}

fn memory() -> (u64, u64, u64, u64) {
    let mut status = MEMORYSTATUSEX { dwLength: size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return (0, 0, 0, 0);
    }
    // Windows exposes the commit limit as "TotalPageFile": physical memory
    // plus page files. Subtracting physical memory keeps the wire field's
    // swap meaning instead of reporting all RAM as swap.
    let commit_total = status.ullTotalPageFile;
    let commit_used = commit_total.saturating_sub(status.ullAvailPageFile);
    let physical_used = status.ullTotalPhys.saturating_sub(status.ullAvailPhys);
    let swap_total = commit_total.saturating_sub(status.ullTotalPhys);
    let swap_used = commit_used.saturating_sub(physical_used).min(swap_total);
    (status.ullTotalPhys, physical_used, swap_total, swap_used)
}

fn system_times() -> Option<(u64, u64)> {
    let (mut idle, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default());
    if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
        return None;
    }
    let idle = filetime(idle);
    let total = filetime(kernel).saturating_add(filetime(user));
    Some((total, idle))
}

fn filetime(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn busy_percent(previous: (u64, u64), current: (u64, u64)) -> f32 {
    let ((previous_total, previous_idle), (total, idle)) = (previous, current);
    if total <= previous_total {
        return 0.0;
    }
    let total_delta = (total - previous_total) as f32;
    let idle_delta = idle.saturating_sub(previous_idle) as f32;
    ((total_delta - idle_delta) / total_delta * 100.0).clamp(0.0, 100.0)
}

fn uptime() -> u64 {
    unsafe { GetTickCount64() / 1000 }
}

fn boot_id() -> String {
    let mut now = FILETIME::default();
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    let now = filetime(now);
    let elapsed = unsafe { GetTickCount64() }.saturating_mul(10_000);
    now.saturating_sub(elapsed).saturating_sub(WINDOWS_FILETIME_UNIX_OFFSET).to_string()
}

fn cpuinfo() -> (String, u32) {
    let name = registry_string(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
        .unwrap_or_else(|| "unknown".into());
    let cores =
        std::thread::available_parallelism().map(|n| n.get().min(u32::MAX as usize) as u32).unwrap_or(1);
    (name.trim().to_owned(), cores.max(1))
}

fn addresses() -> (String, String) {
    let (mut ipv4, mut ipv6) = (String::new(), String::new());
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if skip_iface(&iface.name) || iface.is_link_local() || !iface.is_oper_up() {
            continue;
        }
        match iface.ip() {
            std::net::IpAddr::V4(ip) if ipv4.is_empty() => ipv4 = ip.to_string(),
            std::net::IpAddr::V6(ip) if ipv6.is_empty() => ipv6 = ip.to_string(),
            _ => {}
        }
    }
    (ipv4, ipv6)
}

fn interface_table() -> Vec<MIB_IF_ROW2> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    let status = unsafe { GetIfTable2(&mut table) };
    if status != NO_ERROR || table.is_null() {
        return Vec::new();
    }
    let rows =
        unsafe { slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize).to_vec() };
    unsafe { FreeMibTable(table.cast::<c_void>()) };
    rows
}

fn interface_name(row: &MIB_IF_ROW2) -> String {
    let alias = wide_string(&row.Alias);
    if alias.is_empty() {
        wide_string(&row.Description)
    } else {
        alias
    }
}

fn net_totals(nics: &[String]) -> (u64, u64) {
    interface_table()
        .iter()
        .filter(|row| counted(row, nics))
        .fold((0, 0), |(rx, tx), row| (rx.saturating_add(row.InOctets), tx.saturating_add(row.OutOctets)))
}

fn counted(row: &MIB_IF_ROW2, nics: &[String]) -> bool {
    let name = interface_name(row);
    if !nics.is_empty() {
        return nics.iter().any(|nic| nic == &name);
    }
    row.Type != 24 && !skip_iface(&name)
}

pub fn missing_nics(nics: &[String]) -> Vec<String> {
    if nics.is_empty() {
        return Vec::new();
    }
    let known: Vec<String> = interface_table().iter().map(interface_name).collect();
    nics.iter().filter(|nic| !known.contains(nic)).cloned().collect()
}

fn skip_iface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_INTERFACE_WORDS.iter().any(|word| lower.contains(word))
}

fn disk_usage() -> (u64, u64) {
    let drives = unsafe { GetLogicalDrives() };
    let mut total = 0u64;
    let mut used = 0u64;
    for bit in 0..26 {
        if drives & (1 << bit) == 0 {
            continue;
        }
        let path = [(b'A' + bit as u8) as u16, b':' as u16, b'\\' as u16, 0];
        if unsafe { GetDriveTypeW(path.as_ptr()) } != DRIVE_FIXED {
            continue;
        }
        let (mut available, mut capacity, mut free) = (0, 0, 0);
        if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut available, &mut capacity, &mut free) } != 0 {
            total = total.saturating_add(capacity);
            used = used.saturating_add(capacity.saturating_sub(free));
        }
    }
    (total, used)
}

fn conn_counts() -> (u32, u32) {
    let mut tcp = 0u32;
    let mut udp = 0u32;
    for family in [AF_INET as u32, AF_INET6 as u32] {
        let mut tcp_stats = MIB_TCPSTATS_LH::default();
        if unsafe { GetTcpStatisticsEx(&mut tcp_stats, family) } == NO_ERROR {
            tcp = tcp.saturating_add(tcp_stats.dwNumConns);
        }
        let mut udp_stats = MIB_UDPSTATS::default();
        if unsafe { GetUdpStatisticsEx(&mut udp_stats, family) } == NO_ERROR {
            udp = udp.saturating_add(udp_stats.dwNumAddrs);
        }
    }
    (tcp, udp)
}

fn proc_count() -> u32 {
    let mut info =
        PERFORMANCE_INFORMATION { cb: size_of::<PERFORMANCE_INFORMATION>() as u32, ..Default::default() };
    if unsafe { GetPerformanceInfo(&mut info, size_of::<PERFORMANCE_INFORMATION>() as u32) } != 0 {
        info.ProcessCount
    } else {
        0
    }
}

fn registry_string(path: &str, value: &str) -> Option<String> {
    let path = wide(path);
    let value = wide(value);
    let mut key: HKEY = null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status != NO_ERROR {
        return None;
    }

    let mut kind = 0;
    let mut bytes = 0u32;
    let status = unsafe { RegQueryValueExW(key, value.as_ptr(), null(), &mut kind, null_mut(), &mut bytes) };
    if status != NO_ERROR || kind != REG_SZ || bytes < 2 {
        unsafe { RegCloseKey(key) };
        return None;
    }
    let mut data = vec![0u8; bytes as usize];
    let status =
        unsafe { RegQueryValueExW(key, value.as_ptr(), null(), &mut kind, data.as_mut_ptr(), &mut bytes) };
    unsafe { RegCloseKey(key) };
    if status != NO_ERROR || bytes < 2 {
        return None;
    }
    let (pairs, _) = data[..bytes as usize].as_chunks::<2>();
    let words: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    Some(wide_string(&words))
}

fn virtualization() -> String {
    let values = [
        registry_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
        registry_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
    ];
    let text = values.iter().filter_map(Option::as_deref).collect::<Vec<_>>().join(" ").to_ascii_lowercase();
    for (needle, name) in [
        ("vmware", "vmware"),
        ("virtualbox", "virtualbox"),
        ("qemu", "qemu"),
        ("kvm", "kvm"),
        ("xen", "xen"),
        ("amazon", "amazon"),
        ("google", "google"),
        ("virtual machine", "hyper-v"),
    ] {
        if text.contains(needle) {
            return name.into();
        }
    }
    "none".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_percent_uses_system_time_deltas() {
        assert_eq!(busy_percent((1000, 900), (1200, 950)), 75.0);
        assert_eq!(busy_percent((1000, 900), (1200, 1100)), 0.0);
        assert_eq!(busy_percent((1000, 900), (500, 400)), 0.0);
    }

    #[test]
    fn virtual_interfaces_are_not_billed_by_default() {
        for name in ["vEthernet (WSL)", "Loopback Pseudo-Interface 1", "Tailscale"] {
            assert!(skip_iface(name), "{name}");
        }
        assert!(!skip_iface("Ethernet"));
    }

    #[test]
    fn named_interfaces_override_virtual_interface_filtering() {
        let mut row = MIB_IF_ROW2::default();
        let alias = wide("vEthernet");
        row.Alias[..alias.len()].copy_from_slice(&alias);
        assert!(!counted(&row, &[]));
        assert!(counted(&row, &["vEthernet".into()]));
        assert!(!counted(&row, &["Ethernet".into()]));
    }
}
