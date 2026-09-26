//! Windows metric collection through the native Win32 APIs.
//!
//! This module uses system-information, IP Helper, registry and file-system
//! APIs instead of shelling out to PowerShell or depending on localized output.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::net::IpAddr;
use std::ptr::{null, null_mut};
use std::slice;
use std::time::Instant;

use serde::Serialize;
use windows_sys::core::GUID;
use windows_sys::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemTimeOfDayInformation};
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
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_TIMEOFDAY_INFORMATION;

const DRIVE_FIXED: u32 = 3;
const WINDOWS_FILETIME_UNIX_OFFSET: u64 = 11644473600 * 10_000_000;
const LOAD_WINDOWS: [f32; 3] = [60.0, 300.0, 900.0];
const SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS: i32 = 90;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SystemBootEnvironmentInfo {
    boot_identifier: GUID,
    _firmware_type: u32,
    _boot_flags: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ifaces {
    spec: String,
    only: Vec<String>,
    skip: Vec<String>,
}

impl Ifaces {
    pub fn parse(spec: &str) -> Result<Self, String> {
        if spec.chars().any(char::is_control) {
            return Err("--iface: control characters are not valid in adapter aliases".into());
        }
        let entries: Vec<&str> = spec.split(',').map(str::trim).filter(|entry| !entry.is_empty()).collect();
        let mut ifaces = Self { spec: entries.join(","), ..Self::default() };
        for entry in entries {
            let (list, name) = match entry.strip_prefix('-') {
                Some(name) => (&mut ifaces.skip, name),
                None => (&mut ifaces.only, entry),
            };
            if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
                return Err(format!("--iface: {entry:?} is not a valid adapter alias"));
            }
            list.push(name.to_owned());
        }
        Ok(ifaces)
    }

    pub fn from_legacy(nics: Vec<String>) -> Self {
        Self { spec: nics.join(","), only: nics, skip: Vec::new() }
    }

    pub fn spec(&self) -> &str {
        &self.spec
    }

    pub fn only(&self) -> &[String] {
        &self.only
    }

    fn counts(&self, row: &MIB_IF_ROW2) -> bool {
        let name = interface_name(row);
        if self.skip.iter().any(|excluded| excluded == &name) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.iter().any(|selected| selected == &name);
        }
        row.Type != 24 && row.Type != 131 && !skip_iface(&name)
    }
}

fn epoch<'a>(boot_id: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    let digest = names
        .join("\n")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3));
    format!("{boot_id}/{digest:016x}")
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xe000 == 0x2000,
    }
}

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
    pub iface: String,
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
    ifaces: Ifaces,
    prev_cpu: Option<(u64, u64)>,
    prev_net_at: Option<Instant>,
    prev_net: HashMap<String, (u64, u64)>,
    boot_id: String,
    load: [f32; 3],
    load_at: Option<Instant>,
}

impl Collector {
    pub fn new(ifaces: Ifaces) -> Self {
        Self {
            ifaces,
            prev_cpu: None,
            prev_net_at: None,
            prev_net: HashMap::new(),
            boot_id: boot_id(),
            load: [0.0; 3],
            load_at: None,
        }
    }

    pub fn counted_ifaces(&self) -> Vec<String> {
        interface_table().iter().filter(|row| self.ifaces.counts(row)).map(interface_name).collect()
    }

    pub fn missing_ifaces(&self) -> Vec<String> {
        if self.ifaces.only().is_empty() {
            return Vec::new();
        }
        let known: Vec<String> = interface_table().iter().map(interface_name).collect();
        self.ifaces.only().iter().filter(|name| !known.contains(name)).cloned().collect()
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
        let counted: Vec<(String, u64, u64)> = interface_table()
            .iter()
            .filter(|row| self.ifaces.counts(row))
            .map(|row| (interface_name(row), row.InOctets, row.OutOctets))
            .collect();
        let (rx_total, tx_total) = counted
            .iter()
            .fold((0u64, 0u64), |(rx, tx), (_, r, t)| (rx.saturating_add(*r), tx.saturating_add(*t)));
        let boot_id = epoch(&self.boot_id, counted.iter().map(|(name, ..)| name.as_str()));
        let now = Instant::now();
        let (net_rx, net_tx) = self.net_rate(&counted, now);
        let cpu = self.cpu_percent();
        self.update_load(cpu, now);
        let (tcp, udp) = conn_counts();
        Metrics {
            boot_id,
            iface: self.ifaces.spec().to_owned(),
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

    fn net_rate(&mut self, counted: &[(String, u64, u64)], now: Instant) -> (u64, u64) {
        let rate = match self.prev_net_at {
            Some(previous) => {
                let secs = now.saturating_duration_since(previous).as_secs_f64();
                if secs <= 0.0 {
                    (0, 0)
                } else {
                    let (rx, tx) = counted
                        .iter()
                        .filter_map(|(name, rx, tx)| {
                            let (prev_rx, prev_tx) = self.prev_net.get(name)?;
                            Some((rx.saturating_sub(*prev_rx), tx.saturating_sub(*prev_tx)))
                        })
                        .fold((0u64, 0u64), |(rx, tx), (delta_rx, delta_tx)| {
                            (rx.saturating_add(delta_rx), tx.saturating_add(delta_tx))
                        });
                    ((rx as f64 / secs) as u64, (tx as f64 / secs) as u64)
                }
            }
            None => (0, 0),
        };
        self.prev_net = counted.iter().map(|(name, rx, tx)| (name.clone(), (*rx, *tx))).collect();
        self.prev_net_at = Some(now);
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

fn boot_guid(guid: GUID) -> Option<String> {
    if guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8] {
        return None;
    }
    let [d0, d1, d2, d3, d4, d5, d6, d7] = guid.data4;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1, guid.data2, guid.data3, d0, d1, d2, d3, d4, d5, d6, d7
    ))
}

fn query_boot_guid() -> Option<String> {
    let mut info = SystemBootEnvironmentInfo::default();
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS,
            (&mut info as *mut SystemBootEnvironmentInfo).cast(),
            size_of::<SystemBootEnvironmentInfo>() as u32,
            null_mut(),
        )
    };
    (status >= 0).then(|| boot_guid(info.boot_identifier)).flatten()
}

fn query_boot_time() -> Option<u64> {
    let mut info = SYSTEM_TIMEOFDAY_INFORMATION::default();
    let status = unsafe {
        NtQuerySystemInformation(
            SystemTimeOfDayInformation,
            (&mut info as *mut SYSTEM_TIMEOFDAY_INFORMATION).cast(),
            size_of::<SYSTEM_TIMEOFDAY_INFORMATION>() as u32,
            null_mut(),
        )
    };
    if status < 0 {
        return None;
    }
    let boot_time = i64::from_ne_bytes(info.Reserved1[..8].try_into().ok()?);
    let sleep_bias = u64::from_ne_bytes(info.Reserved1[40..48].try_into().ok()?);
    (boot_time > 0)
        .then_some((boot_time as u64).saturating_sub(sleep_bias).saturating_sub(WINDOWS_FILETIME_UNIX_OFFSET))
}

fn boot_id() -> String {
    if let Some(id) = query_boot_guid() {
        return format!("guid:{id}");
    }
    if let Some(boot_time) = query_boot_time() {
        return format!("time:{boot_time}");
    }

    let mut now = FILETIME::default();
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    let now = filetime(now);
    let elapsed = unsafe { GetTickCount64() }.saturating_mul(10_000);
    format!("estimate:{}", now.saturating_sub(elapsed).saturating_sub(WINDOWS_FILETIME_UNIX_OFFSET))
}

fn cpuinfo() -> (String, u32) {
    let name = registry_string(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
        .unwrap_or_else(|| "unknown".into());
    let cores =
        std::thread::available_parallelism().map(|n| n.get().min(u32::MAX as usize) as u32).unwrap_or(1);
    (name.trim().to_owned(), cores.max(1))
}

fn pick_address(held: &[IpAddr], ipv6: bool) -> String {
    held.iter()
        .filter(|ip| ip.is_ipv6() == ipv6)
        .min_by_key(|ip| !is_public(**ip))
        .map_or_else(String::new, ToString::to_string)
}

fn addresses() -> (String, String) {
    let held: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| !skip_iface(&iface.name) && !iface.is_link_local() && iface.is_oper_up())
        .map(|iface| iface.ip())
        .collect();
    (pick_address(&held, false), pick_address(&held, true))
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

#[cfg(test)]
fn counted(row: &MIB_IF_ROW2, ifaces: &Ifaces) -> bool {
    ifaces.counts(row)
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
    fn boot_guid_formats_as_a_stable_identifier() {
        let guid = GUID {
            data1: 0x0123_4567,
            data2: 0x89ab,
            data3: 0xcdef,
            data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        };
        assert_eq!(boot_guid(guid).as_deref(), Some("01234567-89ab-cdef-0123-456789abcdef"));
        assert_eq!(boot_guid(GUID::default()), None);

        assert!(
            query_boot_guid().is_some() || query_boot_time().is_some(),
            "a kernel boot-time API must be available"
        );
        if let Some(first) = query_boot_guid() {
            assert_eq!(query_boot_guid(), Some(first));
        }
        if let Some(first) = query_boot_time() {
            assert_eq!(query_boot_time(), Some(first));
        }
        assert_eq!(boot_id(), boot_id(), "the OS boot id must not vary between samples");
    }

    #[test]
    fn iface_is_in_the_metrics_protocol() {
        let metrics = Metrics { iface: "Ethernet,-vEthernet (WSL)".into(), ..Metrics::default() };
        let json = serde_json::to_value(metrics).unwrap();
        assert_eq!(json["iface"], "Ethernet,-vEthernet (WSL)");
    }

    #[test]
    fn public_addresses_win_within_each_family() {
        let held: [IpAddr; 4] = [
            "10.0.0.2".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ];
        assert_eq!(pick_address(&held, false), "8.8.8.8");
        assert_eq!(pick_address(&held, true), "2001:4860:4860::8888");
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(!is_public("100.64.1.2".parse().unwrap()));
        assert!(!is_public("198.18.0.1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
    }

    #[test]
    fn interface_filters_support_inclusions_exclusions_and_legacy_names() {
        let mut row = MIB_IF_ROW2::default();
        let alias = wide("vEthernet (WSL)");
        row.Alias[..alias.len()].copy_from_slice(&alias);
        assert!(!counted(&row, &Ifaces::default()));
        assert!(counted(&row, &Ifaces::parse("vEthernet (WSL)").unwrap()));
        assert!(!counted(&row, &Ifaces::parse("Ethernet,-vEthernet (WSL)").unwrap()));
        assert!(!counted(&row, &Ifaces::parse("-vEthernet (WSL)").unwrap()));
        assert!(counted(&row, &Ifaces::from_legacy(vec!["vEthernet (WSL)".into()])));
        row.Type = 131;
        let tunnel_alias = wide("Secure Gateway");
        row.Alias[..tunnel_alias.len()].copy_from_slice(&tunnel_alias);
        assert!(!counted(&row, &Ifaces::default()), "tunnels are excluded by default");
        assert!(
            counted(&row, &Ifaces::parse("Secure Gateway").unwrap()),
            "explicit selection overrides defaults"
        );
    }

    #[test]
    fn iface_parser_normalizes_lists_and_rejects_ambiguous_names() {
        let ifaces = Ifaces::parse(" Ethernet , Wi-Fi, -vEthernet (WSL), ").unwrap();
        assert_eq!(ifaces.spec(), "Ethernet,Wi-Fi,-vEthernet (WSL)");
        assert_eq!(ifaces.only(), ["Ethernet", "Wi-Fi"]);
        for invalid in ["-", "--Ethernet", "eth0,\ninvalid"] {
            assert!(Ifaces::parse(invalid).is_err(), "{invalid:?}");
        }
        assert!(Ifaces::parse(" , ").unwrap().spec().is_empty());
    }

    #[test]
    fn interface_epoch_tracks_the_sorted_counted_set() {
        let value = |names: &[&str]| epoch("boot", names.iter().copied());
        assert_ne!(value(&["Ethernet"]), value(&["Ethernet", "Wi-Fi"]));
        assert_ne!(value(&["Ethernet"]), value(&[]));
        assert_eq!(value(&["Wi-Fi", "Ethernet"]), value(&["Ethernet", "Wi-Fi"]));
    }

    #[test]
    fn network_rates_ignore_joining_adapters_and_counter_resets() {
        let start = Instant::now();
        let mut collector = Collector::new(Ifaces::default());
        collector.prev_net_at = Some(start);
        collector.prev_net.insert("Ethernet".into(), (100, 200));
        let current = vec![("Ethernet".into(), 150, 270), ("Wi-Fi".into(), 900, 900)];
        assert_eq!(collector.net_rate(&current, start + std::time::Duration::from_secs(1)), (50, 70));
        let reset = vec![("Ethernet".into(), 5, 10)];
        assert_eq!(collector.net_rate(&reset, start + std::time::Duration::from_secs(2)), (0, 0));
    }

    #[test]
    fn virtual_interfaces_are_not_billed_by_default() {
        for name in ["vEthernet (WSL)", "Loopback Pseudo-Interface 1", "Tailscale"] {
            assert!(skip_iface(name), "{name}");
        }
        assert!(!skip_iface("Ethernet"));
    }

    #[test]
    fn listed_adapter_alias_overrides_default_filtering() {
        let mut row = MIB_IF_ROW2 { Type: 24, ..Default::default() };
        let alias = wide("Loopback Pseudo-Interface 1");
        row.Alias[..alias.len()].copy_from_slice(&alias);
        assert!(!counted(&row, &Ifaces::default()));
        assert!(counted(&row, &Ifaces::parse("Loopback Pseudo-Interface 1").unwrap()));
    }
}
