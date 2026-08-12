//! PacketEye — pcap-based traffic analyzer.
//!
//! Modes:
//!   live   <iface> [count]   — capture from an interface
//!   file   <dump.pcap>       — parse an offline capture
//!
//! Reports per-IP and per-port volume, protocol mix, top talkers, and a
//! connection summary (TCP SYN/ACK pairs, TCP/UDP/ICMP counts).

use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;

const VERSION: &str = "1.0.0";

#[derive(Default, Clone, Debug)]
struct ProtoStats {
    tcp: u64,
    udp: u64,
    icmp: u64,
    other: u64,
}

#[derive(Default, Debug)]
struct Summary {
    total: u64,
    bytes: u64,
    per_ip: HashMap<Ipv4Addr, u64>,
    per_port: HashMap<u16, u64>,
    tcp_syn: u64,
    tcp_synack: u64,
    protocols: ProtoStats,
}

/// Minimal Ethernet/IP/TCP/UDP/ICMP parsing — enough for solid stats.
fn analyze_packet(data: &[u8], summary: &mut Summary) {
    summary.total += 1;
    summary.bytes += data.len() as u64;

    // Ethernet header (14 bytes): dst(6) src(6) ethertype(2).
    if data.len() < 14 {
        return;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip_start = match ethertype {
        0x0800 => 14,       // IPv4
        0x86dd => return,   // IPv6: skip detailed parse
        _ => return,
    };

    // IPv4 header.
    if data.len() < ip_start + 20 {
        return;
    }
    let ihl = ((data[ip_start] & 0x0f) as usize) * 4;
    if ihl < 20 || data.len() < ip_start + ihl {
        return;
    }
    let src = Ipv4Addr::new(data[ip_start + 12], data[ip_start + 13], data[ip_start + 14], data[ip_start + 15]);
    let dst = Ipv4Addr::new(data[ip_start + 16], data[ip_start + 17], data[ip_start + 18], data[ip_start + 19]);
    let protocol = data[ip_start + 9];

    *summary.per_ip.entry(src).or_insert(0) += 1;
    *summary.per_ip.entry(dst).or_insert(0) += 1;

    let l4 = ip_start + ihl;
    match protocol {
        6 => {
            // TCP
            summary.protocols.tcp += 1;
            if data.len() < l4 + 20 {
                return;
            }
            let sport = u16::from_be_bytes([data[l4], data[l4 + 1]]);
            let dport = u16::from_be_bytes([data[l4 + 2], data[l4 + 3]]);
            *summary.per_port.entry(sport).or_insert(0) += 1;
            *summary.per_port.entry(dport).or_insert(0) += 1;
            let flags = data[l4 + 13];
            if flags & 0x02 != 0 && flags & 0x10 != 0 {
                summary.tcp_synack += 1;
            } else if flags & 0x02 != 0 {
                summary.tcp_syn += 1;
            }
        }
        17 => {
            // UDP
            summary.protocols.udp += 1;
            if data.len() < l4 + 8 {
                return;
            }
            let sport = u16::from_be_bytes([data[l4], data[l4 + 1]]);
            let dport = u16::from_be_bytes([data[l4 + 2], data[l4 + 3]]);
            *summary.per_port.entry(sport).or_insert(0) += 1;
            *summary.per_port.entry(dport).or_insert(0) += 1;
        }
        1 => summary.protocols.icmp += 1,
        _ => summary.protocols.other += 1,
    }
}

fn print_report(summary: &Summary, label: &str) {
    println!("\n=== report: {label} ===");
    println!("packets: {} | bytes: {}", summary.total, summary.bytes);
    println!(
        "protocols: tcp={} udp={} icmp={} other={}",
        summary.protocols.tcp, summary.protocols.udp, summary.protocols.icmp, summary.protocols.other
    );
    println!("tcp handshakes: syn={} synack={}", summary.tcp_syn, summary.tcp_synack);

    let mut ips: Vec<(&Ipv4Addr, &u64)> = summary.per_ip.iter().collect();
    ips.sort_by(|a, b| b.1.cmp(a.1));
    println!("\ntop talkers (by packets):");
    for (ip, count) in ips.iter().take(10) {
        println!("  {ip:>15}  {count}");
    }

    let mut ports: Vec<(&u16, &u64)> = summary.per_port.iter().collect();
    ports.sort_by(|a, b| b.1.cmp(a.1));
    println!("\ntop ports (by packets):");
    for (port, count) in ports.iter().take(15) {
        println!("  {port:<6}  {count}");
    }
}

fn live_mode(iface: &str, count: usize) -> Result<(), String> {
    let mut cap = pcap::Capture::from_device(iface)
        .map_err(|e| format!("cannot open {iface}: {e}"))?
        .promisc(true)
        .snaplen(65535)
        .timeout(200)
        .open()
        .map_err(|e| format!("cannot open {iface}: {e}"))?;

    let mut summary = Summary::default();
    let mut seen = 0usize;
    println!("[*] PacketEye {VERSION} | listening on {iface} (promisc)");
    println!("[*] Ctrl+C to stop\n");
    while count == 0 || seen < count {
        match cap.next_packet() {
            Ok(pkt) => {
                analyze_packet(pkt.data, &mut summary);
                seen += 1;
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("warning: {e}");
                break;
            }
        }
    }
    print_report(&summary, &format!("live {iface} ({seen} pkts)"));
    Ok(())
}

fn file_mode(path: &str) -> Result<(), String> {
    let mut cap = pcap::Capture::from_file(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let mut summary = Summary::default();
    let mut seen = 0usize;
    while let Ok(pkt) = cap.next_packet() {
        analyze_packet(pkt.data, &mut summary);
        seen += 1;
    }
    print_report(&summary, &format!("file {path} ({seen} pkts)"));
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        println!(
            "PacketEye {VERSION} — pcap traffic analyzer\n\
             \n\
             USAGE:\n  packeteye live <iface> [count]   capture live (count=0 for infinite)\n  packeteye file <dump.pcap>        parse offline capture\n\
             \n\
             EXAMPLES:\n  sudo packeteye live eth0\n  packeteye file capture.pcap\n  sudo packeteye live wlan0 1000"
        );
        return;
    }

    let result = match args[0].as_str() {
        "live" => {
            let iface = args.get(1).expect("usage: packeteye live <iface> [count]");
            let count = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);
            live_mode(iface, count)
        }
        "file" => {
            let path = args.get(1).expect("usage: packeteye file <dump.pcap>");
            file_mode(path)
        }
        other => Err(format!("unknown command: {other}")),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
