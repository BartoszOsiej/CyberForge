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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet + IPv4 + TCP SYN frame.
    fn tcp_syn_frame() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 6]);      // dst MAC
        pkt.extend_from_slice(&[0u8; 6]);      // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]);  // EtherType IPv4
        // IPv4 header (20 bytes, IHL=5, protocol=6 TCP).
        pkt.push(0x45);                        // version + IHL
        pkt.push(0x00);                        // DSCP/ECN
        pkt.extend_from_slice(&[0x00, 0x2c]);  // total length
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id/flags/frag
        pkt.push(64);                          // TTL
        pkt.push(6);                           // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]);  // checksum (ignored)
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src IP
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst IP
        // TCP header (20 bytes), SYN flag set.
        pkt.extend_from_slice(&[0x30, 0x39]);  // sport 12345
        pkt.extend_from_slice(&[0x00, 0x50]);  // dport 80
        pkt.extend_from_slice(&[0u8; 4]);      // seq
        pkt.extend_from_slice(&[0u8; 4]);      // ack
        pkt.push(0x50);                        // data offset 5
        pkt.push(0x02);                        // flags: SYN
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // window/checksum/urg
        pkt
    }

    #[test]
    fn counts_tcp_syn_into_summary() {
        let mut s = Summary::default();
        analyze_packet(&tcp_syn_frame(), &mut s);
        assert_eq!(s.total, 1);
        assert_eq!(s.tcp_syn, 1);
        assert_eq!(s.tcp_synack, 0);
        assert_eq!(s.protocols.tcp, 1);
        assert_eq!(s.per_ip.get(&Ipv4Addr::new(10, 0, 0, 1)), Some(&1));
        assert_eq!(s.per_port.get(&80), Some(&1));
        assert_eq!(s.bytes, tcp_syn_frame().len() as u64);
    }

    #[test]
    fn short_garbage_is_safe() {
        let mut s = Summary::default();
        analyze_packet(&[0u8; 5], &mut s);
        assert_eq!(s.total, 1);
        assert_eq!(s.protocols.other, 0); // too short to parse L3
    }

    #[test]
    fn icmp_is_counted() {
        let mut pkt = tcp_syn_frame();
        pkt[14 + 9] = 1; // protocol -> ICMP
        let mut s = Summary::default();
        analyze_packet(&pkt, &mut s);
        assert_eq!(s.protocols.icmp, 1);
        assert_eq!(s.protocols.tcp, 0);
    }

    #[test]
    fn tcp_synack_is_counted() {
        let mut pkt = tcp_syn_frame();
        pkt[14 + 20 + 13] = 0x12; // flags: SYN|ACK
        let mut s = Summary::default();
        analyze_packet(&pkt, &mut s);
        assert_eq!(s.tcp_synack, 1);
        assert_eq!(s.tcp_syn, 0);
    }

    #[test]
    fn tcp_fin_counts_as_tcp_traffic_not_handshake() {
        let mut pkt = tcp_syn_frame();
        pkt[14 + 20 + 13] = 0x01; // flags: FIN
        let mut s = Summary::default();
        analyze_packet(&pkt, &mut s);
        assert_eq!(s.protocols.tcp, 1);
        assert_eq!(s.tcp_syn, 0);
        assert_eq!(s.tcp_synack, 0);
    }

    #[test]
    fn udp_is_counted_with_ports() {
        let mut pkt = tcp_syn_frame();
        pkt[14 + 9] = 17; // protocol -> UDP
        // Replace the TCP header with an 8-byte UDP header: sport 12345, dport 53.
        pkt[14 + 20] = 0x30;
        pkt[14 + 21] = 0x39;
        pkt[14 + 22] = 0x00;
        pkt[14 + 23] = 0x35;
        pkt[14 + 24] = 0x00;
        pkt[14 + 25] = 0x08;
        pkt[14 + 26] = 0x00;
        pkt[14 + 27] = 0x00;
        let mut s = Summary::default();
        analyze_packet(&pkt, &mut s);
        assert_eq!(s.protocols.udp, 1);
        assert_eq!(s.protocols.tcp, 0);
        assert_eq!(s.per_port.get(&53), Some(&1));
        assert_eq!(s.per_port.get(&12345), Some(&1));
    }

    #[test]
    fn arp_frames_are_counted_without_protocol_classification() {
        let mut pkt = tcp_syn_frame();
        pkt[12] = 0x08;
        pkt[13] = 0x06; // EtherType ARP (not IPv4)
        let mut s = Summary::default();
        analyze_packet(&pkt, &mut s);
        assert_eq!(s.total, 1);
        assert_eq!(s.protocols.tcp, 0);
        assert_eq!(s.protocols.udp, 0);
        assert_eq!(s.per_ip.len(), 0); // no L3 parse
    }

    #[test]
    fn ipv6_frames_are_counted_as_total_but_not_parsed() {
        let mut pkt = tcp_syn_frame();
        pkt[12] = 0x86;
        pkt[13] = 0xdd; // EtherType IPv6
        let mut s = Summary::default();
        analyze_packet(&pkt, &mut s);
        assert_eq!(s.total, 1);
        assert_eq!(s.protocols.other, 0); // skipped without classification
        assert_eq!(s.per_ip.len(), 0);
    }
}
