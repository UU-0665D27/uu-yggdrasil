//! Минимальный пробник: TCP-пир → pathfinder → IPv6/TCP SYN к howto.ygg.
//!
//! Запуск: `cargo run --bin probe -- [host:port] [dest_hex] [dest_ipv6] [port]`.
//! Секрет фиксирован (seed 0xfe) и имеет «высокий» ключ, чтобы не стать
//! корнем тестовой сети.

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{net::Ipv6Addr, str::FromStr, time::Duration};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use uu_yggdrasil::{
    address::addr_for_key,
    ironwood::{
        Ironwood, KeyAddr, PacketConn, PacketConnBase,
        network::{Config, handshake_async, spawn_conn},
    },
};

const DEFAULT_PEER: &str = "127.0.0.1:7992";
const DEFAULT_DEST_KEY: &str = "000000002ae375e65f5470ee29eb563a0ada764c7a3f1efaa5f5a4af91dad1cb";
const DEFAULT_DEST_IP: &str = "222:a8e4:50cd:55c:788e:b0a5:4e2f:a92c";

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex key");
    }
    out
}

/// yggdrasil core проксирует через сессию `[type][payload]`,
/// где `1` — обычный IPv6-трафик, `2` — proto-сообщение.
fn session_payload(ip: &[u8]) -> Vec<u8> {
    // yggdrasil core: typeSessionDummy = 0, typeSessionTraffic = 1,
    // typeSessionProto = 2. Ironwood сам тип не добавляет.
    let mut out = Vec::with_capacity(ip.len() + 1);
    out.push(1);
    out.extend_from_slice(ip);
    out
}

fn checksum(src: &[u8; 16], dst: &[u8; 16], tcp: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        let (chunks, remainder) = bytes.as_chunks::<2>();
        for c in chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let Some(&last) = remainder.first() {
            sum += u32::from(u16::from_be_bytes([last, 0]));
        }
    };
    add(src);
    add(dst);
    add(&u32::try_from(tcp.len()).expect("TCP length").to_be_bytes());
    add(&[0, 0, 0, 6]);
    add(tcp);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("checksum")
}

#[allow(clippy::too_many_arguments)]
fn ipv6_tcp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // data offset 5
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    tcp[16..18].copy_from_slice(&0u16.to_be_bytes()); // checksum
    tcp.extend_from_slice(payload);

    let sb = src.octets();
    let db = dst.octets();
    let csum = checksum(&sb, &db, &tcp);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&u16::try_from(tcp.len()).expect("len").to_be_bytes());
    ip[6] = 6; // TCP
    ip[7] = 64;
    ip[8..24].copy_from_slice(&sb);
    ip[24..40].copy_from_slice(&db);
    ip.extend_from_slice(&tcp);
    ip
}

fn icmpv6_echo(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![0u8; 8];
    icmp[0] = 128; // echo request
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(
        &u32::try_from(icmp.len())
            .expect("ICMP length")
            .to_be_bytes(),
    );
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&icmp);
    // Тот же one's complement, но без TCP-заголовка.
    let mut sum = 0u32;
    let (chunks, remainder) = pseudo.as_chunks::<2>();
    for c in chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !u16::try_from(sum).expect("checksum");
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let mut ip = vec![0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&u16::try_from(icmp.len()).expect("len").to_be_bytes());
    ip[6] = 58;
    ip[7] = 64;
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());
    ip.extend_from_slice(&icmp);
    ip
}

fn parse_tcp(pkt: &[u8], sport: u16, dport: u16) -> Option<(u8, u32, u32, &[u8])> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 || pkt[6] != 6 {
        return None;
    }
    let tcp = &pkt[40..];
    if tcp.len() < 20 {
        return None;
    }
    let src = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst = u16::from_be_bytes([tcp[2], tcp[3]]);
    if src != dport || dst != sport {
        return None;
    }
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let flags = tcp[13];
    let off = usize::from(tcp[12] >> 4) * 4;
    Some((flags, seq, ack, &tcp[off..]))
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    uu_yggdrasil::init_tracing();
    let mut args = std::env::args().skip(1);
    let peer = args.next().unwrap_or_else(|| DEFAULT_PEER.into());
    let dest_hex = args.next().unwrap_or_else(|| DEFAULT_DEST_KEY.into());
    let dest_ip_s = args.next().unwrap_or_else(|| DEFAULT_DEST_IP.into());
    let dport: u16 = args.next().as_deref().unwrap_or("80").parse()?;

    let secret = SigningKey::from_bytes(&[0xfe; 32]);
    let our_key = secret.verifying_key();
    let our_ip = Ipv6Addr::from(addr_for_key(our_key.as_bytes()));
    let dest_key = VerifyingKey::from_bytes(&unhex32(&dest_hex))?;
    let dest_ip = Ipv6Addr::from_str(&dest_ip_s)?;

    eprintln!("local={our_ip} dest={dest_ip}:{dport} via={peer}");

    let mut stream = TcpStream::connect(&peer).await?;
    stream.set_nodelay(true)?;
    let meta = timeout(
        Duration::from_secs(6),
        handshake_async(&mut stream, &secret, b"", 0),
    )
    .await??;
    eprintln!(
        "link up: {} (v{}.{})",
        hex(&meta.public_key.as_bytes()[..4]),
        meta.major,
        meta.minor
    );

    let node = Ironwood::new(&secret, Config::default())?;
    let remote_key = meta.public_key;
    let node_task = {
        let node = node.clone();
        tokio::spawn(async move {
            let conn: Box<dyn uu_yggdrasil::ironwood::AsyncConn> = Box::new(stream);
            let _ = spawn_conn(node, remote_key, conn, 0).await;
        })
    };

    let sport =
        40000 + u16::try_from(std::process::id() % 20000).expect("ephemeral source port offset");
    let seq = 0x1234_5678u32;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_lookup = Instant::now() - Duration::from_secs(10);
    let mut synack = false;
    let mut icmp_sent = false;
    let mut buf = vec![0u8; 2048];

    while Instant::now() < deadline {
        node.do_maintenance();

        if !icmp_sent && node.peer_count() > 0 {
            let remote_ip = Ipv6Addr::from(addr_for_key(remote_key.as_bytes()));
            let pkt = session_payload(&icmpv6_echo(our_ip, remote_ip, 0x1234, 1));
            let _ = node.send_to(&pkt, &KeyAddr(remote_key)).await;
            icmp_sent = true;
        }

        if last_lookup.elapsed() >= Duration::from_secs(2) {
            node.send_lookup(dest_key.as_bytes());
            if !synack {
                let ip =
                    session_payload(&ipv6_tcp(our_ip, dest_ip, sport, dport, seq, 0, 0x02, &[]));
                let _ = node.send_to(&ip, &KeyAddr(dest_key)).await;
            }
            last_lookup = Instant::now();
        }

        match timeout(Duration::from_millis(500), node.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => {
                let mut pkt = &buf[..n];
                if !pkt.is_empty() && (pkt[0] == 1 || pkt[0] == 2) {
                    pkt = &pkt[1..];
                }
                if pkt.len() >= 48 && pkt[6] == 58 {
                    eprintln!("ICMPv6 reply type={} code={}", pkt[40], pkt[41]);
                }
                if let Some((flags, rseq, _rack, data)) = parse_tcp(pkt, sport, dport) {
                    if flags & 0x12 == 0x12 && !synack {
                        synack = true;
                        let ack = ipv6_tcp(
                            our_ip,
                            dest_ip,
                            sport,
                            dport,
                            seq.wrapping_add(1),
                            rseq.wrapping_add(1),
                            0x10,
                            &[],
                        );
                        let ack = session_payload(&ack);
                        let _ = node.send_to(&ack, &KeyAddr(dest_key)).await;
                        let get = b"GET / HTTP/1.0\r\nHost: howto.ygg\r\n\r\n";
                        let req = ipv6_tcp(
                            our_ip,
                            dest_ip,
                            sport,
                            dport,
                            seq.wrapping_add(1),
                            rseq.wrapping_add(1),
                            0x18,
                            get,
                        );
                        let req = session_payload(&req);
                        let _ = node.send_to(&req, &KeyAddr(dest_key)).await;
                        eprintln!("SYN-ACK; GET sent");
                    } else if flags & 0x10 != 0 && !data.is_empty() {
                        print!("{}", String::from_utf8_lossy(data));
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("recv error: {e}");
                break;
            }
            Err(_) => {}
        }
    }

    if !synack {
        eprintln!(
            "no SYN-ACK; peers={} path={}",
            node.peer_count(),
            node.has_path(&dest_key)
        );
    }
    node.close()?;
    let _ = timeout(Duration::from_secs(1), node_task).await;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}
