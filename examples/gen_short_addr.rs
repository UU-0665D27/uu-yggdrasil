use ed25519_dalek::SigningKey;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::{
    fmt::Write,
    fs, io,
    net::Ipv6Addr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

const PREFIX: u8 = 0x02;

fn save_best(best: &Best) -> io::Result<()> {
    let addr = Ipv6Addr::from(best.addr).to_string();

    // privpub = hex(seed) || hex(pub) = Yggdrasil PrivateKey (128 hex)
    let privpub = format!("{}{}", hex(&best.seed), hex(&best.pubkey));
    debug_assert_eq!(privpub.len(), 128);

    fs::create_dir_all("keys")?;

    let addr_safe: String = addr
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    let fname = format!(
        "keys/key_{}_{}_{}.txt",
        best.len,
        addr_safe,
        hex(&best.pubkey)
    );

    // Содержимое — только privpub + \n (для copy-paste в yggdrasil.conf)
    fs::write(&fname, format!("{privpub}\n"))?;
    fs::write("keys/BEST.txt", format!("{privpub}\n"))?;
    Ok(())
}

// Быстрая версия: temp ограничен 14 байтами адреса, без Vec.
fn addr_for_key(key: &[u8; 32]) -> [u8; 16] {
    let mut inverted = [0u8; 32];
    for (d, s) in inverted.iter_mut().zip(key) {
        *d = !*s;
    }

    let mut addr = [0u8; 16];
    addr[0] = PREFIX;

    let mut done = false;
    let mut ones: u8 = 0;
    let mut acc: u8 = 0;
    let mut acc_bits: u8 = 0;
    let mut out = 2usize;

    for idx in 0..256 {
        let bit = (inverted[idx >> 3] >> (7 - (idx & 7))) & 1;
        if !done {
            if bit == 1 {
                ones = ones.wrapping_add(1);
            } else {
                done = true;
            }
            continue;
        }
        acc = (acc << 1) | bit;
        acc_bits += 1;
        if acc_bits == 8 {
            if out < 16 {
                addr[out] = acc;
                out += 1;
            }
            acc = 0;
            acc_bits = 0;
        }
    }
    addr[1] = ones;
    addr
}

struct Best {
    len: usize,
    addr: [u8; 16],
    pubkey: [u8; 32],
    seed: [u8; 32],
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn main() {
    let best_len = AtomicUsize::new(usize::MAX);
    let best = Mutex::new(Option::<Best>::None);
    let start = Instant::now();
    let threads = rayon::current_num_threads();
    eprintln!("Ищем с {threads} потоками, Ctrl-C для остановки");

    (0..threads).into_par_iter().for_each(|_| {
        loop {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("gen");
            let sk = SigningKey::from_bytes(&seed);
            let pk = sk.verifying_key().to_bytes();
            let addr = addr_for_key(&pk);

            // Быстрый отсев: без хотя бы одного нулевого байта в ключевой части
            // адрес не может стать короче (нулевой байт — единственный шанс
            // получить «::» или срез ведущих нулей).
            if !addr[2..].contains(&0) && best_len.load(Ordering::Relaxed) != usize::MAX {
                continue;
            }

            let s = Ipv6Addr::from(addr).to_string();
            let len = s.len();

            if len < best_len.load(Ordering::Relaxed) {
                let mut g = best.lock().unwrap();
                if g.as_ref().is_none_or(|b| len < b.len) {
                    let seed = sk.to_bytes();
                    *g = Some(Best {
                        len,
                        addr,
                        pubkey: pk,
                        seed,
                    });
                    best_len.store(len, Ordering::Relaxed);

                    if let Err(e) = save_best(g.as_ref().unwrap()) {
                        eprintln!("save failed: {e}");
                    }
                    drop(g);
                    println!(
                        "[{:>8.2}s] len={len} addr={s} pub={}",
                        start.elapsed().as_secs_f64(),
                        hex(&pk)
                    );
                }
            }
        }
    });
}
