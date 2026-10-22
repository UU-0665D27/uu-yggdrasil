#![no_main]

use libfuzzer_sys::fuzz_target;

use std::time::{Duration, Instant};
use uu_yggdrasil::ironwood::encrypted::{
    crypto::{EdPriv, GroupAuth},
    session::{SessionEvent, SessionManager},
};

const MAX_MANAGERS: usize = 4;
const SEED_BYTES: usize = 4;
const MAX_PAYLOAD: usize = 128;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // data[0] — количество менеджеров (1..=4).
    let n_managers = (data[0] as usize % MAX_MANAGERS) + 1;

    // data[2..2 + n*4] — seed'ы (по 4 байта на менеджера).
    let seeds_end = (2 + n_managers * SEED_BYTES).min(data.len());

    let mut managers = Vec::with_capacity(n_managers);
    let mut keys = Vec::with_capacity(n_managers);
    for i in 0..n_managers {
        let mut seed = [0u8; 32];
        seed[0] = i as u8;
        for j in 0..SEED_BYTES {
            let pos = 2 + i * SEED_BYTES + j;
            if pos < seeds_end {
                seed[1 + j] = data[pos];
            }
        }
        let ed = EdPriv::from_bytes(&seed);
        keys.push(ed.verifying_key());
        managers.push(SessionManager::new(ed, GroupAuth::new("")));
    }

    let body = &data[seeds_end..];
    let mut now = Instant::now();
    let mut i = 0;
    while i < body.len() {
        let op = body[i];
        i += 1;
        match op % 4 {
            // handle_data: from → to, сырые байты (init/ack/traffic/мусор).
            0 if i + 2 <= body.len() => {
                let from_i = (body[i] as usize) % n_managers;
                let to_i = (body[i + 1] as usize) % n_managers;
                i += 2;
                let end = (i + MAX_PAYLOAD).min(body.len());
                let payload = &body[i..end];
                i = end;
                let events = managers[to_i].handle_data(keys[from_i], payload, now);
                for ev in events {
                    match ev {
                        SessionEvent::Send { dest, .. } => {
                            assert!(keys.contains(&dest), "Send to unknown key");
                        }
                        SessionEvent::Deliver { from, .. } => {
                            assert!(keys.contains(&from), "Deliver from unknown key");
                        }
                    }
                }
            }
            // write_to: from → to, сгенерированный payload.
            1 if i + 2 <= body.len() => {
                let from_i = (body[i] as usize) % n_managers;
                let to_i = (body[i + 1] as usize) % n_managers;
                i += 2;
                let len = (op as usize) % 64;
                let msg = vec![0xAAu8; len];
                let events = managers[from_i].write_to(keys[to_i], msg, now);
                for ev in events {
                    if let SessionEvent::Send { dest, .. } = ev {
                        assert_eq!(dest, keys[to_i], "write_to: wrong dest");
                    }
                }
            }
            // do_maintenance + сдвиг времени на 1 с.
            2 => {
                for m in &mut managers {
                    m.do_maintenance(now);
                }
                now += Duration::from_secs(1);
            }
            // Прочитать счётчики (no panic).
            3 if i < body.len() => {
                let idx = (body[i] as usize) % n_managers;
                i += 1;
                let _ = managers[idx].session_count();
                let _ = managers[idx].buffer_count();
            }
            _ => break,
        }
    }

    // Финальная проверка: после всей нагрузки узел консистентен.
    for m in &managers {
        let _ = m.session_count();
        let _ = m.buffer_count();
    }
});
