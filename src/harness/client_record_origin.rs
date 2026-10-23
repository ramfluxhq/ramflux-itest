// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Mutable signed-record test origin for negative discovery scenarios.
use crate::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct ClientRecordOrigin {
    pub(crate) url: String,
    record: Arc<Mutex<ramflux_protocol::WellKnownClientRecord>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ClientRecordOrigin {
    pub(crate) fn start(
        record: ramflux_protocol::WellKnownClientRecord,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        let record = Arc::new(Mutex::new(record));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&record);
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut head = [0_u8; 4096];
                        if stream.read(&mut head).is_err() {
                            continue;
                        }
                        let Ok(record) = shared.lock() else {
                            break;
                        };
                        let Ok(body) = serde_json::to_vec(&*record) else {
                            break;
                        };
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream
                            .write_all(header.as_bytes())
                            .and_then(|()| stream.write_all(&body));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { url, record, stop, thread: Some(thread) })
    }

    pub(crate) fn replace(
        &self,
        record: ramflux_protocol::WellKnownClientRecord,
    ) -> Result<(), Box<dyn std::error::Error>> {
        *self.record.lock().map_err(|_| "record mutex poisoned")? = record;
        Ok(())
    }
}
impl Drop for ClientRecordOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn sign_client_record(
    record: &mut ramflux_protocol::WellKnownClientRecord,
    seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    record.node_public_key = ramflux_crypto::public_key_base64url_from_seed(seed);
    record.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::client_discovery_signing_bytes(record)?,
        seed,
    );
    Ok(())
}
