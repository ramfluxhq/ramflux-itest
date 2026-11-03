// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Deterministic OpenAI-compatible endpoint; request bodies remain memory-only.
use super::TestResult;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
pub(super) const PING: &str = "K5C_PONG";
pub(super) const TOOL_MARKER: &str = "K5C_TOOL_EXECUTED";
pub(super) fn streamed_text() -> String {
    (0..40).fold(String::new(), |mut text, n| {
        use std::fmt::Write as _;
        let _ = write!(text, "delta-{n:02} ");
        text
    })
}
pub(super) struct FakeLlm {
    pub port: u16,
    pub requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for FakeLlm {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl FakeLlm {
    pub fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let records = Arc::clone(&requests);
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        if serve(socket, &records).is_err() {
                            eprintln!("k5c fake LLM request refused");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { port, requests, stop, thread: Some(thread) })
    }
    pub fn count(&self) -> TestResult<usize> {
        Ok(self.requests.lock().map_err(|_| "LLM records poisoned")?.len())
    }
    pub fn absent_since(&self, start: usize, marker: &str) -> TestResult<bool> {
        let records = self.requests.lock().map_err(|_| "LLM records poisoned")?;
        Ok(records.len() > start
            && records[start..].iter().all(|r| !r.to_string().contains(marker)))
    }
}
fn read_request(socket: &mut TcpStream) -> TestResult<Value> {
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(socket);
    let mut total = 0;
    let mut length = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        total += n;
        if n == 0 || total > 16_384 {
            return Err("invalid fake LLM HTTP headers".into());
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    let length = length.filter(|n| *n <= 1_048_576).ok_or("unbounded fake LLM request")?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}
fn script(request: &Value) -> TestResult<(Vec<Value>, String)> {
    let messages = request["messages"].as_array().ok_or("LLM messages absent")?;
    let last_user = messages.iter().rposition(|m| m["role"] == "user").ok_or("LLM user absent")?;
    let prompt = messages[last_user]["content"].to_string();
    let results = &messages[last_user + 1..];
    if prompt.contains("k5c tool") {
        if results.iter().any(|r| r["role"] == "tool") {
            let ran = results
                .iter()
                .any(|r| r["role"] == "tool" && r["content"].to_string().contains(TOOL_MARKER));
            return Ok((Vec::new(), if ran { "TOOL_RAN" } else { "TOOL_REFUSED" }.into()));
        }
        let tool = json!({"index":0,"id":"k5c-file-read","type":"function","function":{"name":"file_read","arguments":"{\"path\":\"k5c-tool.txt\"}"}});
        return Ok((vec![tool], String::new()));
    }
    if prompt.contains("k5c stream") {
        return Ok((Vec::new(), streamed_text()));
    }
    Ok((Vec::new(), PING.into()))
}
fn serve(mut socket: TcpStream, records: &Arc<Mutex<Vec<Value>>>) -> TestResult {
    let request = read_request(&mut socket)?;
    let (tools, text) = script(&request)?;
    records.lock().map_err(|_| "LLM records poisoned")?.push(request.clone());
    let finish = if tools.is_empty() { "stop" } else { "tool_calls" };
    if request["stream"] == true {
        socket.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        )?;
        let chunks = if tools.is_empty() {
            if text == streamed_text() {
                (0..40).map(|n| json!({"content":format!("delta-{n:02} ")})).collect()
            } else {
                vec![json!({"content":text})]
            }
        } else {
            vec![json!({"tool_calls":tools})]
        };
        for delta in chunks {
            writeln!(
                socket,
                "data: {}\n",
                json!({"id":"k5c-response","object":"chat.completion.chunk","model":"fixture-model","choices":[{"index":0,"delta":delta,"finish_reason":null}]})
            )?;
            socket.flush()?;
            thread::sleep(Duration::from_millis(10));
        }
        writeln!(
            socket,
            "data: {}\n",
            json!({"choices":[{"index":0,"delta":{},"finish_reason":finish}]})
        )?;
        socket.write_all(b"data: [DONE]\n\n")?;
    } else {
        let message = if tools.is_empty() {
            json!({"role":"assistant","content":text})
        } else {
            json!({"role":"assistant","content":null,"tool_calls":tools.into_iter().map(|mut t| { t.as_object_mut().map(|m| m.remove("index")); t }).collect::<Vec<_>>()})
        };
        let body = serde_json::to_vec(
            &json!({"id":"k5c-response","object":"chat.completion","model":"fixture-model","choices":[{"index":0,"message":message,"finish_reason":finish}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}),
        )?;
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        socket.write_all(&body)?;
    }
    socket.flush()?;
    Ok(())
}
