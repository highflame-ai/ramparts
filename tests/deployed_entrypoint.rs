//! The server must boot with the exact argv the deployed container uses.
//!
//! WHY THIS TEST EXISTS
//!
//! A change to `MCPScannerServer::start()` made the server refuse to bind a
//! non-loopback address unless an environment variable was set. Every unit test
//! passed, clippy was clean, and the release pipeline in highflame-cloud then
//! failed at its smoke step with "Server not responding on port 8080", because
//! `Deploy-Dockerfile` runs:
//!
//!     ENTRYPOINT [ "/app/ramparts", "server", "--port", "8080", "--host", "0.0.0.0" ]
//!
//! Nothing in this repository exercised that invocation. `start()` had zero test
//! coverage — no test ever bound a listener — and the test that was added
//! asserted the NEW default (`host == "127.0.0.1"`) rather than checking that
//! the documented deployment still worked. Asserting the value you just changed
//! proves nothing.
//!
//! This test closes that gap by running the real binary with the real argv and
//! requiring it to serve the probe endpoint Kubernetes uses. It fails on any
//! change that stops the container from starting, whatever the cause.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Ask the OS for a free port, then release it. A small race is acceptable
/// here and far better than a hardcoded port that collides in CI.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Poll a probe endpoint until it answers or the deadline passes.
fn wait_for_probe(port: u16, deadline: Duration) -> Result<u16, String> {
    let url = format!("http://127.0.0.1:{port}/healthz");
    let started = Instant::now();
    while started.elapsed() < deadline {
        let output = Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "2",
                &url,
            ])
            .output();
        if let Ok(out) = output {
            let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(code) = code.parse::<u16>() {
                if code > 0 && code != 0 {
                    return Ok(code);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("no response from {url} within {deadline:?}"))
}

#[test]
fn server_boots_with_the_deployed_entrypoint_argv() {
    let port = free_port();

    // The same argv as Deploy-Dockerfile's ENTRYPOINT, including --host 0.0.0.0.
    // Cleared of the environment so no locally-set variable can mask a
    // regression that would hit a bare container.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ramparts"))
        .args(["server", "--port", &port.to_string(), "--host", "0.0.0.0"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the ramparts binary should be spawnable");

    // Capture stderr so a startup refusal appears in the failure message
    // instead of leaving only "no response".
    let stderr = child.stderr.take().expect("stderr piped");
    let log = std::thread::spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .take(40)
            .collect::<Vec<_>>()
            .join("\n")
    });

    let server = Server(child);

    match wait_for_probe(port, Duration::from_secs(30)) {
        Ok(code) => {
            assert_eq!(
                code, 200,
                "the Kubernetes readiness probe /healthz must return 200"
            );
        }
        Err(e) => {
            drop(server);
            let captured = log.join().unwrap_or_default();
            panic!(
                "the server did not serve /healthz with the deployed argv.\n\
                 This is what breaks the container in highflame-cloud.\n\n\
                 {e}\n\nserver stderr:\n{captured}"
            );
        }
    }
}

/// Studio's MCP scan runs in the browser, so the endpoint must answer a
/// cross-origin preflight.
///
/// The same change that broke the container also replaced `allow_origin(Any)`
/// with an allowlist read from an environment variable. With nothing set — which
/// is how the deployment is configured — no `Access-Control-Allow-Origin` header
/// was emitted at all, so the browser would have blocked Studio's request. The
/// pipeline smoke test could never catch that: it curls from localhost with no
/// Origin header, so no preflight happens.
#[test]
fn preflight_from_a_browser_origin_is_allowed() {
    let port = free_port();

    let child = Command::new(env!("CARGO_BIN_EXE_ramparts"))
        .args(["server", "--port", &port.to_string(), "--host", "0.0.0.0"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the ramparts binary should be spawnable");
    let _server = Server(child);

    wait_for_probe(port, Duration::from_secs(30)).expect("server should come up");

    let out = Command::new("curl")
        .args([
            "-s",
            "-i",
            "-X",
            "OPTIONS",
            "-H",
            "Origin: https://studio.highflame.ai",
            "-H",
            "Access-Control-Request-Method: POST",
            "-H",
            "Access-Control-Request-Headers: content-type",
            "--max-time",
            "5",
            &format!("http://127.0.0.1:{port}/v1/ramparts/scan"),
        ])
        .output()
        .expect("curl should run");

    let response = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        response.contains("access-control-allow-origin"),
        "a cross-origin preflight must return Access-Control-Allow-Origin, \
         otherwise Studio's browser-side MCP scan is blocked. Got:\n{response}"
    );
}
