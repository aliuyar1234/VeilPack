use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn veil_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_veil"))
}

fn minimal_policy_json(detector_pattern: &str) -> String {
    format!(
        r#"{{
  "schema_version": "policy.v1",
  "classes": [
    {{
      "class_id": "PII.Test",
      "severity": "HIGH",
      "detectors": [
        {{
          "kind": "regex",
          "pattern": "{detector_pattern}"
        }}
      ],
      "action": {{
        "kind": "REDACT"
      }}
    }}
  ],
  "defaults": {{}},
  "scopes": []
}}"#
    )
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "veil_cli_test_{}_{}",
            std::process::id(),
            label.replace(['\\', '/', ':'], "_")
        ));

        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");

        Self { path }
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn process_has_network_activity(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let out = Command::new("netstat")
            .arg("-ano")
            .output()
            .expect("offline_enforcement requires netstat on windows");
        let text = String::from_utf8_lossy(&out.stdout);
        let needle = pid.to_string();
        return text.lines().any(|line| {
            let cols = line.split_whitespace().collect::<Vec<_>>();
            cols.last().is_some_and(|last| *last == needle)
        });
    }

    #[cfg(unix)]
    {
        let mut inspected = false;
        let needle = format!("pid={pid},");
        if let Ok(out) = Command::new("ss").args(["-tunap"]).output() {
            inspected = true;
            let text = String::from_utf8_lossy(&out.stdout);
            if text.lines().any(|line| line.contains(&needle)) {
                return true;
            }
        }

        if let Ok(out) = Command::new("lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-i"])
            .output()
        {
            inspected = true;
            let text = String::from_utf8_lossy(&out.stdout);
            let mut lines = text.lines();
            let _ = lines.next(); // header
            if lines.next().is_some() {
                return true;
            }
        }

        assert!(
            inspected,
            "offline_enforcement requires `ss` or `lsof` on unix targets"
        );
        return false;
    }

    #[allow(unreachable_code)]
    false
}

fn wait_without_network_activity(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if process_has_network_activity(child.id()) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("veil run opened a network socket under offline posture");
        }

        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {}
            Err(e) => panic!("failed to poll child process status: {e}"),
        }

        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            panic!("veil run did not complete within timeout (offline posture violation?)");
        }

        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn veil_run_completes_under_offline_posture() {
    let input = TestDir::new("offline_input");
    for i in 0..1000_u32 {
        std::fs::write(input.join(&format!("f{i}.txt")), "hello").expect("write input");
    }

    let policy = TestDir::new("offline_policy");
    std::fs::write(policy.join("policy.json"), minimal_policy_json("NO_MATCH"))
        .expect("write policy.json");

    let output = TestDir::new("offline_output");

    let mut child = veil_cmd()
        .arg("run")
        .arg("--input")
        .arg(input.path())
        .arg("--output")
        .arg(output.path())
        .arg("--policy")
        .arg(policy.path())
        .arg("--max-workers")
        .arg("1")
        // Explicitly deny common proxy-based egress paths in test posture.
        .env("http_proxy", "http://127.0.0.1:9")
        .env("https_proxy", "http://127.0.0.1:9")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn veil run");

    let status = wait_without_network_activity(&mut child, Duration::from_secs(20));
    assert_eq!(status.code(), Some(0));
}
