"""Concrete MCP tool implementations.

Each tool:
  - has an explicit, validated schema,
  - declares its side effect,
  - calls a real OS-level command or service where one is available
    on the host (and the engine is in live mode),
  - otherwise returns a professional dry-run envelope that the
    executor can still verify against.

The set is organised by domain:
  - firewall.*      (iptables / ufw / netsh / pf — block, rate-limit)
  - network.*       (ip link / nmcli — node isolation, segmentation)
  - secrets.*       (vault / local store — rotate, revoke)
  - code.*          (bandit / semgrep / git — scan, patch, scrub history)
  - runtime.*       (systemctl / tar / lvm — restart, snapshot, safe-mode)
  - notify.*        (webhook / SMTP / file — incidents, ops alerts)
  - observe.*       (log tail / endpoint probe / metric — verification)
  - kb.*            (NVD / local YAML — CVE + playbook lookup)

Real-command invocations use `subprocess.run` with explicit `args=[...]`
(no shell=True), bounded timeouts, and structured stdout parsing.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import smtplib
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

from .mcp_registry import MCPSchemaField, MCPTool
from .types import SideEffect, ToolResult


# ===========================================================================
# Helpers
# ===========================================================================

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"


def _run(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    """Wrapper around subprocess.run that returns (rc, stdout, stderr)."""
    try:
        cp = subprocess.run(args, capture_output=True, text=True,
                            timeout=timeout, check=False)
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or "timeout"


def _is_root() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _resolve_workdir(work_dir: str | None) -> Path:
    p = Path(work_dir or "./mcp_workspace").resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


# ===========================================================================
# firewall.*
# ===========================================================================

class FirewallBlockIPv4(MCPTool):
    name = "firewall.block_ipv4"
    description = "Block a source IPv4 address at the host firewall."
    domain = "firewall"
    side_effect = SideEffect.WRITE
    idempotent = True
    requires_authorization = True
    schema = [
        MCPSchemaField("ipv4", "ipv4", description="source address to block"),
        MCPSchemaField("duration_minutes", "int", required=False,
                        description="auto-expire in N minutes (0 = permanent)"),
        MCPSchemaField("reason", "string", required=False),
    ]
    real_binary = "iptables" if IS_LINUX else ("netsh" if IS_WINDOWS else "pfctl")

    def validate(self, params):
        errors = super().validate(params)
        ip = params.get("ipv4", "")
        if ip and not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
            errors.append(f"ipv4: '{ip}' is not a valid dotted-quad")
        return errors

    def _do_call(self, params: dict) -> ToolResult:
        ip = params["ipv4"]
        if not _is_root() and IS_LINUX:
            return ToolResult(
                status="failed",
                tool=self.name,
                error="iptables requires root; rerun with sudo or use a SOAR connector",
            )
        if IS_LINUX:
            rc, out, err = _run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
            ok = rc == 0
            return ToolResult(status="ok" if ok else "failed", tool=self.name,
                              payload={"rule": f"iptables INPUT DROP src={ip}",
                                       "stdout": out.strip()},
                              error=err.strip() if not ok else None)
        if IS_WINDOWS:
            name = f"CyberLLM-block-{ip}"
            rc, out, err = _run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}", "dir=in", "action=block",
                 f"remoteip={ip}"])
            ok = rc == 0
            return ToolResult(status="ok" if ok else "failed", tool=self.name,
                              payload={"rule_name": name, "stdout": out.strip()},
                              error=err.strip() if not ok else None)
        return ToolResult(status="failed", tool=self.name,
                          error=f"no firewall driver for platform={platform.system()}")


class FirewallRateLimit(MCPTool):
    name = "firewall.rate_limit"
    description = "Rate-limit a source IPv4 address (packets / minute)."
    domain = "firewall"
    side_effect = SideEffect.WRITE
    requires_authorization = True
    schema = [
        MCPSchemaField("ipv4", "ipv4"),
        MCPSchemaField("rate_per_minute", "int"),
        MCPSchemaField("duration_minutes", "int", required=False),
    ]
    real_binary = "iptables" if IS_LINUX else None

    def _do_call(self, params: dict) -> ToolResult:
        if not (IS_LINUX and _is_root()):
            return ToolResult(status="failed", tool=self.name,
                              error="needs Linux iptables hashlimit + root")
        ip = params["ipv4"]
        rate = int(params["rate_per_minute"])
        rc, out, err = _run([
            "iptables", "-I", "INPUT", "-s", ip,
            "-m", "hashlimit",
            "--hashlimit-name", f"CyberLLM-{ip}",
            "--hashlimit-above", f"{rate}/min",
            "--hashlimit-mode", "srcip",
            "-j", "DROP",
        ])
        ok = rc == 0
        return ToolResult(status="ok" if ok else "failed", tool=self.name,
                          payload={"rule": f"hashlimit {rate}/min src={ip}",
                                   "stdout": out.strip()},
                          error=err.strip() if not ok else None)


class FirewallListRules(MCPTool):
    name = "firewall.list_rules"
    description = "List active firewall rules (read-only)."
    domain = "firewall"
    side_effect = SideEffect.READ
    real_binary = "iptables" if IS_LINUX else "netsh" if IS_WINDOWS else None

    def _do_call(self, params: dict) -> ToolResult:
        if IS_LINUX:
            rc, out, err = _run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
        elif IS_WINDOWS:
            rc, out, err = _run(["netsh", "advfirewall", "firewall", "show", "rule",
                                  "name=all"])
        else:
            return ToolResult(status="failed", tool=self.name,
                              error="unsupported platform")
        return ToolResult(status="ok" if rc == 0 else "failed", tool=self.name,
                          payload={"rules": (out or "")[:2000]},
                          error=err.strip() if rc != 0 else None)


# ===========================================================================
# network.*
# ===========================================================================

class NetworkIsolateNode(MCPTool):
    name = "network.isolate_node"
    description = "Move a node into a quarantine VLAN / drop all but mgmt."
    domain = "network"
    side_effect = SideEffect.DESTRUCTIVE
    idempotent = True
    requires_authorization = True
    schema = [
        MCPSchemaField("node_id", "string"),
        MCPSchemaField("quarantine_vlan", "int", required=False),
        MCPSchemaField("management_cidr", "string", required=False),
    ]
    real_binary = "nmcli" if IS_LINUX else None

    def _do_call(self, params: dict) -> ToolResult:
        # We can't actually re-VLAN a remote ECU; this is the
        # connector-stub style. A production deployment would call
        # the switch / SDN controller.
        node = params["node_id"]
        return ToolResult(
            status="ok",
            tool=self.name,
            payload={
                "node_id": node,
                "vlan": params.get("quarantine_vlan", 99),
                "action": "moved to quarantine VLAN (connector stub)",
                "note": "Connect to your switch/SDN controller for the real call.",
            },
        )


# ===========================================================================
# secrets.*
# ===========================================================================

class SecretsRotate(MCPTool):
    name = "secrets.rotate"
    description = ("Rotate a named secret: prefer Vault if present, "
                    "otherwise generate a fresh token in a local secret store.")
    domain = "secrets"
    side_effect = SideEffect.DESTRUCTIVE
    requires_authorization = True
    schema = [
        MCPSchemaField("secret_id", "string"),
        MCPSchemaField("length", "int", required=False),
    ]
    real_binary = "vault"

    def _do_call(self, params: dict) -> ToolResult:
        import secrets as pysecrets
        sid = params["secret_id"]
        length = int(params.get("length", 32))
        token = pysecrets.token_urlsafe(length)
        # Vault path: would call `vault kv put secret/<sid> value=...`
        # We deliberately do NOT shell-out to vault here because we
        # cannot guarantee the operator's policy. Instead we always
        # use the local fallback and report.
        store = _resolve_workdir(self.work_dir) / "secret_store"
        store.mkdir(parents=True, exist_ok=True)
        if IS_LINUX or IS_MACOS:
            try:
                store.chmod(0o700)
            except Exception:
                pass
        path = store / f"{sid}.secret"
        path.write_text(token, encoding="utf-8")
        if IS_LINUX or IS_MACOS:
            try:
                path.chmod(0o600)
            except Exception:
                pass
        return ToolResult(
            status="ok",
            tool=self.name,
            payload={
                "secret_id": sid,
                "stored_at": str(path),
                "length": length,
                "fingerprint": f"sha256:{_short_hash(token)}",
                "note": "Wire HashiCorp Vault or AWS Secrets Manager for production.",
            },
        )


class SecretsRevoke(MCPTool):
    name = "secrets.revoke"
    description = "Mark a secret as revoked (delete from local store)."
    domain = "secrets"
    side_effect = SideEffect.DESTRUCTIVE
    requires_authorization = True
    schema = [MCPSchemaField("secret_id", "string")]

    def _do_call(self, params: dict) -> ToolResult:
        store = _resolve_workdir(self.work_dir) / "secret_store"
        path = store / f"{params['secret_id']}.secret"
        if path.exists():
            path.unlink()
            return ToolResult(status="ok", tool=self.name,
                              payload={"revoked": params["secret_id"]})
        return ToolResult(status="ok", tool=self.name,
                          payload={"revoked": params["secret_id"],
                                   "note": "no local copy found, no-op"})


def _short_hash(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


# ===========================================================================
# code.*
# ===========================================================================

class CodeStaticScan(MCPTool):
    name = "code.static_scan"
    description = "Run a real static analyser (bandit / semgrep) over a path."
    domain = "code"
    side_effect = SideEffect.READ
    schema = [
        MCPSchemaField("path", "string"),
        MCPSchemaField("analyser", "enum", required=False,
                        enum=["bandit", "semgrep", "auto"]),
    ]
    real_binary = "bandit"     # checked at call time, may upgrade to semgrep

    def _do_call(self, params: dict) -> ToolResult:
        path = params["path"]
        analyser = params.get("analyser", "auto")
        chosen = analyser
        if analyser == "auto":
            chosen = "semgrep" if shutil.which("semgrep") else "bandit"
        if chosen == "semgrep" and shutil.which("semgrep"):
            rc, out, _ = _run(["semgrep", "--config=auto",
                               "--json", "--error", path], timeout=120)
            try:
                data = json.loads(out)
                n = len(data.get("results", []))
            except Exception:
                data, n = {"raw": (out or "")[:2000]}, 0
            return ToolResult(status="ok", tool=self.name,
                              payload={"analyser": "semgrep",
                                       "findings": n, "report": data})
        if chosen == "bandit" and shutil.which("bandit"):
            rc, out, _ = _run(["bandit", "-r", path, "-f", "json", "-q"],
                              timeout=120)
            try:
                data = json.loads(out)
                n = len(data.get("results", []))
            except Exception:
                data, n = {"raw": (out or "")[:2000]}, 0
            return ToolResult(status="ok", tool=self.name,
                              payload={"analyser": "bandit",
                                       "findings": n, "report": data})
        return ToolResult(status="failed", tool=self.name,
                          error="neither bandit nor semgrep is installed")


class CodeProposePatch(MCPTool):
    name = "code.propose_patch"
    description = ("Write a unified-diff patch proposal to the workspace "
                    "(does not modify the target repo directly).")
    domain = "code"
    side_effect = SideEffect.WRITE
    requires_authorization = False
    schema = [
        MCPSchemaField("rule_id", "string"),
        MCPSchemaField("file", "string"),
        MCPSchemaField("diff", "string"),
        MCPSchemaField("rationale", "string", required=False),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        patches = _resolve_workdir(self.work_dir) / "patches"
        patches.mkdir(parents=True, exist_ok=True)
        fname = (re.sub(r"[^A-Za-z0-9._-]+", "_", params["file"])
                  + f".{params['rule_id']}.patch")
        path = patches / fname
        path.write_text(
            f"# rule_id: {params['rule_id']}\n"
            f"# file:    {params['file']}\n"
            f"# rationale: {params.get('rationale', '')}\n"
            f"# generated: {datetime.now().isoformat()}\n\n"
            f"{params['diff']}\n",
            encoding="utf-8",
        )
        return ToolResult(status="ok", tool=self.name,
                          payload={"patch_path": str(path),
                                   "rule_id": params["rule_id"]})


class CodeScrubGitHistory(MCPTool):
    name = "code.scrub_git_history"
    description = ("Issue a guarded git-filter-repo or BFG instruction. "
                    "Always writes a plan file; only executes in live mode "
                    "with explicit authorization (irreversible).")
    domain = "code"
    side_effect = SideEffect.DESTRUCTIVE
    requires_authorization = True
    schema = [
        MCPSchemaField("repo_path", "string"),
        MCPSchemaField("pattern", "string"),
    ]
    real_binary = "git"

    def _do_call(self, params: dict) -> ToolResult:
        # Even in live mode we *don't* run a history-rewriting command
        # automatically — we write a runbook instead. This is one of the
        # rare destructive operations where automation is dangerous.
        runbook = _resolve_workdir(self.work_dir) / "runbooks"
        runbook.mkdir(parents=True, exist_ok=True)
        rb = runbook / f"scrub_git_history_{int(time.time())}.md"
        rb.write_text(
            f"# History-scrub runbook\n\n"
            f"- repo: `{params['repo_path']}`\n"
            f"- pattern: `{params['pattern']}`\n\n"
            "Recommended (review before running):\n\n"
            "```\n"
            "git clone --mirror <REPO> repo.git\n"
            "cd repo.git\n"
            f"git filter-repo --replace-text <(echo '{params['pattern']}==>REMOVED')\n"
            "git push --force --all\n"
            "```\n",
            encoding="utf-8",
        )
        return ToolResult(status="ok", tool=self.name,
                          payload={"runbook": str(rb),
                                   "note": "operator must review and run manually"})


# ===========================================================================
# runtime.*
# ===========================================================================

class RuntimeServiceRestart(MCPTool):
    name = "runtime.restart_service"
    description = "Restart a systemd service or Windows service."
    domain = "runtime"
    side_effect = SideEffect.WRITE
    requires_authorization = True
    schema = [MCPSchemaField("service", "string")]
    real_binary = "systemctl" if IS_LINUX else "sc" if IS_WINDOWS else None

    def _do_call(self, params: dict) -> ToolResult:
        svc = params["service"]
        if IS_LINUX:
            rc, out, err = _run(["systemctl", "restart", svc])
            return ToolResult(status="ok" if rc == 0 else "failed",
                              tool=self.name,
                              payload={"service": svc, "stdout": out.strip()},
                              error=err.strip() if rc != 0 else None)
        if IS_WINDOWS:
            _run(["sc", "stop", svc])
            rc, out, err = _run(["sc", "start", svc])
            return ToolResult(status="ok" if rc == 0 else "failed",
                              tool=self.name,
                              payload={"service": svc, "stdout": out.strip()},
                              error=err.strip() if rc != 0 else None)
        return ToolResult(status="failed", tool=self.name,
                          error="unsupported platform")


class RuntimeSnapshot(MCPTool):
    name = "runtime.snapshot"
    description = "Tar-archive a path into the workspace (cheap forensics snapshot)."
    domain = "runtime"
    side_effect = SideEffect.WRITE
    schema = [
        MCPSchemaField("source_path", "string"),
        MCPSchemaField("label", "string", required=False),
    ]
    real_binary = "tar"

    def _do_call(self, params: dict) -> ToolResult:
        src = Path(params["source_path"])
        if not src.exists():
            return ToolResult(status="failed", tool=self.name,
                              error=f"source not found: {src}")
        snaps = _resolve_workdir(self.work_dir) / "snapshots"
        snaps.mkdir(parents=True, exist_ok=True)
        label = params.get("label", "snapshot")
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        out_path = snaps / f"{label}_{ts}.tar"
        rc, _, err = _run(["tar", "-cf", str(out_path), "-C", str(src.parent),
                            src.name], timeout=120)
        if rc != 0:
            return ToolResult(status="failed", tool=self.name,
                              error=err.strip() or "tar failed")
        return ToolResult(status="ok", tool=self.name,
                          payload={"snapshot_path": str(out_path),
                                   "bytes": out_path.stat().st_size})


class RuntimeSafeMode(MCPTool):
    name = "runtime.safe_mode"
    description = ("Switch a target (vehicle / ECU / service) into safe mode. "
                    "Connector-stub for non-domain-specific environments.")
    domain = "runtime"
    side_effect = SideEffect.DESTRUCTIVE
    requires_authorization = True
    schema = [MCPSchemaField("target", "string")]

    def _do_call(self, params: dict) -> ToolResult:
        target = params["target"]
        return ToolResult(
            status="ok",
            tool=self.name,
            payload={
                "target": target,
                "action": "safe-mode requested (connector stub)",
                "note": "Wire your fleet management or ECU controller here.",
            },
        )


# ===========================================================================
# notify.*
# ===========================================================================

class NotifyWebhook(MCPTool):
    name = "notify.webhook"
    description = "POST a JSON payload to a webhook URL (Slack-style)."
    domain = "notify"
    side_effect = SideEffect.WRITE
    schema = [
        MCPSchemaField("url", "string"),
        MCPSchemaField("title", "string"),
        MCPSchemaField("body", "string", required=False),
        MCPSchemaField("severity", "enum", required=False,
                        enum=["info", "warn", "high", "critical"]),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        payload = {
            "title": params["title"],
            "body": params.get("body", ""),
            "severity": params.get("severity", "info"),
        }
        try:
            req = urllib.request.Request(
                params["url"],
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                code = r.status
            ok = 200 <= code < 300
            return ToolResult(status="ok" if ok else "failed", tool=self.name,
                              payload={"http_status": code,
                                       "title": params["title"]})
        except Exception as exc:    # noqa: BLE001
            return ToolResult(status="failed", tool=self.name,
                              error=f"{type(exc).__name__}: {exc}")


class NotifyCreateIncident(MCPTool):
    name = "notify.create_incident"
    description = ("Open a structured incident. Tries webhook first, then "
                    "falls back to writing a JSON file in the workspace.")
    domain = "notify"
    side_effect = SideEffect.WRITE
    schema = [
        MCPSchemaField("severity", "enum",
                        enum=["info", "low", "warn", "medium",
                              "high", "critical"]),
        MCPSchemaField("summary", "string"),
        MCPSchemaField("rule_id", "string", required=False),
        MCPSchemaField("evidence", "string", required=False),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        webhook = os.environ.get("CYBERLLM_INCIDENT_WEBHOOK")
        if webhook:
            try:
                req = urllib.request.Request(
                    webhook,
                    data=json.dumps(params).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as r:
                    if 200 <= r.status < 300:
                        return ToolResult(status="ok", tool=self.name,
                                          payload={"channel": "webhook",
                                                   "http_status": r.status})
            except Exception:
                pass    # fall through to file fallback
        # File fallback — always works.
        d = _resolve_workdir(self.work_dir) / "incidents"
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%dT%H%M%S")
        f = d / f"incident_{ts}_{params.get('rule_id','GEN')}.json"
        f.write_text(json.dumps({**params,
                                   "created_at": datetime.now().isoformat()},
                                 indent=2), encoding="utf-8")
        return ToolResult(status="ok", tool=self.name,
                          payload={"channel": "file", "incident_path": str(f)})


class NotifyEmail(MCPTool):
    name = "notify.email"
    description = "Send an alert email via SMTP (env-configured)."
    domain = "notify"
    side_effect = SideEffect.WRITE
    schema = [
        MCPSchemaField("to", "string"),
        MCPSchemaField("subject", "string"),
        MCPSchemaField("body", "string"),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        host = os.environ.get("SMTP_HOST")
        if not host:
            return ToolResult(status="failed", tool=self.name,
                              error="SMTP_HOST not set; cannot send email")
        msg = EmailMessage()
        msg["From"] = os.environ.get("SMTP_FROM", "cyberllm@example.com")
        msg["To"] = params["to"]
        msg["Subject"] = params["subject"]
        msg.set_content(params["body"])
        try:
            with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 25)),
                               timeout=5) as s:
                s.send_message(msg)
            return ToolResult(status="ok", tool=self.name,
                              payload={"to": params["to"]})
        except Exception as exc:        # noqa: BLE001
            return ToolResult(status="failed", tool=self.name,
                              error=f"{type(exc).__name__}: {exc}")


class NotifyDriver(MCPTool):
    name = "notify.driver"
    description = ("Write a structured driver-facing notification (HUD / "
                    "head-unit). Connector-stub for non-vehicle hosts.")
    domain = "notify"
    side_effect = SideEffect.WRITE
    schema = [
        MCPSchemaField("vehicle", "string"),
        MCPSchemaField("message", "string"),
        MCPSchemaField("urgency", "enum",
                        enum=["info", "warning", "critical"]),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        d = _resolve_workdir(self.work_dir) / "driver_notifications"
        d.mkdir(parents=True, exist_ok=True)
        f = d / f"{params['vehicle']}_{int(time.time())}.json"
        f.write_text(json.dumps(params, indent=2), encoding="utf-8")
        return ToolResult(status="ok", tool=self.name,
                          payload={"path": str(f)})


# ===========================================================================
# observe.*  — used for pre/post-condition checks
# ===========================================================================

class ObserveEndpoint(MCPTool):
    name = "observe.endpoint"
    description = "HTTP-probe an endpoint and assert it responds within a window."
    domain = "observe"
    side_effect = SideEffect.READ
    schema = [
        MCPSchemaField("url", "string"),
        MCPSchemaField("expected_status", "int", required=False),
        MCPSchemaField("timeout_s", "int", required=False),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        url = params["url"]
        timeout = int(params.get("timeout_s", 5))
        expected = int(params.get("expected_status", 200))
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                code = r.status
            ok = code == expected
            return ToolResult(status="ok" if ok else "failed",
                              tool=self.name,
                              payload={"http_status": code,
                                       "expected": expected})
        except Exception as exc:        # noqa: BLE001
            return ToolResult(status="failed", tool=self.name,
                              error=f"{type(exc).__name__}: {exc}")


class ObserveLogTail(MCPTool):
    name = "observe.log_tail"
    description = "Watch a log file for N seconds and report matched lines."
    domain = "observe"
    side_effect = SideEffect.READ
    schema = [
        MCPSchemaField("path", "string"),
        MCPSchemaField("pattern", "string"),
        MCPSchemaField("timeout_s", "int", required=False),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        path = Path(params["path"])
        timeout = float(params.get("timeout_s", 5))
        pat = re.compile(params["pattern"])
        if not path.exists():
            return ToolResult(status="failed", tool=self.name,
                              error=f"log path not found: {path}")
        deadline = time.time() + timeout
        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)        # to end
            matches: list[str] = []
            while time.time() < deadline and len(matches) < 100:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                if pat.search(line):
                    matches.append(line.rstrip("\n"))
        return ToolResult(
            status="ok",
            tool=self.name,
            payload={"matches": matches, "n": len(matches)},
        )


class ObservePortClosed(MCPTool):
    name = "observe.port_closed"
    description = "Verify a TCP port is no longer reachable from this host."
    domain = "observe"
    side_effect = SideEffect.READ
    schema = [
        MCPSchemaField("host", "string"),
        MCPSchemaField("port", "int"),
        MCPSchemaField("timeout_s", "int", required=False),
    ]

    def _do_call(self, params: dict) -> ToolResult:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(float(params.get("timeout_s", 2)))
        try:
            rc = s.connect_ex((params["host"], int(params["port"])))
            closed = rc != 0
        finally:
            s.close()
        return ToolResult(status="ok", tool=self.name,
                          payload={"closed": closed})


# ===========================================================================
# kb.*  — read-only knowledge tools
# ===========================================================================

class KBLookupCVE(MCPTool):
    name = "kb.lookup_cve"
    description = "Look up a CVE by id from the local cache, or NVD if reachable."
    domain = "kb"
    side_effect = SideEffect.READ
    schema = [MCPSchemaField("cve_id", "string")]

    def _do_call(self, params: dict) -> ToolResult:
        cve = params["cve_id"]
        cache = _resolve_workdir(self.work_dir) / "cve_cache"
        cache.mkdir(parents=True, exist_ok=True)
        local = cache / f"{cve}.json"
        if local.exists():
            return ToolResult(status="ok", tool=self.name,
                              payload={"source": "cache",
                                       "data": json.loads(local.read_text())})
        try:
            url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
                   + cve)
            req = urllib.request.Request(url, headers={"User-Agent": "CyberLLM/1.0"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode("utf-8"))
            local.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return ToolResult(status="ok", tool=self.name,
                              payload={"source": "nvd",
                                       "vulns": len(data.get("vulnerabilities",
                                                              []))})
        except Exception as exc:        # noqa: BLE001
            return ToolResult(status="failed", tool=self.name,
                              error=f"NVD unreachable: {exc}")


# ===========================================================================
# network.port_scan  — real active recon (paper C.1)
# ===========================================================================

class NetworkPortScan(MCPTool):
    name = "network.port_scan"
    description = ("Active TCP port scan of a host (nmap if installed, else a "
                    "bounded pure-Python connect scan).")
    domain = "network"
    side_effect = SideEffect.READ
    requires_authorization = True          # active scanning needs a go-ahead
    schema = [
        MCPSchemaField("target", "string", description="host or IPv4 (CIDR is reduced to the host)"),
        MCPSchemaField("ports", "string", required=False,
                        description="nmap port spec, e.g. '1-1024' or '22,80,443'"),
    ]
    real_binary = "nmap"

    # A socket scan is always possible, so the tool is "available" even
    # without nmap — dry-run remains the safety gate.
    def real_available(self) -> bool:
        return True

    _COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306,
                     3389, 5432, 6379, 8080, 8443, 11434]

    def _do_call(self, params: dict) -> ToolResult:
        target = params["target"]
        ports = str(params.get("ports", "1-1024"))
        if shutil.which("nmap"):
            rc, out, err = _run(
                ["nmap", "-sT", "-Pn", "--open", "-p", ports, "-oG", "-", target],
                timeout=90)
            open_ports = sorted({int(m) for m in re.findall(r"(\d+)/open", out)})
            return ToolResult(status="ok", tool=self.name,
                              payload={"backend": "nmap", "target": target,
                                       "open_ports": open_ports})
        # Pure-Python fallback: connect-scan a bounded set of common ports
        # on the single host (CIDR reduced to the host part).
        host = target.split("/")[0]
        open_ports = []
        for p in self._COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                if s.connect_ex((host, p)) == 0:
                    open_ports.append(p)
            except Exception:           # noqa: BLE001 — unreachable host port
                pass
            finally:
                s.close()
        return ToolResult(status="ok", tool=self.name,
                          payload={"backend": "socket", "target": host,
                                   "open_ports": open_ports})


# ===========================================================================
# observe.packet_capture  — real traffic / CAN capture (paper C.3)
# ===========================================================================

class ObservePacketCapture(MCPTool):
    name = "observe.packet_capture"
    description = ("Capture a bounded burst of packets / CAN frames "
                    "(tshark → tcpdump → candump, whichever is present).")
    domain = "observe"
    side_effect = SideEffect.READ
    requires_authorization = True
    schema = [
        MCPSchemaField("interface", "string", required=False,
                        description="e.g. 'eth0', 'any', or 'can0' for CAN"),
        MCPSchemaField("count", "int", required=False),
        MCPSchemaField("timeout_s", "int", required=False),
    ]
    real_binary = "tshark"

    def real_available(self) -> bool:
        return any(shutil.which(b) for b in ("tshark", "tcpdump", "candump"))

    def _do_call(self, params: dict) -> ToolResult:
        iface = params.get("interface", "any")
        count = int(params.get("count", 50))
        timeout_s = min(int(params.get("timeout_s", 10)), 30)   # hard cap
        if shutil.which("tshark"):
            rc, out, _ = _run(["tshark", "-i", iface, "-a", f"duration:{timeout_s}",
                               "-c", str(count), "-n"], timeout=timeout_s + 15)
            lines = [ln for ln in out.splitlines() if ln.strip()]
            return ToolResult(status="ok", tool=self.name,
                              payload={"backend": "tshark", "interface": iface,
                                       "packets": len(lines), "sample": lines[:20]})
        if shutil.which("tcpdump"):
            rc, out, _ = _run(["tcpdump", "-i", iface, "-c", str(count), "-nn", "-tt"],
                              timeout=timeout_s + 15)
            lines = [ln for ln in out.splitlines() if ln.strip()]
            return ToolResult(status="ok", tool=self.name,
                              payload={"backend": "tcpdump", "interface": iface,
                                       "packets": len(lines), "sample": lines[:20]})
        if shutil.which("candump"):
            rc, out, _ = _run(["candump", "-n", str(count), iface],
                              timeout=timeout_s + 5)
            frames = [ln for ln in out.splitlines() if ln.strip()]
            return ToolResult(status="ok", tool=self.name,
                              payload={"backend": "candump", "interface": iface,
                                       "frames": len(frames), "sample": frames[:20]})
        return ToolResult(status="failed", tool=self.name,
                          error="no packet-capture backend (tshark/tcpdump/candump)")


# ===========================================================================
# Factory
# ===========================================================================

def default_toolset() -> list[MCPTool]:
    return [
        FirewallBlockIPv4(),
        FirewallRateLimit(),
        FirewallListRules(),
        NetworkIsolateNode(),
        NetworkPortScan(),
        SecretsRotate(),
        SecretsRevoke(),
        CodeStaticScan(),
        CodeProposePatch(),
        CodeScrubGitHistory(),
        RuntimeServiceRestart(),
        RuntimeSnapshot(),
        RuntimeSafeMode(),
        NotifyWebhook(),
        NotifyCreateIncident(),
        NotifyEmail(),
        NotifyDriver(),
        ObserveEndpoint(),
        ObserveLogTail(),
        ObservePortClosed(),
        ObservePacketCapture(),
        KBLookupCVE(),
    ]


