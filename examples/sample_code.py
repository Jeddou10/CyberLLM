"""Deliberately vulnerable sample for the source-code scanner."""
import hashlib
import subprocess


API_KEY = "sk_live_8f4d2c5a9b1e3a7d4f6c"   # CODE-003: hard-coded secret


def store_password(pw: str) -> str:
    # CODE-002: weak hash for credentials.
    return hashlib.md5(pw.encode("utf-8")).hexdigest()


def run_diagnostic(user_input: str) -> str:
    # CODE-001: shell injection sink.
    return subprocess.call(user_input, shell=True)


if __name__ == "__main__":
    print(store_password("hunter2"))
    print(run_diagnostic("ls /"))
