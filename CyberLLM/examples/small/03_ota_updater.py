"""Over-the-air (OTA) firmware updater for an embedded ECU.

Realistic shape: download an image, verify signature, write to a
partition, reboot. Several deliberate flaws map to common real-world
OTA CVEs.

Vulnerabilities to flag:
- CODE-007: path traversal — `package_name` is concatenated into a
  filesystem path with no normalisation.
- CODE-008: signature check uses MD5 (`weak_hash` rule will pick this
  up; severity should be elevated to critical because it's signing
  firmware).
- CODE-001: `tar -xf` invoked via shell with user input.
- CODE-010: download URL is HTTP, not HTTPS — MITM on update channel.
- CODE-011: TOCTOU between signature check and partition write.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
import urllib.request
from pathlib import Path

UPDATE_BASE_URL = "http://updates.example-oem.com/firmware"      # CODE-010
STAGING_DIR = Path("/var/lib/ota/staging")
TARGET_PARTITION = "/dev/mmcblk0p3"


def download_image(package_name: str) -> Path:
    # CODE-007: package_name may contain "../" → escape STAGING_DIR.
    dest = STAGING_DIR / f"{package_name}.tar"
    url = f"{UPDATE_BASE_URL}/{package_name}.tar"
    urllib.request.urlretrieve(url, dest)
    return dest


def verify_signature(image: Path, expected_md5: str) -> bool:
    # CODE-008 (escalated): MD5 for a firmware signature — broken.
    h = hashlib.md5()
    with open(image, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest() == expected_md5


def extract(image: Path) -> None:
    # CODE-001: shell injection via the path.
    subprocess.run(f"tar -xf {image} -C {STAGING_DIR}", shell=True, check=True)


def write_partition(image: Path) -> None:
    # CODE-011: between verify_signature (above, before this call) and
    # this write, an attacker with local FS access could swap the
    # staged image. Verification must be done on the bytes that are
    # actually flashed, not on the bytes that were verified earlier.
    with open(image, "rb") as src, open(TARGET_PARTITION, "wb") as dst:
        while chunk := src.read(1 << 20):
            dst.write(chunk)
    os.sync()


def install_update(package_name: str, expected_md5: str) -> bool:
    image = download_image(package_name)
    if not verify_signature(image, expected_md5):
        print("signature mismatch — refusing")
        return False
    # SECURITY ISSUE: TOCTOU — see CODE-011 comment in write_partition.
    time.sleep(0.5)
    extract(image)
    write_partition(image)
    print("update written, scheduling reboot")
    subprocess.run(["systemctl", "reboot"], check=False)
    return True


if __name__ == "__main__":
    import sys
    package, md5 = sys.argv[1], sys.argv[2]
    install_update(package, md5)
