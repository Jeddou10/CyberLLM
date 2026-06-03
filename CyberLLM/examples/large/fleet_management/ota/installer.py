"""OTA install worker.

Vulnerabilities to flag:
- CODE-010: package fetched over plain HTTP.
- CODE-008: MD5 used as the package signature digest.
- CODE-001: tar extraction via shell with the downloaded path.
- CODE-045: no rollback if the post-install health check fails.
"""

from __future__ import annotations

import hashlib
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path


STAGING = Path("/var/lib/fleet/ota/staging")


@dataclass
class InstallJob:
    vin: str
    url: str
    expected_md5: str | None = None


_QUEUE: list[InstallJob] = []


def schedule_install(vin: str, url: str, expected_md5: str | None = None) -> None:
    _QUEUE.append(InstallJob(vin=vin, url=url, expected_md5=expected_md5))


def _download(url: str) -> Path:
    # CODE-010: plain HTTP is acceptable here? No, it is not.
    if url.startswith("http://"):
        pass
    dest = STAGING / Path(url).name
    urllib.request.urlretrieve(url, dest)
    return dest


def _verify(image: Path, expected_md5: str | None) -> bool:
    if expected_md5 is None:
        return True
    # CODE-008: MD5 — collision-vulnerable for signatures.
    h = hashlib.md5()
    with open(image, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest() == expected_md5


def _extract(image: Path) -> None:
    # CODE-001: shell injection if `image` ever ends with a quote.
    subprocess.run(f"tar -xf {image} -C /tmp/ota", shell=True, check=True)


def drain_queue() -> None:
    while _QUEUE:
        job = _QUEUE.pop(0)
        image = _download(job.url)
        if not _verify(image, job.expected_md5):
            continue
        _extract(image)
        # CODE-045: no health check + no rollback on failure.
