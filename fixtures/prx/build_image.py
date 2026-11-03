#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain

"""Build one pinned fixture image and record cold/warm timings and its identity."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime", choices=["docker", "podman"])
    parser.add_argument("--measure-cold", action="store_true")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    source = (fixture / "Containerfile").read_text()
    revision = next(line.removeprefix("ARG PRX_SHA=") for line in source.splitlines()
                    if line.startswith("ARG PRX_SHA="))
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise SystemExit("invalid pinned fixture revision")
    tag = f"localhost/ramflux-itest-prx:{revision[:8]}"
    args.evidence.mkdir(parents=True, exist_ok=True)
    records = []
    for mode in (["cold", "warm"] if args.measure_cold else ["warm"]):
        command = [args.runtime, "build", "-t", tag, "-f", str(fixture / "Containerfile")]
        if args.runtime == "podman":
            command.append("--layers")
        if mode == "cold":
            command.append("--no-cache")
        command.append(str(fixture))
        started = time.monotonic()
        with (args.evidence / f"prx-image-{mode}.log").open("w") as log:
            try:
                code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                      timeout=10800, check=False).returncode
            except subprocess.TimeoutExpired:
                code = 124
        record = {"mode": mode, "seconds": round(time.monotonic() - started, 3),
                  "exit": code, "revision": revision, "tag": tag}
        records.append(record)
        (args.evidence / "prx-image-times.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        if code:
            return code
    identity = subprocess.check_output([args.runtime, "image", "inspect", "--format", "{{.Id}}", tag],
                                       text=True, timeout=60).strip()
    (args.evidence / "prx-image-id.txt").write_text(identity + "\n")
    print(f"PRX fixture image: {identity}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
