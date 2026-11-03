#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain
"""Transfer exactly one pinned PRX image and verify its immutable image ID."""
import argparse
import json
from pathlib import Path
import subprocess
import tarfile


def run(*args):
    return subprocess.check_output(args, timeout=300, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("save", "load"))
    parser.add_argument("runtime", choices=("docker", "podman"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    pin = next(line.removeprefix("ARG PRX_SHA=") for line in Path(__file__).with_name("Containerfile").read_text().splitlines() if line.startswith("ARG PRX_SHA="))
    tag = f"localhost/ramflux-itest-prx:{pin[:8]}"
    archive = args.directory / "prx.tar"
    record = args.directory / "image.json"
    if args.mode == "save":
        args.directory.mkdir(parents=True, exist_ok=True)
        image_id = run(args.runtime, "image", "inspect", "--format", "{{.Id}}", tag)
        subprocess.run([args.runtime, "save", "--output", str(archive), tag], check=True, timeout=300)
        record.write_text(json.dumps({"id": image_id, "tag": tag, "revision": pin}) + "\n")
    with tarfile.open(archive) as stream:
        manifest = stream.extractfile("manifest.json")
        if manifest is None:
            raise ValueError("archive has no Docker manifest")
        entries = json.load(manifest)
        if len(entries) != 1 or entries[0]["RepoTags"] != [tag]:
            raise ValueError("archive must contain exactly the pinned PRX image")
    if args.mode == "load":
        expected = json.loads(record.read_text())
        if expected["tag"] != tag or expected["revision"] != pin:
            raise ValueError("archive provenance does not match pinned revision")
        subprocess.run([args.runtime, "load", "--input", str(archive)], check=True, timeout=300)
        actual = run(args.runtime, "image", "inspect", "--format", "{{.Id}}", tag)
        if actual != expected["id"]:
            raise ValueError("loaded image ID differs from build artifact")
    revision = run(args.runtime, "image", "inspect", "--format", '{{index .Config.Labels "org.opencontainers.image.revision"}}', tag)
    if revision != pin:
        raise ValueError("image revision label differs from pinned revision")
    print(f"PRX {args.mode}: one image, immutable ID and revision verified")


if __name__ == "__main__":
    main()
