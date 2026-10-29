# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain

"""Read required service inputs from the pinned product's preflight and Compose files."""
import importlib.util
import json
from pathlib import Path
import sys


def inventory(deploy, files=None):
    spec = importlib.util.spec_from_file_location(
        "product_preflight", deploy / "scripts/compose-preflight.py"
    )
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    reverse = {new: old for old, new in preflight.MAPPING.items()}
    entries = []
    files = ([deploy / name for name in files] if files else
             [deploy / "docker-compose.yml", *sorted(deploy.glob("docker-compose.itest*.yml"))])
    for path in files:
        for environment in preflight.podman_environments(path.read_text()):
            for service_key, expression in environment.items():
                if service_key not in preflight.REQUIRED_SECURITY_INPUTS:
                    continue
                outer = preflight.DOTENV_EXPRESSION.fullmatch(expression)
                if outer:
                    key = outer[1] or outer[2]
                    default = outer[4] if outer[3] in (":-", "-") else ""
                    entries.append(dict(service_key=service_key, key=key,
                                        fixture_key=reverse.get(key, key), default=default or ""))
                elif not expression.strip() or "$" in expression:
                    raise ValueError(f"unsupported required security input: {path.name}:{service_key}")
    if not entries:
        raise ValueError("no required Compose security inputs found")
    return entries


if __name__ == "__main__":
    print(json.dumps(inventory(Path(sys.argv[1]), sys.argv[2:])))
