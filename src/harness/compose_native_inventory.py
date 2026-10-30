# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain

"""Verify enabled native service inputs in real provider output without printing credentials."""
import importlib.util
import json
import os
from pathlib import Path
import sys


def check(deploy, provider, gateways, rendered):
    spec = importlib.util.spec_from_file_location("product_preflight", deploy / "scripts/compose-preflight.py")
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    environments = (preflight.docker_environments(rendered) if provider == "docker"
                    else preflight.podman_service_inputs(rendered)[0])
    fields = ["RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED",
              "RAMFLUX_CUSTODY_NODE_RECORD_FILE", "RAMFLUX_CUSTODY_HANDSHAKE_POOL",
              "RAMFLUX_CUSTODY_AUTHENTICATED_POOL", "RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS"]
    counts = dict.fromkeys(fields, 0)
    for environment in environments:
        for field in fields:
            if field not in environment:
                continue
            source = field
            if field == "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED":
                source = {"gw-a": "RAMFLUX_CUSTODY_GATEWAY_A_SIGNING_SEED",
                          "gw-b": "RAMFLUX_CUSTODY_GATEWAY_B_SIGNING_SEED"}.get(
                              environment.get("RAMFLUX_GATEWAY_ID"), field)
            expected = os.environ[source]
            assert expected and environment[field] == expected, field
            counts[field] += 1
    for field, count in counts.items():
        expected = (gateways if field == "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED" else
                    1 if field == "RAMFLUX_CUSTODY_NODE_RECORD_FILE" else gateways + 1)
        assert count == expected, field
    print(json.dumps({"provider": provider, "gateways": gateways, "checked_service_fields": counts}))


if __name__ == "__main__":
    check(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.stdin.read())
