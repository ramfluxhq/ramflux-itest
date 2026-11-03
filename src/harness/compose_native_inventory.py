# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain

"""Validate provider environments using the Rust field policy without printing credentials."""
import importlib.util
import json
import os
from pathlib import Path
import sys


def check(deploy, provider, gateways, fields, rendered):
    spec = importlib.util.spec_from_file_location("product_preflight", deploy / "scripts/compose-preflight.py")
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    environments = (preflight.docker_environments(rendered) if provider == "docker"
                    else preflight.podman_service_inputs(rendered)[0])
    counts = {field["key"]: 0 for field in fields}
    roles = {field["key"]: [] for field in fields}
    empty_excerpts = []
    for environment in environments:
        role = ("router" if "RAMFLUX_CUSTODY_NODE_RECORD_FILE" in environment else
                "gateway" if "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED" in environment else None)
        if role:
            empty_excerpts.append({"service_role": role, "rendered_empty_allowed_fields": {
                field["key"]: environment[field["key"]] for field in fields
                if field["allow_empty"] and field["key"] in environment}})
        for field in fields:
            key = field["key"]
            if key not in environment:
                continue
            assert role and field["service_set"] in (role, "both"), key + ": unexpected service"
            source = key
            if key == "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED":
                source = {"gw-a": "RAMFLUX_CUSTODY_GATEWAY_A_SIGNING_SEED",
                          "gw-b": "RAMFLUX_CUSTODY_GATEWAY_B_SIGNING_SEED"}.get(
                              environment.get("RAMFLUX_GATEWAY_ID"), key)
            expected = os.environ[source]
            assert field["allow_empty"] or expected, key + ": required input empty"
            assert environment[key] == expected, key + ": value changed"
            counts[key] += 1
            roles[key].append(role)
    for field in fields:
        key, service_set = field["key"], field["service_set"]
        expected = 1 if service_set == "router" else gateways if service_set == "gateway" else gateways + 1
        assert counts[key] == expected, (f"{key}: count={counts[key]} expected={expected}; "
                                         f"rendered_excerpt={json.dumps(empty_excerpts)}")
    print(json.dumps({"provider": provider, "gateways": gateways,
                      "checked_service_fields": counts, "service_sets": roles}))


if __name__ == "__main__":
    check(Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4]), sys.stdin.read())
