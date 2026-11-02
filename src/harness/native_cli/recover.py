# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain
"""Keep one fixture phrase in memory between real creation and attended recovery."""
import errno
import fcntl
import json
import os
import pty
import re
import select
import subprocess
import sys
import termios
import time
from create import create_account


class CeremonyFailure(Exception):
    def __init__(self, fields):
        self.fields = fields


def cli_error_code(stderr):
    # Match whole fixed CLI errors; never include an exception, terminal buffer or payload.
    known = {
        b"SDK error: invalid custody setup": "custody_setup_invalid",
        b"SDK error: custody setup expired": "custody_expired",
        b"SDK error: recovery confirmation failed; setup cancelled": "confirmation_failed",
        b"SDK error: non-synchronizing primary vault unavailable; no file fallback": "vault_unavailable",
        b"SDK error: no confirmed home node is selected": "no_node",
        b"Account fingerprint confirmation did not match.": "fingerprint_mismatch",
    }
    return known.get(stderr.strip(), "other_cli_error")


def recover(binary, socket, account, words):
    master, slave = pty.openpty()

    def terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(
        [binary, "--socket", socket, "account", "recover", "--account=" + account],
        stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=terminal, close_fds=True,
    )
    os.close(slave)
    pending = b""
    confirmations = 0
    phrase_sent = False
    password_sent = False
    deadline = time.monotonic() + 100
    try:
        while child.poll() is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("recovery ceremony timed out")
            if not select.select([master], [], [], 0.1)[0]:
                continue
            try:
                data = os.read(master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            pending += data
            if b"Type the displayed account fingerprint to confirm: " in pending:
                match = re.search(rb"Account fingerprint: ([^\r\n]+)", pending)
                if match is None or confirmations:
                    raise RuntimeError("recovery fingerprint prompt changed")
                os.write(master, match[1] + b"\n")
                confirmations += 1
                pending = b""
            if b"Recovery phrase (hidden): " in pending:
                if phrase_sent:
                    raise RuntimeError("duplicate recovery phrase prompt")
                os.write(master, " ".join(words).encode() + b"\n")
                phrase_sent = True
                pending = b""
            if b"Local data passphrase (hidden): " in pending:
                if password_sent:
                    raise RuntimeError("duplicate local passphrase prompt")
                os.write(master, os.environ["RESTORE_LOCAL_PASSPHRASE"].encode() + b"\n")
                password_sent = True
                pending = b""
        output, stderr = child.communicate(timeout=10)
        if child.returncode != 0 or confirmations != 1 or not phrase_sent or not password_sent:
            raise CeremonyFailure({
                "code": cli_error_code(stderr), "exit": child.returncode,
                "confirmed": confirmations, "phrase_sent": phrase_sent,
                "password_sent": password_sent,
            })
        return json.loads(output)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)


def main():
    binary, socket = sys.argv[1:]
    account, words = create_account(binary, socket, "Restore source")
    print(json.dumps(account), flush=True)
    # Only public selectors cross this pipe; words never enter argv, files or test output.
    request = json.loads(sys.stdin.readline())
    try:
        restored = recover(binary, request["socket"], request["account_id"], words)
    finally:
        words.clear()
    print(json.dumps(restored), flush=True)


if __name__ == "__main__":
    try:
        main()
    except CeremonyFailure as error:
        print(json.dumps({"fixture_error": error.fields}), flush=True)
        sys.exit(1)
    except Exception:
        # Never disclose terminal buffers or exception values from a secret ceremony.
        print(json.dumps({"fixture_error": {"code": "helper_failed"}}), flush=True)
        sys.exit(1)
