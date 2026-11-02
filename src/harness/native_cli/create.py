# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Span Brain
"""Drive rf's real local terminal ceremony without recording recovery material."""
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


def create_account(binary, socket, name):
    master, slave = pty.openpty()

    def terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(
        [binary, "--socket", socket, "account", "create", "--display-name", name],
        stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=terminal, close_fds=True,
    )
    os.close(slave)
    pending = b""
    words = []
    challenges = 0
    passwords = 0
    saved = False
    deadline = time.monotonic() + 90
    try:
        while child.poll() is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("rf account create terminal ceremony timed out")
            if not select.select([master], [], [], 0.1)[0]:
                continue
            try:
                data = os.read(master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            pending += data
            if not saved and b"Press Enter after saving the words to hide them: " in pending:
                match = re.search(rb"private\.\r?\n([^\r\n]+)", pending)
                if match is None:
                    raise RuntimeError("rf recovery phrase prompt changed")
                words = match[1].decode().split()
                if len(words) != 24:
                    raise RuntimeError("rf did not show 24 recovery words")
                os.write(master, b"\n")
                pending = b""
                saved = True
            match = re.search(rb"Recovery word (\d+) \(hidden\): ", pending)
            if match:
                os.write(master, words[int(match[1]) - 1].encode() + b"\n")
                challenges += 1
                pending = pending[match.end():]
            for prompt in [b"New local data passphrase (hidden): ", b"Repeat local data passphrase (hidden): "]:
                if prompt in pending:
                    os.write(master, b"group cli test local passphrase\n")
                    passwords += 1
                    pending = b""
        output, _ = child.communicate(timeout=10)
        if child.returncode != 0 or challenges != 3 or passwords != 2:
            # Never echo terminal buffers, stdout or errors from the secret ceremony.
            raise RuntimeError(f"rf account create failed: exit={child.returncode}, challenges={challenges}, passwords={passwords}")
        account = json.loads(output)
        return {"account_id": account["account_id"]}, words
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)


if __name__ == "__main__":
    account, _ = create_account(*sys.argv[1:])
    print(json.dumps(account))
