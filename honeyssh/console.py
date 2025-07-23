from __future__ import annotations
import re
import select
import socket
import time
from .logutils import log_activity
from .completion import autocomplete


def _read_escape_sequence(chan) -> str:
    seq = ""
    end_time = time.time() + 0.2
    while time.time() < end_time:
        timeout = max(0, end_time - time.time())
        readable, _, _ = select.select([chan], [], [], timeout)
        if not readable:
            break
        try:
            ch = chan.recv(1).decode("utf-8", errors="ignore")
        except Exception:
            break
        if not ch:
            break
        seq += ch
        if ch.isalpha() or ch == "~":
            if seq == "O":
                continue
            break
    return seq


def read_line_advanced(
    chan,
    prompt,
    history,
    current_dir,
    username,
    fs,
    session_log,
    session_id,
    client_ip,
    jobs,
    cmd_count,
):
    chan.send(prompt.encode())
    buffer = ""
    pos = 0
    history_index = len(history)
    last_completions = []
    tab_count = 0

    def redraw_line():
        chan.send(b"\r\x1b[2K" + prompt.encode() + buffer.encode())
        diff = len(buffer) - pos
        if diff > 0:
            chan.send(f"\x1b[{diff}D".encode())

    while True:
        readable, _, _ = select.select([chan], [], [], 0.1)
        if readable:
            try:
                raw = chan.recv(1)
                if not raw:
                    return None, jobs, cmd_count
                try:
                    data = raw.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        data = raw.decode("latin-1")
                    except Exception:
                        continue
                if data == "\x1b":
                    data += _read_escape_sequence(chan)
                log_activity(session_id, client_ip, username, data)

                if data in ["\r", "\n"]:
                    chan.send(b"\r\n")
                    if buffer.strip():
                        history.append(buffer.strip())
                    return buffer.strip(), jobs, cmd_count
                elif data == "\t":
                    buffer, last_completions, tab_count = autocomplete(
                        buffer,
                        current_dir,
                        username,
                        fs,
                        chan,
                        history,
                        last_completions,
                        tab_count,
                        prompt,
                    )
                    pos = len(buffer)
                    chan.send(b"\r" + prompt.encode() + buffer.encode() + b"\x1b[K")
                elif data in ["\x7f", "\x08"]:
                    if pos > 0:
                        buffer = buffer[: pos - 1] + buffer[pos:]
                        pos -= 1
                        redraw_line()
                    last_completions = []
                    tab_count = 0
                elif data == "\x03":
                    chan.send(b"^C\r\n")
                    buffer = ""
                    pos = 0
                    history_index = len(history)
                    chan.send(prompt.encode())
                    last_completions = []
                    tab_count = 0
                    continue
                elif data == "\x04":
                    chan.send(b"logout\r\n")
                    return "exit", jobs, cmd_count
                elif re.match(r"\x1b\[[0-9;]*[ABCD]$", data) or re.match(r"\x1bO[ABCD]$", data):
                    key = data[-1]
                    if key == "A":
                        if history_index > 0:
                            history_index -= 1
                            buffer = history[history_index] if 0 <= history_index < len(history) else ""
                            pos = len(buffer)
                        redraw_line()
                    elif key == "B":
                        if history_index < len(history):
                            history_index += 1
                            buffer = history[history_index] if 0 <= history_index < len(history) else ""
                            pos = len(buffer)
                        else:
                            history_index = len(history)
                            buffer = ""
                            pos = 0
                        redraw_line()
                    elif key == "C":
                        if pos < len(buffer):
                            pos += 1
                            chan.send(b"\x1b[C")
                    elif key == "D":
                        if pos > 0:
                            pos -= 1
                            chan.send(b"\x1b[D")
                    last_completions = []
                    tab_count = 0
                elif len(data) == 1 and 32 <= ord(data) <= 255:
                    buffer = buffer[:pos] + data + buffer[pos:]
                    pos += 1
                    redraw_line()
                    last_completions = []
                    tab_count = 0
            except UnicodeDecodeError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Read line error: {e}")
                return "", jobs, cmd_count


def read_password(chan):
    buffer = ""
    while True:
        readable, _, _ = select.select([chan], [], [], 0.1)
        if readable:
            try:
                data = chan.recv(1).decode("utf-8", errors="ignore")
                if data == "\x1b":
                    _read_escape_sequence(chan)
                    continue
                if data in ["\r", "\n"]:
                    chan.send(b"\r\n")
                    return buffer
                elif data == "\x7f" and buffer:
                    buffer = buffer[:-1]
                    chan.send(b"\b \b")
                elif len(data) == 1 and ord(data) >= 32:
                    buffer += data
                    chan.send(b"*")
            except UnicodeDecodeError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Read password error: {e}")
                return ""


__all__ = ["read_line_advanced", "read_password"]
