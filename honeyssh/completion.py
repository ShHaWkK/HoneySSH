from __future__ import annotations
import os
import re
from .constants import (
    AVAILABLE_COMMANDS,
    COMMAND_OPTIONS,
    USER_DEFINED_COMMANDS,
    FAKE_MYSQL_DATA,
    FAKE_NETWORK_HOSTS,
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def get_completions(current_input, current_dir, username, fs, history):
    base_cmds = (
        AVAILABLE_COMMANDS
        + list(COMMAND_OPTIONS.keys())
        + list(USER_DEFINED_COMMANDS)
        + [
            "whoami",
            "id",
            "uname",
            "pwd",
            "exit",
            "history",
            "sudo",
            "su",
            "curl",
            "wget",
            "telnet",
            "ping",
            "nmap",
            "traceroute",
            "tracepath",
            "dig",
            "nslookup",
            "tcpdump",
            "nc",
            "netcat",
            "ss",
            "man",
            "arp",
            "scp",
            "sftp",
            "who",
            "w",
            "touch",
            "rm",
            "mkdir",
            "rmdir",
            "cp",
            "mv",
            "backup_data",
            "systemctl",
            "fg",
            "app_status",
            "status_report",
            "jobs",
        ]
    )
    if current_dir == "__mysql__":
        mysql_words = ["SELECT", "FROM", "WHERE", "SHOW", "USE", "DESCRIBE", "EXIT", "\\q"]
        mysql_words += list(FAKE_MYSQL_DATA.keys())
        for db in FAKE_MYSQL_DATA.values():
            mysql_words.extend(db.keys())
        if not current_input.strip():
            return sorted(mysql_words)
        partial = current_input.strip().split()[-1]
        return sorted([w for w in mysql_words if w.lower().startswith(partial.lower())])
    if not current_input.strip():
        return sorted(base_cmds)
    parts = current_input.strip().split()
    cmd = parts[0] if parts else ""
    partial = parts[-1] if parts else ""
    prev_parts = parts[:-1] if len(parts) > 1 else []
    completions: list[str] = []

    redirect_match = re.search(r"(?:>>|>)\s*(\S*)$", current_input)
    if redirect_match:
        partial_path = redirect_match.group(1)
        base_path = partial_path if partial_path.startswith("/") else (f"{current_dir}/{partial_path}" if current_dir != "/" else f"/{partial_path}")
        path = os.path.normpath(base_path)
        if not partial_path or partial_path.endswith("/"):
            parent_dir = path
            base_name = ""
        else:
            parent_dir = os.path.dirname(path) or "/"
            base_name = os.path.basename(path)
        if parent_dir in fs and fs[parent_dir]["type"] == "dir" and "contents" in fs[parent_dir]:
            for item in fs[parent_dir]["contents"]:
                full_path = f"{parent_dir}/{item}" if parent_dir != "/" else f"/{item}"
                if full_path in fs and item.startswith(base_name):
                    completions.append(item)
        prefix = partial_path if partial_path.endswith("/") else (partial_path.rsplit("/", 1)[0] + "/") if "/" in partial_path else ""
        return sorted([f"{prefix}{c}" for c in completions])
    if len(parts) == 1 and not current_input.endswith(" "):
        completions = [c for c in base_cmds if c.startswith(partial)]
        return sorted(completions)
    if cmd in COMMAND_OPTIONS and (partial.startswith("-") or (prev_parts and prev_parts[-1].startswith("-"))):
        completions = [opt for opt in COMMAND_OPTIONS[cmd] if opt.startswith(partial)]
        return sorted(completions)
    if cmd in ["cd", "ls", "cat", "rm", "scp", "find", "grep", "touch", "mkdir", "rmdir", "cp", "mv"]:
        base_path = partial if partial.startswith("/") else (f"{current_dir}/{partial}" if current_dir != "/" else f"/{partial}")
        path = os.path.normpath(base_path)
        if partial.endswith("/"):
            parent_dir = path
            base_name = ""
        else:
            parent_dir = os.path.dirname(path) or "/"
            base_name = os.path.basename(path)
        if parent_dir in fs and fs[parent_dir]["type"] == "dir" and "contents" in fs[parent_dir]:
            for item in fs[parent_dir]["contents"]:
                full_path = f"{parent_dir}/{item}" if parent_dir != "/" else f"/{item}"
                if full_path in fs and item.startswith(base_name):
                    if cmd == "cd" and fs[full_path]["type"] == "dir":
                        completions.append(item)
                    elif cmd in ["ls", "cat", "rm", "scp", "find", "grep", "touch", "mkdir", "rmdir", "cp", "mv"]:
                        completions.append(item)
        prefix = partial if partial.endswith("/") else (partial.rsplit("/", 1)[0] + "/") if "/" in partial else ""
        return sorted([f"{prefix}{c}" for c in completions])
    if cmd in ["ping", "telnet", "nmap", "traceroute", "tracepath", "dig", "nslookup", "scp", "curl", "wget"]:
        for ip, info in FAKE_NETWORK_HOSTS.items():
            if info["name"].startswith(partial) or ip.startswith(partial):
                completions.append(info["name"])
                completions.append(ip)
    completions.extend([h for h in history[-10:] if h.startswith(partial)])
    return sorted(completions)


def autocomplete(
    current_input,
    current_dir,
    username,
    fs,
    chan,
    history,
    last_completions=None,
    tab_count=0,
    prompt="",
):
    last_completions = last_completions or []
    completions = get_completions(current_input, current_dir, username, fs, history)

    parts = current_input.split()
    partial = ""
    if current_input.endswith(" "):
        partial = ""
    elif parts:
        partial = parts[-1]

    def _apply_completion(word):
        p = parts[:-1] if parts else []
        p.append(word)
        return " ".join(p)

    if not completions:
        return current_input, [], 0

    path_cmds = ["cd", "ls", "cat", "rm", "scp", "find", "grep", "touch", "mkdir", "rmdir", "cp", "mv"]

    if tab_count > 0 and completions == last_completions:
        chan.send(b"\r\n")
        display_list = []
        for c in completions:
            norm = os.path.normpath(f"{current_dir}/{c}" if not c.startswith("/") else c)
            if norm in fs and fs[norm]["type"] == "dir":
                disp = f"\033[01;34m{c}\033[0m/"
            else:
                disp = c
            display_list.append(disp)
        max_len = max(_visible_len(it) for it in display_list) + 2
        per_row = max(1, 80 // max_len)
        for i, it in enumerate(display_list):
            pad = max_len - _visible_len(it)
            chan.send((it + " " * pad).encode())
            if (i + 1) % per_row == 0:
                chan.send(b"\r\n")
        if len(display_list) % per_row:
            chan.send(b"\r\n")
        chan.send(b"\r" + prompt.encode() + current_input.encode() + b"\x1b[K")
        return current_input, completions, 0

    if len(completions) == 1:
        completion = completions[0]
        cmd = parts[0] if parts else ""
        path = completion
        if cmd in path_cmds:
            if not completion.startswith("/"):
                path = os.path.normpath(f"{current_dir}/{completion}" if current_dir != "/" else f"/{completion}")
            if path in fs and fs[path]["type"] == "dir":
                completion += "/"
        return _apply_completion(completion), [], 0

    common = os.path.commonprefix(completions)
    if common and common != partial:
        path = os.path.normpath(f"{current_dir}/{common}" if not common.startswith("/") else common)
        if path in fs and fs[path]["type"] == "dir":
            common += "/"
        return _apply_completion(common), completions, 1

    return current_input, completions, 1


__all__ = ["_visible_len", "get_completions", "autocomplete"]
