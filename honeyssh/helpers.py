import os
import random
import fnmatch
from .completion import _visible_len


def _format_ls_columns(items, width=80):
    if not items:
        return ""
    max_len = max(_visible_len(it) for it in items) + 2
    cols = max(1, width // max_len)
    lines = []
    for i in range(0, len(items), cols):
        row = items[i : i + cols]
        padded = [it + " " * (max_len - _visible_len(it)) for it in row]
        lines.append("".join(padded))
    return "\r\n".join(lines)


def _human_size(size):
    units = ["B", "K", "M", "G"]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size}{unit}"
        size //= 1024


def _random_permissions():
    patterns = [
        "rwxr-xr-x",
        "rw-r--r--",
        "rwx------",
        "rwxrwxr-x",
        "rw-rw-r--",
        "rwxr-x---",
    ]
    return random.choice(patterns)


def has_wildcards(path: str) -> bool:
    return any(ch in path for ch in ["*", "?", "[", "]"])


def expand_wildcards(arg, current_dir, fs, username):
    if not has_wildcards(arg):
        return [arg]
    if arg.startswith("~"):
        arg = arg.replace("~", f"/home/{username}", 1)
    if not arg.startswith("/"):
        arg = f"{current_dir}/{arg}" if current_dir != "/" else f"/{arg}"
    pattern = os.path.normpath(arg)
    matches = sorted(p for p in fs if fnmatch.fnmatch(p, pattern))
    return matches if matches else [arg]


__all__ = [
    "_format_ls_columns",
    "_human_size",
    "_random_permissions",
    "has_wildcards",
    "expand_wildcards",
]
