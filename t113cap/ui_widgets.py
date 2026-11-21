from __future__ import annotations

import os
import shutil
import subprocess
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Iterable, List, Optional, Sequence, Tuple

from .ui_theme import (
    ACCENT,
    BG_ALT,
    BORDER,
    FONT,
    FONT_MONO,
    GREEN,
    MUTED,
    PANEL,
    PANEL_2,
    RED,
    TEXT,
    TEXT_SOFT,
)


class Card(tk.Frame):
    def __init__(self, parent, padding: int = 15, **kwargs):
        super().__init__(
            parent,
            bg=PANEL,
            highlightbackground=BORDER,
            highlightthickness=1,
            bd=0,
            **kwargs,
        )
        self.body = tk.Frame(self, bg=PANEL)
        self.body.pack(fill="both", expand=True, padx=padding, pady=padding)


def section_header(parent, title: str, hint: str = "", right: Optional[tk.Widget] = None) -> tk.Frame:
    header = tk.Frame(parent, bg=PANEL)
    accent = tk.Frame(header, bg=ACCENT, width=3, height=18)
    accent.pack(side="left", padx=(0, 8))
    accent.pack_propagate(False)
    label = tk.Label(header, text=title, bg=PANEL, fg=TEXT, font=(FONT, 10, "bold"), anchor="w")
    label.pack(side="left")
    if hint:
        tk.Label(header, text=hint, bg=PANEL, fg=MUTED, font=(FONT, 8), anchor="w").pack(
            side="left", padx=(8, 0)
        )
    if right is not None:
        right.pack(side="right")
    return header


def field_label(parent, text: str, row: int, column: int = 0) -> tk.Label:
    label = tk.Label(parent, text=text, bg=PANEL, fg=MUTED, font=(FONT, 8), anchor="w")
    label.grid(row=row, column=column, sticky="w", pady=(2, 1))
    return label


class StatTile(tk.Frame):
    def __init__(self, parent, title: str, value: str = "--", accent: str = TEXT):
        super().__init__(parent, bg=BG_ALT, highlightbackground=BORDER, highlightthickness=1, bd=0)
        self.title_label = tk.Label(
            self, text=title, bg=BG_ALT, fg=MUTED, font=(FONT, 8), anchor="w"
        )
        self.title_label.pack(fill="x", padx=12, pady=(9, 0))
        self.value_label = tk.Label(
            self, text=value, bg=BG_ALT, fg=accent, font=(FONT, 15, "bold"), anchor="w"
        )
        self.value_label.pack(fill="x", padx=12, pady=(1, 9))

    def set(self, value: str, color: Optional[str] = None) -> None:
        self.value_label.configure(text=value, fg=color or TEXT)


def make_tree(
    parent,
    columns: Sequence[Tuple[str, str, int, str, bool]],
    height: int = 10,
) -> Tuple[tk.Frame, ttk.Treeview]:
    frame = tk.Frame(parent, bg=PANEL)
    tree = ttk.Treeview(
        frame,
        columns=[column[0] for column in columns],
        show="headings",
        height=height,
        selectmode="browse",
    )
    for key, title, width, anchor, stretch in columns:
        tree.heading(key, text=title, anchor="w")
        tree.column(key, width=width, minwidth=40, anchor=anchor, stretch=stretch)
    vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return frame, tree


def make_console(parent, height: int = 9) -> Tuple[tk.Frame, tk.Text]:
    frame = tk.Frame(parent, bg=BG_ALT, highlightbackground=BORDER, highlightthickness=1)
    text = tk.Text(
        frame,
        height=height,
        bg=BG_ALT,
        fg=TEXT_SOFT,
        insertbackground=TEXT,
        relief="flat",
        borderwidth=0,
        wrap="word",
        font=(FONT_MONO, 9),
        padx=10,
        pady=8,
        state="disabled",
    )
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=scrollbar.set)
    text.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    text.tag_configure("time", foreground="#587291")
    text.tag_configure("info", foreground=TEXT_SOFT)
    text.tag_configure("ok", foreground=GREEN)
    text.tag_configure("warn", foreground="#fbbf24")
    text.tag_configure("error", foreground=RED)
    text.tag_configure("accent", foreground=ACCENT)
    return frame, text


def clear_tree(tree: ttk.Treeview) -> None:
    children = tree.get_children()
    if children:
        tree.delete(*children)


def truncate_middle(text: str, length: int) -> str:
    if length <= 4 or len(text) <= length:
        return text
    left = (length - 3) // 2
    right = length - 3 - left
    return text[:left] + "..." + text[-right:]


def format_mtime(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "--"


def find_wireshark() -> Optional[str]:
    which = shutil.which("wireshark")
    if which:
        return which
    candidates = [
        Path(r"C:\Program Files\Wireshark\Wireshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\Wireshark.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def open_path(path: str) -> None:
    if os.name == "nt":
        os.startfile(path)  # type: ignore[attr-defined]
        return
    subprocess.Popen(["xdg-open", path])


def open_wireshark(path: str) -> bool:
    exe = find_wireshark()
    if exe:
        subprocess.Popen([exe, path])
        return True
    try:
        open_path(path)
        return True
    except OSError:
        return False


def set_text(text: tk.Text, content: str) -> None:
    text.configure(state="normal")
    text.delete("1.0", "end")
    text.insert("1.0", content)
    text.configure(state="disabled")
