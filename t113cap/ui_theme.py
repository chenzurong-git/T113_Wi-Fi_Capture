from __future__ import annotations

import tkinter as tk
from tkinter import ttk


BG = "#08111f"
BG_ALT = "#0c1728"
PANEL = "#101d31"
PANEL_2 = "#15243b"
PANEL_3 = "#1b2c47"
BORDER = "#263b5c"
BORDER_SOFT = "#1c2d49"
TEXT = "#e9f1fb"
TEXT_SOFT = "#c3d1e5"
MUTED = "#8298b8"
ACCENT = "#22d3ee"
ACCENT_2 = "#0ea5c6"
ACCENT_DARK = "#073b49"
GREEN = "#34d399"
GREEN_DARK = "#064e3b"
RED = "#fb7185"
RED_DARK = "#4c1020"
AMBER = "#fbbf24"
BLUE = "#60a5fa"

FONT = "Microsoft YaHei UI"
FONT_MONO = "Cascadia Mono"


def configure_theme(root: tk.Tk) -> ttk.Style:
    root.configure(bg=BG)
    root.option_add("*Font", (FONT, 9))
    root.option_add("*TCombobox*Listbox.background", PANEL_2)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_DARK)
    root.option_add("*TCombobox*Listbox.selectForeground", TEXT)
    root.option_add("*TCombobox*Listbox.font", (FONT, 9))

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", font=(FONT, 9), background=BG, foreground=TEXT)
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED)
    style.configure("PanelAccent.TLabel", background=PANEL, foreground=ACCENT)

    style.configure(
        "TButton",
        background=PANEL_2,
        foreground=TEXT,
        borderwidth=0,
        focusthickness=0,
        padding=(12, 8),
    )
    style.map(
        "TButton",
        background=[("active", PANEL_3), ("disabled", PANEL_2)],
        foreground=[("disabled", MUTED)],
    )
    style.configure(
        "Accent.TButton",
        background=ACCENT,
        foreground="#06222b",
        borderwidth=0,
        focusthickness=0,
        padding=(14, 10),
        font=(FONT, 10, "bold"),
    )
    style.map(
        "Accent.TButton",
        background=[("active", "#67e8f9"), ("pressed", ACCENT_2), ("disabled", "#174653")],
        foreground=[("disabled", "#6f93a0")],
    )
    style.configure(
        "Danger.TButton",
        background=RED,
        foreground="#2b0710",
        borderwidth=0,
        focusthickness=0,
        padding=(14, 10),
        font=(FONT, 10, "bold"),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#fda4af"), ("pressed", "#e11d48"), ("disabled", "#4f2530")],
        foreground=[("disabled", "#9b7a83")],
    )
    style.configure(
        "Secondary.TButton",
        background=PANEL_2,
        foreground=TEXT_SOFT,
        borderwidth=0,
        padding=(11, 8),
    )
    style.map("Secondary.TButton", background=[("active", PANEL_3), ("disabled", PANEL_2)])
    style.configure(
        "Ghost.TButton",
        background=PANEL,
        foreground=MUTED,
        borderwidth=0,
        padding=(8, 6),
    )
    style.map("Ghost.TButton", background=[("active", PANEL_2)], foreground=[("active", TEXT)])

    style.configure(
        "TEntry",
        fieldbackground=PANEL_2,
        foreground=TEXT,
        insertcolor=TEXT,
        bordercolor=BORDER,
        lightcolor=PANEL_2,
        darkcolor=PANEL_2,
        padding=7,
    )
    style.map("TEntry", bordercolor=[("focus", ACCENT)], fieldbackground=[("disabled", BG_ALT)])
    style.configure(
        "TCombobox",
        fieldbackground=PANEL_2,
        background=PANEL_2,
        foreground=TEXT,
        arrowcolor=TEXT_SOFT,
        bordercolor=BORDER,
        lightcolor=PANEL_2,
        darkcolor=PANEL_2,
        padding=6,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", PANEL_2), ("disabled", BG_ALT)],
        foreground=[("readonly", TEXT), ("disabled", MUTED)],
        bordercolor=[("focus", ACCENT)],
    )
    style.configure(
        "TSpinbox",
        fieldbackground=PANEL_2,
        background=PANEL_2,
        foreground=TEXT,
        arrowcolor=TEXT_SOFT,
        bordercolor=BORDER,
        lightcolor=PANEL_2,
        darkcolor=PANEL_2,
        padding=6,
    )
    style.map("TSpinbox", bordercolor=[("focus", ACCENT)])

    style.configure(
        "Card.TCheckbutton",
        background=PANEL,
        foreground=TEXT_SOFT,
        indicatorbackground=PANEL_2,
        indicatorforeground=ACCENT,
        bordercolor=BORDER,
        focuscolor=PANEL,
        padding=2,
    )
    style.map(
        "Card.TCheckbutton",
        background=[("active", PANEL)],
        foreground=[("active", TEXT), ("disabled", MUTED)],
        indicatorbackground=[("selected", ACCENT), ("active", PANEL_3)],
    )

    style.configure(
        "Mode.TRadiobutton",
        background=PANEL_2,
        foreground=MUTED,
        borderwidth=0,
        padding=(8, 7),
        font=(FONT, 9),
    )
    style.map(
        "Mode.TRadiobutton",
        background=[("selected", ACCENT), ("active", PANEL_3)],
        foreground=[("selected", "#06222b"), ("active", TEXT)],
    )

    style.configure(
        "Treeview",
        background=PANEL,
        fieldbackground=PANEL,
        foreground=TEXT_SOFT,
        bordercolor=PANEL,
        lightcolor=PANEL,
        darkcolor=PANEL,
        rowheight=27,
        font=(FONT, 9),
    )
    style.map(
        "Treeview",
        background=[("selected", "#123a4a")],
        foreground=[("selected", TEXT)],
    )
    style.configure(
        "Treeview.Heading",
        background=BG_ALT,
        foreground=MUTED,
        borderwidth=0,
        relief="flat",
        padding=(7, 7),
        font=(FONT, 9, "bold"),
    )
    style.map("Treeview.Heading", background=[("active", PANEL_3)], foreground=[("active", TEXT)])

    style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
    style.configure(
        "TNotebook.Tab",
        background=BG,
        foreground=MUTED,
        borderwidth=0,
        padding=(16, 9),
        font=(FONT, 9, "bold"),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", PANEL), ("active", BG_ALT)],
        foreground=[("selected", ACCENT), ("active", TEXT)],
    )
    style.configure("TScrollbar", background=PANEL_2, troughcolor=BG_ALT, borderwidth=0, arrowcolor=MUTED)
    style.map("TScrollbar", background=[("active", PANEL_3)])
    style.configure("TSeparator", background=BORDER_SOFT)
    return style
