from __future__ import annotations

import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, List, Optional

from .adb import AdbClient, AdbDevice, AdbError
from .controller import CaptureConfig, CaptureStatus, DeviceInfo, StreamCaptureSession, T113Controller
from .pcap_reader import (
    PcapMeta,
    PcapSummary,
    export_packets_csv,
    format_bytes,
    format_duration,
    read_pcap,
    scan_pcap,
    trim_incomplete_pcap_tail,
)
from .settings import AppSettings, load_settings, save_settings
from .ui_theme import (
    ACCENT,
    AMBER,
    BG,
    BG_ALT,
    BLUE,
    BORDER,
    FONT,
    GREEN,
    MUTED,
    PANEL,
    PANEL_2,
    RED,
    TEXT,
    TEXT_SOFT,
    configure_theme,
)
from .ui_widgets import (
    Card,
    StatTile,
    clear_tree,
    field_label,
    find_wireshark,
    format_mtime,
    make_console,
    make_tree,
    open_path,
    open_wireshark,
    section_header,
    set_text,
    truncate_middle,
)


STATE_IDLE = "idle"
STATE_STARTING = "starting"
STATE_CAPTURING = "capturing"
STATE_STOPPING = "stopping"
STATE_PROCESSING = "processing"


class T113CaptureApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.adb = AdbClient(self.settings.adb_path or None)
        self.controller = T113Controller(self.adb)
        self.devices: List[AdbDevice] = []
        self.device_info: Optional[DeviceInfo] = None
        self.selected_serial = self.settings.serial
        self.ui_queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self.state = STATE_IDLE
        self.operation_busy = False
        self.monitor_active = False
        self.capture_config: Optional[CaptureConfig] = None
        self.stream_session: Optional[StreamCaptureSession] = None
        self.capture_local_path: Optional[Path] = None
        self.capture_started_monotonic = 0.0
        self.capture_started_wall: Optional[datetime] = None
        self.remote_size = 0
        self.poll_token = 0
        self.poll_inflight = False
        self.finishing = False
        self.closing = False
        self.record_meta: Dict[str, PcapMeta] = {}
        self.record_paths: Dict[str, str] = {}
        self.summary_cache: Dict[str, PcapSummary] = {}
        self.current_summary: Optional[PcapSummary] = None
        self.packet_by_iid: Dict[str, Any] = {}
        self.scan_inflight = False
        self.device_refresh_inflight = False
        self.summary_inflight_path: Optional[str] = None
        self.last_log_tail = ""

        self.var_device = tk.StringVar()
        self.var_channel = tk.StringVar(value=str(self.settings.channel))
        self.var_mode = tk.StringVar(value=self.settings.mode)
        self.var_count = tk.StringVar(value=str(self.settings.packet_count))
        self.var_duration = tk.StringVar(value=str(self.settings.duration_sec))
        self.var_filter = tk.StringVar(value=self.settings.bpf_filter)
        self.var_delete_remote = tk.BooleanVar(value=self.settings.delete_remote)
        self.var_open_wireshark = tk.BooleanVar(value=self.settings.open_wireshark)
        self.var_restore_exit = tk.BooleanVar(value=self.settings.restore_on_exit)
        self.var_stream_capture = tk.BooleanVar(value=self.settings.stream_capture)
        self.var_output_dir = tk.StringVar(value=self.settings.output_dir)
        self.var_search = tk.StringVar()
        self.var_type_filter = tk.StringVar(value="全部")

        self.minsize(1000, 680)
        self.title("T113 WiFi Capture · ADB 抓包控制台")
        configure_theme(self)
        self._center_window()
        self._apply_window_icon()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._drain_ui_queue)
        self.after(220, self._startup)

    def _center_window(self) -> None:
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        width = max(1000, min(1280, screen_width - 80))
        height = max(680, min(900, screen_height - 90))
        x = max(0, (screen_width - width) // 2)
        y = max(0, (screen_height - height) // 2 - 12)
        self.geometry("{}x{}+{}+{}".format(width, height, x, y))

    def _apply_window_icon(self) -> None:
        base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
        icon_path = base / "assets" / "t113_capture.ico"
        if icon_path.is_file():
            try:
                self.iconbitmap(str(icon_path))
            except tk.TclError:
                pass

    def _build_ui(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._build_header()

        body = tk.Frame(self, bg=BG)
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=(14, 8))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, minsize=354)
        body.grid_columnconfigure(1, weight=1)

        left = tk.Frame(body, bg=BG, width=354)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        self._build_left_panel(left)

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)
        self._build_right_panel(right)
        self._build_footer()

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=BG_ALT, height=82, highlightbackground=BORDER, highlightthickness=1)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        brand = tk.Frame(header, bg=BG_ALT)
        brand.grid(row=0, column=0, sticky="w", padx=(22, 14), pady=14)
        canvas = tk.Canvas(brand, width=44, height=44, bg=BG_ALT, highlightthickness=0)
        canvas.pack(side="left")
        canvas.create_oval(2, 2, 42, 42, fill="#0b2d3b", outline="#15566a")
        canvas.create_arc(10, 12, 34, 36, start=225, extent=90, style="arc", outline=ACCENT, width=2)
        canvas.create_arc(7, 8, 37, 39, start=224, extent=92, style="arc", outline="#67e8f9", width=2)
        canvas.create_oval(19, 22, 25, 28, fill=ACCENT, outline="")

        title_box = tk.Frame(brand, bg=BG_ALT)
        title_box.pack(side="left", padx=(12, 0))
        tk.Label(
            title_box,
            text="T113  WiFi  Capture",
            bg=BG_ALT,
            fg=TEXT,
            font=(FONT, 16, "bold"),
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="ADB 抓包控制台  ·  Monitor Mode  ·  PCAP",
            bg=BG_ALT,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        right = tk.Frame(header, bg=BG_ALT)
        right.grid(row=0, column=2, sticky="e", padx=22, pady=14)
        self.header_pill = tk.Frame(right, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        self.header_pill.pack(side="left", padx=(0, 12))
        self.header_dot = tk.Canvas(self.header_pill, width=12, height=12, bg=PANEL, highlightthickness=0)
        self.header_dot.pack(side="left", padx=(10, 4), pady=8)
        self.header_dot_id = self.header_dot.create_oval(3, 3, 9, 9, fill=MUTED, outline="")
        self.lbl_header_state = tk.Label(
            self.header_pill, text="未连接", bg=PANEL, fg=MUTED, font=(FONT, 8), padx=2
        )
        self.lbl_header_state.pack(side="left", padx=(0, 10), pady=6)

        self.cmb_device = ttk.Combobox(right, textvariable=self.var_device, width=26, state="readonly")
        self.cmb_device.pack(side="left", padx=(0, 8))
        self.cmb_device.bind("<<ComboboxSelected>>", self._on_device_selected)
        self.btn_refresh = ttk.Button(
            right, text="刷新设备", style="Secondary.TButton", command=lambda: self._refresh_devices(True)
        )
        self.btn_refresh.pack(side="left")

    def _build_left_panel(self, parent: tk.Frame) -> None:
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        scroll_host = tk.Frame(parent, bg=BG)
        scroll_host.grid(row=0, column=0, sticky="nsew")
        scroll_host.grid_rowconfigure(0, weight=1)
        scroll_host.grid_columnconfigure(0, weight=1)
        canvas = tk.Canvas(scroll_host, bg=BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(scroll_host, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        inner = tk.Frame(canvas, bg=BG)
        inner_window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_inner_configure(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(event) -> None:
            canvas.itemconfigure(inner_window, width=event.width)

        def on_mousewheel(event) -> None:
            if canvas.winfo_exists():
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        inner.bind("<Configure>", on_inner_configure)
        canvas.bind("<Configure>", on_canvas_configure)
        canvas.bind("<Enter>", lambda _event: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda _event: canvas.unbind_all("<MouseWheel>"))

        device_card = Card(inner, padding=10)
        device_card.pack(fill="x", pady=(0, 8))
        section_header(device_card.body, "设备信息", "ADB").pack(fill="x", pady=(0, 7))
        info_grid = tk.Frame(device_card.body, bg=PANEL)
        info_grid.pack(fill="x")
        info_grid.grid_columnconfigure(0, minsize=54)
        info_grid.grid_columnconfigure(1, weight=1)
        self.device_values: Dict[str, tk.Label] = {}
        rows = [("model", "型号"), ("os", "系统"), ("kernel", "内核"), ("privilege", "权限"), ("monitor", "监听口")]
        for row, (key, title) in enumerate(rows):
            field_label(info_grid, title, row, 0)
            value = tk.Label(
                info_grid,
                text="--",
                bg=PANEL,
                fg=TEXT_SOFT,
                font=(FONT, 8),
                anchor="w",
                justify="left",
            )
            value.grid(row=row, column=1, sticky="ew", padx=(4, 0), pady=(2, 1))
            self.device_values[key] = value

        device_actions = tk.Frame(device_card.body, bg=PANEL)
        device_actions.pack(fill="x", pady=(9, 0))
        self.btn_init = ttk.Button(
            device_actions,
            text="初始化监听",
            style="Accent.TButton",
            command=self._initialize_monitor,
        )
        self.btn_init.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.btn_restore = ttk.Button(
            device_actions,
            text="恢复设备",
            style="Secondary.TButton",
            command=self._restore_device,
        )
        self.btn_restore.pack(side="left", fill="x", expand=True, padx=(5, 0))

        monitor_card = Card(inner, padding=10)
        monitor_card.pack(fill="x", pady=(0, 8))
        section_header(monitor_card.body, "监听与信道", "mon1").pack(fill="x", pady=(0, 7))
        channel_row = tk.Frame(monitor_card.body, bg=PANEL)
        channel_row.pack(fill="x")
        self.cmb_channel = ttk.Combobox(
            channel_row,
            textvariable=self.var_channel,
            values=[str(value) for value in list(range(1, 15)) + list(range(36, 166, 4))],
            width=8,
        )
        self.cmb_channel.pack(side="left")
        self.btn_channel = ttk.Button(
            channel_row, text="应用信道", style="Secondary.TButton", command=self._apply_channel
        )
        self.btn_channel.pack(side="left", padx=(7, 0), fill="x", expand=True)
        quick = tk.Frame(monitor_card.body, bg=PANEL)
        quick.pack(fill="x", pady=(7, 0))
        for index, channel in enumerate((1, 6, 11, 36, 44, 149)):
            button = ttk.Button(
                quick,
                text=str(channel),
                style="Ghost.TButton",
                width=4,
                command=lambda value=channel: self._quick_channel(value),
            )
            button.pack(side="left", padx=(0 if index == 0 else 5, 0))
        tk.Label(
            monitor_card.body,
            text="2.4 GHz：1–14    ·    5 GHz：36–165",
            bg=PANEL,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        ).pack(fill="x", pady=(7, 0))

        capture_card = Card(inner, padding=10)
        capture_card.pack(fill="x", pady=(0, 8))
        section_header(capture_card.body, "抓包设置", "tcpdump").pack(fill="x", pady=(0, 7))
        segment = tk.Frame(capture_card.body, bg=PANEL_2, highlightbackground=BORDER, highlightthickness=1)
        segment.pack(fill="x")
        for index, (value, label) in enumerate((("manual", "手动停止"), ("count", "按包数"), ("duration", "限时"))):
            radio = ttk.Radiobutton(
                segment,
                text=label,
                value=value,
                variable=self.var_mode,
                style="Mode.TRadiobutton",
                command=self._update_mode_fields,
            )
            radio.grid(row=0, column=index, sticky="ew", padx=(1 if index else 0, 1), pady=1)
            segment.grid_columnconfigure(index, weight=1)

        self.mode_detail = tk.Frame(capture_card.body, bg=PANEL)
        self.mode_detail.pack(fill="x", pady=(7, 2))
        self.count_frame = tk.Frame(self.mode_detail, bg=PANEL)
        tk.Label(self.count_frame, text="抓满包数", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.spin_count = ttk.Spinbox(
            self.count_frame, from_=1, to=10000000, increment=500, textvariable=self.var_count, width=12
        )
        self.spin_count.pack(side="left", padx=(8, 0))
        self.duration_frame = tk.Frame(self.mode_detail, bg=PANEL)
        tk.Label(self.duration_frame, text="抓包时长", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.spin_duration = ttk.Spinbox(
            self.duration_frame, from_=1, to=86400, increment=5, textvariable=self.var_duration, width=8
        )
        self.spin_duration.pack(side="left", padx=(8, 4))
        tk.Label(self.duration_frame, text="秒", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.manual_hint = tk.Label(
            self.mode_detail,
            text="持续抓包，直到点击「停止抓包」",
            bg=PANEL,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        )

        tk.Label(
            capture_card.body,
            text="BPF 过滤（可选）",
            bg=PANEL,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        ).pack(fill="x", pady=(4, 2))
        self.ent_filter = ttk.Entry(capture_card.body, textvariable=self.var_filter)
        self.ent_filter.pack(fill="x", pady=(2, 1))
        tk.Label(
            capture_card.body,
            text="示例：type mgt subtype beacon   /   wlan addr1 00:11:22:33:44:55",
            bg=PANEL,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        ).pack(fill="x", pady=(0, 6))

        options = tk.Frame(capture_card.body, bg=PANEL)
        options.pack(fill="x", pady=(4, 0))
        self.chk_delete = ttk.Checkbutton(
            options,
            text="结束后清理板端文件",
            variable=self.var_delete_remote,
            style="Card.TCheckbutton",
        )
        self.chk_delete.grid(row=0, column=0, sticky="w")
        self.chk_open = ttk.Checkbutton(
            options,
            text="完成后自动打开 Wireshark",
            variable=self.var_open_wireshark,
            style="Card.TCheckbutton",
        )
        self.chk_open.grid(row=0, column=1, sticky="w", padx=(6, 0))
        self.chk_restore = ttk.Checkbutton(
            options,
            text="退出时恢复 wlan0",
            variable=self.var_restore_exit,
            style="Card.TCheckbutton",
        )
        self.chk_restore.grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.chk_stream = ttk.Checkbutton(
            options,
            text="边抓边传到电脑（推荐）",
            variable=self.var_stream_capture,
            style="Card.TCheckbutton",
        )
        self.chk_stream.grid(row=1, column=1, sticky="w", padx=(6, 0), pady=(2, 0))

        bottom = tk.Frame(parent, bg=BG)
        bottom.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        actions = tk.Frame(bottom, bg=BG)
        actions.pack(fill="x")
        self.btn_start = ttk.Button(
            actions, text="开始抓包", style="Accent.TButton", command=self._start_capture
        )
        self.btn_start.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=5)
        self.btn_stop = ttk.Button(
            actions, text="停止抓包", style="Danger.TButton", command=self._stop_capture
        )
        self.btn_stop.pack(side="left", fill="x", expand=True, padx=(5, 0), ipady=5)
        self.lbl_action_hint = tk.Label(
            bottom,
            text="准备就绪",
            bg=BG,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        )
        self.lbl_action_hint.pack(fill="x", pady=(5, 0))
        self._update_mode_fields()

    def _build_right_panel(self, parent: tk.Frame) -> None:
        stats_card = Card(parent, padding=14)
        stats_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        stats_body = stats_card.body
        top = tk.Frame(stats_body, bg=PANEL)
        top.pack(fill="x", pady=(0, 9))
        tk.Label(top, text="当前会话", bg=PANEL, fg=TEXT, font=(FONT, 10, "bold")).pack(side="left")
        self.remote_label = tk.Label(
            top,
            text="/tmp/t113_wifi_capture.pcap",
            bg=PANEL,
            fg=MUTED,
            font=(FONT, 8),
            anchor="e",
        )
        self.remote_label.pack(side="right")
        tiles = tk.Frame(stats_body, bg=PANEL)
        tiles.pack(fill="x")
        self.tile_state = StatTile(tiles, "状态", "空闲", TEXT)
        self.tile_elapsed = StatTile(tiles, "运行时长", "00:00", TEXT_SOFT)
        self.tile_size = StatTile(tiles, "远程数据", "0 B", ACCENT)
        self.tile_packets = StatTile(tiles, "数据包", "--", GREEN)
        for index, tile in enumerate((self.tile_state, self.tile_elapsed, self.tile_size, self.tile_packets)):
            tile.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 8, 0))
            tiles.grid_columnconfigure(index, weight=1)

        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=1, column=0, sticky="nsew")
        self._build_records_tab()
        self._build_packets_tab()
        self._build_log_tab()

    def _build_records_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="抓包记录")
        card = Card(tab, padding=12)
        card.pack(fill="both", expand=True)
        body = card.body
        toolbar = tk.Frame(body, bg=PANEL)
        toolbar.pack(fill="x", pady=(0, 8))
        tk.Label(toolbar, text="输出目录", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.lbl_output_dir = tk.Label(
            toolbar,
            text=self.var_output_dir.get(),
            bg=PANEL,
            fg=TEXT_SOFT,
            font=(FONT, 8),
            anchor="w",
        )
        self.lbl_output_dir.pack(side="left", padx=(8, 10))
        ttk.Button(toolbar, text="选择", style="Ghost.TButton", command=self._choose_output_dir).pack(
            side="right", padx=(6, 0)
        )
        ttk.Button(toolbar, text="打开目录", style="Ghost.TButton", command=self._open_output_dir).pack(
            side="right", padx=(6, 0)
        )
        ttk.Button(toolbar, text="刷新", style="Ghost.TButton", command=lambda: self._scan_output_async()).pack(
            side="right", padx=(6, 0)
        )

        tree_frame, self.tree_records = make_tree(
            body,
            [
                ("name", "文件名", 245, "w", True),
                ("size", "大小", 85, "e", False),
                ("packets", "数据包", 78, "e", False),
                ("duration", "时长", 78, "e", False),
                ("mtime", "抓取时间", 150, "w", False),
            ],
            height=9,
        )
        tree_frame.pack(fill="both", expand=True)
        self.tree_records.bind("<<TreeviewSelect>>", self._on_record_selected)
        self.tree_records.bind("<Double-1>", lambda _event: self._open_selected_record())
        bottom = tk.Frame(body, bg=PANEL)
        bottom.pack(fill="x", pady=(8, 0))
        self.lbl_records_summary = tk.Label(
            bottom, text="尚未扫描抓包文件", bg=PANEL, fg=MUTED, font=(FONT, 8), anchor="w"
        )
        self.lbl_records_summary.pack(side="left", fill="x", expand=True)
        ttk.Button(
            bottom, text="定位文件", style="Ghost.TButton", command=self._reveal_selected_record
        ).pack(side="right", padx=(6, 0))
        ttk.Button(
            bottom, text="Wireshark 打开", style="Secondary.TButton", command=self._open_selected_record
        ).pack(side="right")

    def _build_packets_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="数据包预览")
        card = Card(tab, padding=12)
        card.pack(fill="both", expand=True)
        body = card.body
        toolbar = tk.Frame(body, bg=PANEL)
        toolbar.pack(fill="x", pady=(0, 8))
        tk.Label(toolbar, text="筛选", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(side="left")
        self.ent_search = ttk.Entry(toolbar, textvariable=self.var_search, width=26)
        self.ent_search.pack(side="left", padx=(7, 7))
        self.ent_search.bind("<KeyRelease>", self._on_packet_filter_changed)
        self.cmb_type = ttk.Combobox(
            toolbar,
            textvariable=self.var_type_filter,
            values=["全部", "管理帧", "控制帧", "数据帧", "其他"],
            width=9,
            state="readonly",
        )
        self.cmb_type.pack(side="left")
        self.cmb_type.bind("<<ComboboxSelected>>", self._on_packet_filter_changed)
        ttk.Button(
            toolbar, text="导出 CSV", style="Ghost.TButton", command=self._export_current_csv
        ).pack(side="right")
        ttk.Button(
            toolbar, text="Wireshark 打开", style="Secondary.TButton", command=self._open_current_pcap
        ).pack(side="right", padx=(0, 6))

        tree_frame, self.tree_packets = make_tree(
            body,
            [
                ("number", "#", 55, "e", False),
                ("time", "时间", 95, "w", False),
                ("source", "源地址", 132, "w", False),
                ("destination", "目的地址", 132, "w", False),
                ("protocol", "类型 / 协议", 142, "w", False),
                ("length", "长度", 56, "e", False),
                ("info", "摘要", 300, "w", True),
            ],
            height=11,
        )
        tree_frame.pack(fill="both", expand=True)
        self.tree_packets.tag_configure("mgmt", foreground=AMBER)
        self.tree_packets.tag_configure("ctrl", foreground=BLUE)
        self.tree_packets.tag_configure("data", foreground=GREEN)
        self.tree_packets.tag_configure("other", foreground=MUTED)
        self.tree_packets.bind("<<TreeviewSelect>>", self._on_packet_selected)
        self.tree_packets.bind("<Double-1>", lambda _event: self._open_current_pcap())

        self.lbl_packets_summary = tk.Label(
            body, text="选择左侧抓包记录后可预览数据包", bg=PANEL, fg=MUTED, font=(FONT, 8), anchor="w"
        )
        self.lbl_packets_summary.pack(fill="x", pady=(8, 3))
        detail_frame = tk.Frame(body, bg=PANEL)
        detail_frame.pack(fill="x")
        self.packet_detail = tk.Text(
            detail_frame,
            height=3,
            bg=BG_ALT,
            fg=TEXT_SOFT,
            relief="flat",
            borderwidth=0,
            wrap="word",
            font=("Cascadia Mono", 8),
            padx=9,
            pady=6,
            state="disabled",
        )
        self.packet_detail.pack(fill="x")

    def _build_log_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="运行日志")
        card = Card(tab, padding=12)
        card.pack(fill="both", expand=True)
        body = card.body
        toolbar = tk.Frame(body, bg=PANEL)
        toolbar.pack(fill="x", pady=(0, 8))
        tk.Label(toolbar, text="操作与设备输出", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(side="left")
        ttk.Button(toolbar, text="清空", style="Ghost.TButton", command=self._clear_log).pack(side="right")
        ttk.Button(toolbar, text="保存日志", style="Ghost.TButton", command=self._save_log).pack(
            side="right", padx=(0, 6)
        )
        console_frame, self.log_text = make_console(body, height=13)
        console_frame.pack(fill="both", expand=True)

    def _build_footer(self) -> None:
        footer = tk.Frame(self, bg=BG)
        footer.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 9))
        self.lbl_footer = tk.Label(
            footer,
            text="就绪",
            bg=BG,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        )
        self.lbl_footer.pack(side="left")
        tk.Label(
            footer,
            text="T113 Capture Console  v1.0",
            bg=BG,
            fg="#526986",
            font=(FONT, 8),
            anchor="e",
        ).pack(side="right")

    def _post(self, callback: Callable[..., None], *args: Any, **kwargs: Any) -> None:
        if not self.closing:
            self.ui_queue.put(lambda: callback(*args, **kwargs))

    def _drain_ui_queue(self) -> None:
        try:
            while True:
                callback = self.ui_queue.get_nowait()
                callback()
        except queue.Empty:
            pass
        if not self.closing:
            self.after(70, self._drain_ui_queue)

    def _log(self, message: str, level: str = "info") -> None:
        self._post(self._append_log, message, level)

    def _append_log(self, message: str, level: str) -> None:
        if not hasattr(self, "log_text"):
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", "[{}] ".format(timestamp), "time")
        self.log_text.insert("end", message.rstrip() + "\n", level)
        try:
            line_count = int(self.log_text.index("end-1c").split(".")[0])
            if line_count > 1800:
                self.log_text.delete("1.0", "500.0")
        except tk.TclError:
            pass
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _save_log(self) -> None:
        path = filedialog.asksaveasfilename(
            title="保存运行日志",
            defaultextension=".log",
            filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile="t113_capture_{}.log".format(datetime.now().strftime("%Y%m%d_%H%M%S")),
        )
        if not path:
            return
        try:
            Path(path).write_text(self.log_text.get("1.0", "end-1c"), encoding="utf-8")
            self._log("日志已保存：{}".format(path), "ok")
        except OSError as exc:
            messagebox.showerror("保存失败", str(exc), parent=self)

    def _startup(self) -> None:
        self._log("T113 抓包控制台启动", "accent")
        if not self.adb.available:
            self._log("未找到 adb.exe，请安装 Android Platform Tools 或设置 ADB 环境变量", "error")
            self.lbl_footer.configure(text="ADB 不可用", fg=RED)
        else:
            self._log("ADB：{}".format(self.adb.adb_path))
            self._refresh_devices(True)
        self._scan_output_async()
        self.after(12000, self._watch_devices)

    def _watch_devices(self) -> None:
        if self.closing:
            return
        if self.state == STATE_IDLE and not self.operation_busy and not self.device_refresh_inflight:
            self._refresh_devices(False)
        self.after(12000, self._watch_devices)

    def _refresh_devices(self, manual: bool = True) -> None:
        if self.device_refresh_inflight or self.state != STATE_IDLE:
            return
        self.device_refresh_inflight = True
        if manual:
            self.btn_refresh.configure(state="disabled")
            self.lbl_footer.configure(text="正在扫描 ADB 设备…", fg=MUTED)
        self._log("正在扫描 ADB 设备…") if manual else None

        def worker() -> None:
            try:
                devices = self.adb.devices()
            except Exception as exc:
                self._post(self._on_device_refresh_error, str(exc), manual)
                return
            self._post(self._apply_devices, devices, manual)

        threading.Thread(target=worker, daemon=True, name="adb-devices").start()

    def _on_device_refresh_error(self, message: str, manual: bool) -> None:
        self.device_refresh_inflight = False
        self.btn_refresh.configure(state="normal")
        self._set_header_state("ADB 错误", RED)
        self.lbl_footer.configure(text="ADB 扫描失败", fg=RED)
        if manual:
            self._log("ADB 扫描失败：{}".format(message), "error")
        self._update_controls()

    def _apply_devices(self, devices: List[AdbDevice], manual: bool) -> None:
        self.device_refresh_inflight = False
        self.btn_refresh.configure(state="normal")
        previous = self.selected_serial
        self.devices = devices
        online_devices = [device for device in devices if device.online]
        available_serials = [device.serial for device in devices]
        if previous not in available_serials:
            if online_devices:
                previous = online_devices[0].serial
            elif devices:
                previous = devices[0].serial
            else:
                previous = ""
        self.selected_serial = previous
        self.cmb_device.configure(values=[device.display_name for device in devices])
        selected_index = next((index for index, device in enumerate(devices) if device.serial == previous), -1)
        if selected_index >= 0:
            self.cmb_device.current(selected_index)
            self.var_device.set(devices[selected_index].display_name)
        else:
            self.cmb_device.set("")
            self.var_device.set("")
        selected = self._selected_device()
        if selected and selected.online:
            self._set_header_state("设备在线", GREEN)
            self.lbl_footer.configure(text="{} 已连接".format(selected.serial), fg=GREEN)
            if manual or selected.serial != previous or self.device_info is None or self.device_info.serial != previous:
                self._load_device_info(manual)
        else:
            self._set_header_state("未连接", MUTED)
            self.lbl_footer.configure(text="未发现在线设备" if not devices else "设备离线", fg=AMBER)
            self.monitor_active = False
            self.device_info = None
            self._clear_device_info()
            if manual:
                self._log("未发现在线 ADB 设备", "warn")
        self.settings.serial = self.selected_serial
        self._save_settings_quietly()
        self._update_controls()

    def _selected_device(self) -> Optional[AdbDevice]:
        for device in self.devices:
            if device.serial == self.selected_serial:
                return device
        return None

    def _selected_online(self) -> bool:
        device = self._selected_device()
        return bool(device and device.online)

    def _on_device_selected(self, _event=None) -> None:
        index = self.cmb_device.current()
        if index < 0 or index >= len(self.devices):
            return
        device = self.devices[index]
        self.selected_serial = device.serial
        self.settings.serial = self.selected_serial
        self._save_settings_quietly()
        self.device_info = None
        if device.online:
            self._set_header_state("设备在线", GREEN)
            self._load_device_info(True)
        else:
            self._set_header_state("设备离线", AMBER)
            self.monitor_active = False
            self._clear_device_info()
        self._update_controls()

    def _load_device_info(self, manual: bool = True) -> None:
        serial = self.selected_serial
        if not serial:
            return
        if manual:
            for label in self.device_values.values():
                label.configure(text="读取中…")
        self.lbl_footer.configure(text="正在读取设备信息…", fg=MUTED)

        def worker() -> None:
            try:
                info = self.controller.get_device_info(serial)
            except Exception as exc:
                self._post(self._on_device_info_error, serial, str(exc), manual)
                return
            self._post(self._apply_device_info, info, manual)

        threading.Thread(target=worker, daemon=True, name="device-info").start()

    def _on_device_info_error(self, serial: str, message: str, manual: bool) -> None:
        if serial != self.selected_serial:
            return
        self._clear_device_info()
        self.monitor_active = False
        self.lbl_footer.configure(text="读取设备信息失败", fg=RED)
        if manual:
            self._log("读取设备信息失败：{}".format(message), "error")
        self._update_controls()

    def _clear_device_info(self) -> None:
        for label in self.device_values.values():
            label.configure(text="--")

    def _apply_device_info(self, info: DeviceInfo, manual: bool) -> None:
        if info.serial != self.selected_serial:
            return
        old_monitor = self.monitor_active
        old_channel = self.device_info.channel if self.device_info else None
        self.device_info = info
        self.monitor_active = info.monitor_active
        self.device_values["model"].configure(text=info.model or "未知")
        self.device_values["os"].configure(text=truncate_middle(info.os_name or "未知", 30))
        self.device_values["kernel"].configure(text=info.kernel or "未知")
        self.device_values["privilege"].configure(text="root" if info.root else "普通用户", fg=GREEN if info.root else AMBER)
        if info.monitor_active:
            monitor_text = "mon1 · 监听中"
            if info.channel:
                monitor_text += " · CH {}".format(info.channel)
            self.device_values["monitor"].configure(text=monitor_text, fg=ACCENT)
            if info.channel:
                self.var_channel.set(str(info.channel))
        else:
            self.device_values["monitor"].configure(text="未启用", fg=MUTED)
        self.lbl_footer.configure(text="{} · {} · {}".format(info.serial, info.os_name, info.model), fg=MUTED)
        if manual or old_monitor != info.monitor_active or old_channel != info.channel:
            if info.monitor_active:
                self._log("监听接口 mon1 已就绪，当前信道 {}".format(info.channel or "--"), "ok")
            elif manual:
                self._log("设备在线；监听模式尚未启用", "info")
        self._update_controls()

    def _set_header_state(self, text: str, color: str) -> None:
        self.lbl_header_state.configure(text=text, fg=color)
        self.header_dot.itemconfigure(self.header_dot_id, fill=color)

    def _update_mode_fields(self) -> None:
        mode = self.var_mode.get()
        self.count_frame.pack_forget()
        self.duration_frame.pack_forget()
        self.manual_hint.pack_forget()
        if mode == "count":
            self.count_frame.pack(anchor="w")
        elif mode == "duration":
            self.duration_frame.pack(anchor="w")
        else:
            self.manual_hint.pack(fill="x")

    def _quick_channel(self, channel: int) -> None:
        self.var_channel.set(str(channel))
        self._apply_channel()

    def _update_controls(self) -> None:
        online = self._selected_online()
        busy = self.operation_busy or self.state in (STATE_STARTING, STATE_STOPPING, STATE_PROCESSING)
        capturing = self.state == STATE_CAPTURING
        config_state = "disabled" if busy or capturing else "normal"
        self.btn_init.configure(state="normal" if online and not busy and not capturing else "disabled")
        self.btn_restore.configure(state="normal" if online and not busy and not capturing else "disabled")
        self.btn_start.configure(state="normal" if online and not busy and not capturing else "disabled")
        self.btn_stop.configure(state="normal" if capturing and not busy else "disabled")
        self.cmb_device.configure(state="disabled" if capturing or busy else "readonly")
        self.btn_refresh.configure(state="disabled" if capturing or busy else "normal")
        self.cmb_channel.configure(state=config_state)
        self.btn_channel.configure(state=config_state)
        for widget in (self.spin_count, self.spin_duration, self.ent_filter):
            widget.configure(state=config_state)
        for widget in (self.chk_delete, self.chk_open, self.chk_restore, self.chk_stream):
            widget.configure(state=config_state)

    def _set_session_state(self, title: str, color: str, hint: str = "") -> None:
        self.tile_state.set(title, color)
        if hint:
            self.lbl_action_hint.configure(text=hint, fg=color if color != TEXT else MUTED)

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        seconds = max(0, int(seconds))
        hours, remain = divmod(seconds, 3600)
        minutes, secs = divmod(remain, 60)
        if hours:
            return "{}:{:02d}:{:02d}".format(hours, minutes, secs)
        return "{:02d}:{:02d}".format(minutes, secs)

    def _parse_channel(self) -> Optional[int]:
        try:
            channel = int(self.var_channel.get().strip())
        except ValueError:
            messagebox.showwarning("信道无效", "请输入 1–196 之间的信道号。", parent=self)
            return None
        if not 1 <= channel <= 196:
            messagebox.showwarning("信道无效", "信道必须在 1–196 之间。", parent=self)
            return None
        return channel

    def _read_capture_config(self) -> Optional[CaptureConfig]:
        channel = self._parse_channel()
        if channel is None:
            return None
        mode = self.var_mode.get()
        try:
            packet_count = int(self.var_count.get().strip())
            duration = int(self.var_duration.get().strip())
        except ValueError:
            messagebox.showwarning("参数无效", "抓包包数和时长必须是整数。", parent=self)
            return None
        config = CaptureConfig(
            channel=channel,
            mode=mode,
            packet_count=packet_count,
            duration_sec=duration,
            bpf_filter=self.var_filter.get().strip(),
        )
        try:
            config.validate()
        except ValueError as exc:
            messagebox.showwarning("参数无效", str(exc), parent=self)
            return None
        return config

    def _initialize_monitor(self) -> None:
        if not self._selected_online():
            messagebox.showwarning("未连接设备", "请先选择一台在线 ADB 设备。", parent=self)
            return
        if self.operation_busy or self.state != STATE_IDLE:
            return
        channel = self._parse_channel()
        if channel is None:
            return
        serial = self.selected_serial
        self.operation_busy = True
        self._set_session_state("初始化", ACCENT, "正在创建 mon1 监听接口…")
        self._update_controls()
        self._log("开始初始化监听接口 mon1（会暂时关闭 wlan0）", "accent")

        def worker() -> None:
            try:
                self._log("正在执行监听模式初始化脚本…")
                self.controller.prepare_monitor(serial)
                self._log("监听接口已创建，设置信道 {}…".format(channel))
                self.controller.set_channel(serial, channel)
                info = self.controller.get_device_info(serial)
            except Exception as exc:
                self._post(self._on_monitor_error, "初始化监听", str(exc))
                return
            self._post(self._on_monitor_ready, info, channel)

        threading.Thread(target=worker, daemon=True, name="monitor-init").start()

    def _on_monitor_ready(self, info: DeviceInfo, channel: int) -> None:
        self.operation_busy = False
        self.state = STATE_IDLE
        self._apply_device_info(info, False)
        self.var_channel.set(str(channel))
        self._set_session_state("空闲", TEXT, "监听已就绪，可以开始抓包")
        self._log("监听模式初始化完成，mon1 信道 {}".format(channel), "ok")
        self._set_header_state("监听就绪", ACCENT)
        self._update_controls()

    def _on_monitor_error(self, action: str, message: str) -> None:
        self.operation_busy = False
        self.state = STATE_IDLE
        self._set_session_state("空闲", TEXT, "{}失败".format(action))
        self._log("{}失败：{}".format(action, message), "error")
        self._update_controls()
        messagebox.showerror("{}失败".format(action), message, parent=self)

    def _apply_channel(self) -> None:
        if not self._selected_online():
            messagebox.showwarning("未连接设备", "请先选择一台在线 ADB 设备。", parent=self)
            return
        if self.operation_busy or self.state != STATE_IDLE:
            return
        channel = self._parse_channel()
        if channel is None:
            return
        serial = self.selected_serial
        need_init = not self.monitor_active
        self.operation_busy = True
        self._set_session_state("配置中", ACCENT, "正在设置监听信道…")
        self._update_controls()
        self._log("正在切换 mon1 到信道 {}…".format(channel))

        def worker() -> None:
            try:
                if need_init:
                    self.controller.prepare_monitor(serial)
                self.controller.set_channel(serial, channel)
                info = self.controller.get_device_info(serial)
            except Exception as exc:
                self._post(self._on_monitor_error, "设置信道", str(exc))
                return
            self._post(self._on_monitor_ready, info, channel)

        threading.Thread(target=worker, daemon=True, name="channel-set").start()

    def _restore_device(self) -> None:
        if not self._selected_online():
            messagebox.showwarning("未连接设备", "请先选择一台在线 ADB 设备。", parent=self)
            return
        if self.operation_busy or self.state != STATE_IDLE:
            return
        if not messagebox.askyesno(
            "恢复设备",
            "将删除 mon1 监听接口并重新启用 wlan0。\n确定继续吗？",
            parent=self,
        ):
            return
        serial = self.selected_serial
        self.operation_busy = True
        self._set_session_state("恢复中", AMBER, "正在恢复普通无线网卡…")
        self._update_controls()
        self._log("正在删除 mon1 并恢复 wlan0…", "warn")

        def worker() -> None:
            try:
                self.controller.restore_device(serial)
                info = self.controller.get_device_info(serial)
            except Exception as exc:
                self._post(self._on_monitor_error, "恢复设备", str(exc))
                return
            self._post(self._on_device_restored, info)

        threading.Thread(target=worker, daemon=True, name="device-restore").start()

    def _on_device_restored(self, info: DeviceInfo) -> None:
        self.operation_busy = False
        self.state = STATE_IDLE
        self.monitor_active = False
        self._apply_device_info(info, False)
        self._set_session_state("空闲", TEXT, "设备已恢复为普通网卡")
        self._set_header_state("设备在线", GREEN)
        self._log("设备已恢复，wlan0 已重新启用", "ok")
        self._update_controls()

    def _start_capture(self) -> None:
        if not self._selected_online():
            messagebox.showwarning("未连接设备", "请先选择一台在线 ADB 设备。", parent=self)
            return
        if self.operation_busy or self.state != STATE_IDLE:
            return
        config = self._read_capture_config()
        if config is None:
            return
        try:
            Path(self.var_output_dir.get()).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("输出目录不可用", str(exc), parent=self)
            return
        serial = self.selected_serial
        need_init = not self.monitor_active
        stream_capture = bool(self.var_stream_capture.get())
        self.capture_started_wall = datetime.now()
        local_path = self._next_local_path(config) if stream_capture else None
        self.capture_config = config
        self.capture_local_path = local_path
        self.operation_busy = True
        self.state = STATE_STARTING
        self.poll_token += 1
        self._set_session_state("启动中", ACCENT, "正在启动 tcpdump…")
        self.tile_elapsed.set("00:00")
        self.tile_size.set("0 B")
        self.tile_packets.set("--")
        self._update_controls()
        mode_text = {"manual": "手动停止", "count": "{} 包".format(config.packet_count), "duration": "{} 秒".format(config.duration_sec)}[config.mode]
        self._log(
            "开始抓包：mon1 · CH {} · {} · 过滤={}".format(config.channel, mode_text, config.bpf_filter or "无"),
            "accent",
        )

        def worker() -> None:
            try:
                if need_init:
                    self._log("监听接口未启用，先自动初始化…")
                    self.controller.prepare_monitor(serial)
                self.controller.set_channel(serial, config.channel)
                if stream_capture:
                    self.controller.cleanup_remote(serial)
                    session = self.controller.start_stream_capture(serial, config, str(local_path))
                    pid = None
                else:
                    session = None
                    pid = self.controller.start_capture(serial, config)
            except Exception as exc:
                self._post(self._on_capture_start_error, str(exc))
                return
            self._post(self._on_capture_started, pid, config, session)

        threading.Thread(target=worker, daemon=True, name="capture-start").start()

    def _on_capture_start_error(self, message: str) -> None:
        self.operation_busy = False
        self.state = STATE_IDLE
        self.capture_config = None
        self.stream_session = None
        self.capture_local_path = None
        self._set_session_state("失败", RED, "抓包启动失败")
        self._log("抓包启动失败：{}".format(message), "error")
        self._update_controls()
        messagebox.showerror("抓包启动失败", message, parent=self)

    def _on_capture_started(
        self, pid: Optional[int], config: CaptureConfig, session: Optional[StreamCaptureSession]
    ) -> None:
        self.operation_busy = False
        self.state = STATE_CAPTURING
        self.monitor_active = True
        self.capture_config = config
        self.stream_session = session
        self.capture_started_monotonic = time.monotonic()
        self.capture_started_wall = datetime.now()
        self.remote_size = 0
        self.last_log_tail = ""
        self.remote_label.configure(
            text=str(self.capture_local_path) if session and self.capture_local_path else "/tmp/t113_wifi_capture.pcap"
        )
        self.poll_token += 1
        token = self.poll_token
        mode_hint = "PCAP 正在实时写入电脑" if session else "tcpdump 正在板端运行，PID {}".format(pid)
        self._set_session_state("抓包中", GREEN, mode_hint)
        self.tile_elapsed.set("00:00")
        self.tile_size.set("0 B")
        self.tile_packets.set("--")
        self._set_header_state("抓包中", GREEN)
        if session:
            self._log("已开启边抓边传，PCAP 实时写入 {}".format(self.capture_local_path), "ok")
        else:
            self._log("tcpdump 已启动，PID={}，远端文件 /tmp/t113_wifi_capture.pcap".format(pid), "ok")
        self.settings.serial = self.selected_serial
        self._save_settings_quietly()
        self._update_controls()
        self.after(900, lambda: self._poll_capture(token))

    def _poll_capture(self, token: int) -> None:
        if token != self.poll_token or self.state != STATE_CAPTURING or self.closing:
            return
        if self.poll_inflight:
            self.after(900, lambda: self._poll_capture(token))
            return
        self.poll_inflight = True
        serial = self.selected_serial

        def worker() -> None:
            try:
                if self.stream_session is not None:
                    status = self.stream_session.status()
                else:
                    status = self.controller.remote_status(serial)
            except Exception as exc:
                self._post(self._on_capture_poll_error, token, str(exc))
                return
            self._post(self._on_capture_poll, token, status)

        threading.Thread(target=worker, daemon=True, name="capture-poll").start()

    def _on_capture_poll(self, token: int, status: CaptureStatus) -> None:
        self.poll_inflight = False
        if token != self.poll_token or self.state != STATE_CAPTURING:
            return
        self.remote_size = status.size
        elapsed = time.monotonic() - self.capture_started_monotonic
        self.tile_elapsed.set(self._format_elapsed(elapsed))
        self.tile_size.set(format_bytes(status.size))
        if status.alive:
            self.after(1000, lambda: self._poll_capture(token))
            return
        if status.log_tail and status.log_tail != self.last_log_tail:
            self.last_log_tail = status.log_tail
            self._log("tcpdump 输出：{}".format(status.log_tail))
        self._log(
            "实时传输已结束，准备解析本地 PCAP" if self.stream_session else "tcpdump 已结束，准备拉取抓包文件",
            "ok",
        )
        self._finish_capture_async("抓包已结束")

    def _on_capture_poll_error(self, token: int, message: str) -> None:
        self.poll_inflight = False
        if token != self.poll_token or self.state != STATE_CAPTURING:
            return
        self._log("读取抓包状态失败：{}".format(message), "warn")
        self.after(1800, lambda: self._poll_capture(token))

    def _stop_capture(self) -> None:
        if self.state != STATE_CAPTURING:
            return
        serial = self.selected_serial
        self.state = STATE_STOPPING
        self.poll_token += 1
        self.operation_busy = False
        self._set_session_state("停止中", AMBER, "正在向 tcpdump 发送 SIGINT…")
        self._update_controls()
        self._log("正在停止抓包（SIGINT，确保缓冲区写入文件）…", "warn")

        def worker() -> None:
            try:
                if self.stream_session is not None:
                    self.controller.stop_stream_capture(serial, self.stream_session)
                else:
                    self.controller.stop_capture(serial)
            except Exception as exc:
                self._post(self._log, "停止命令返回异常：{}".format(exc), "warn")
            self._post(self._finish_capture_async, "手动停止")

        threading.Thread(target=worker, daemon=True, name="capture-stop").start()

    def _next_local_path(self, config: CaptureConfig) -> Path:
        output = Path(self.var_output_dir.get())
        output.mkdir(parents=True, exist_ok=True)
        stamp = (self.capture_started_wall or datetime.now()).strftime("%Y%m%d_%H%M%S")
        mode_suffix = {
            "manual": "manual",
            "count": "{}p".format(config.packet_count),
            "duration": "{}s".format(config.duration_sec),
        }.get(config.mode, config.mode)
        base = "t113_{}_ch{}_{}".format(stamp, config.channel, mode_suffix)
        candidate = output / (base + ".pcap")
        index = 2
        while candidate.exists():
            candidate = output / "{}_{}.pcap".format(base, index)
            index += 1
        return candidate

    def _finish_capture_async(self, reason: str) -> None:
        if self.finishing:
            return
        self.finishing = True
        self.state = STATE_PROCESSING
        self._set_session_state("处理中", ACCENT, "正在拉取并解析抓包文件…")
        self._update_controls()
        config = self.capture_config or CaptureConfig(channel=int(self.var_channel.get() or 6))
        serial = self.selected_serial
        stream_session = self.stream_session
        delete_remote = bool(self.var_delete_remote.get())
        local_path = self.capture_local_path or self._next_local_path(config)
        if stream_session:
            self._log("{}，正在整理本地实时 PCAP…".format(reason), "accent")
        else:
            self._log("{}，正在拉取抓包数据…".format(reason), "accent")

        def worker() -> None:
            try:
                if stream_session is not None:
                    stream_session.wait(15)
                    stream_session.stop(grace_timeout=2.0)
                    status = stream_session.status()
                    if status.size < 24:
                        message = stream_session.error or stream_session.stderr_text or "没有捕获到有效数据"
                        self._post(
                            self._on_capture_finished,
                            {"ok": False, "message": "实时传输失败：{}".format(message), "remote_size": status.size},
                            reason,
                            config,
                        )
                        return
                    trimmed = trim_incomplete_pcap_tail(local_path)
                    if trimmed:
                        self._log("已移除流式传输末尾未写完的 {} 字节记录，文件可正常打开".format(trimmed), "warn")
                    try:
                        self.controller.cleanup_remote(serial)
                    except Exception as exc:
                        self._log("清理板端流式状态失败：{}".format(exc), "warn")
                    summary = read_pcap(local_path, detail_limit=10000)
                    self._post(
                        self._on_capture_finished,
                        {
                            "ok": True,
                            "path": local_path,
                            "summary": summary,
                            "remote_size": summary.file_size,
                            "deleted": False,
                            "streamed": True,
                        },
                        reason,
                        config,
                    )
                    return
                status = self.controller.remote_status(serial)
                if status.alive:
                    self.controller.stop_capture(serial)
                    status = self.controller.remote_status(serial)
                if status.size < 24:
                    self._post(
                        self._on_capture_finished,
                        {"ok": False, "message": "没有捕获到有效数据（板端文件为空或不存在）", "remote_size": status.size},
                        reason,
                        config,
                    )
                    return
                self._log("ADB pull /tmp/t113_wifi_capture.pcap → {}".format(local_path))
                self.controller.pull_capture(serial, str(local_path), timeout=900)
                deleted = False
                if delete_remote:
                    try:
                        self.controller.cleanup_remote(serial)
                        deleted = True
                    except Exception as exc:
                        self._log("删除板端文件失败：{}".format(exc), "warn")
                summary = read_pcap(local_path, detail_limit=10000)
            except Exception as exc:
                self._post(self._on_capture_finished, {"ok": False, "message": str(exc)}, reason, config)
                return
            self._post(
                self._on_capture_finished,
                {
                    "ok": True,
                    "path": local_path,
                    "summary": summary,
                    "remote_size": summary.file_size,
                    "deleted": deleted,
                },
                reason,
                config,
            )

        threading.Thread(target=worker, daemon=True, name="capture-finish").start()

    def _on_capture_finished(self, result: Dict[str, Any], reason: str, config: CaptureConfig) -> None:
        self.finishing = False
        self.operation_busy = False
        self.state = STATE_IDLE
        self.capture_config = None
        self.stream_session = None
        self.capture_local_path = None
        self._update_controls()
        if not result.get("ok"):
            self._set_session_state("未完成", AMBER, reason)
            self._set_header_state("设备在线", GREEN)
            self.tile_packets.set("0", AMBER)
            self._log(result.get("message", "抓包处理失败"), "error")
            self.lbl_footer.configure(text="抓包未产生有效数据", fg=AMBER)
            return
        summary: PcapSummary = result["summary"]
        local_path: Path = result["path"]
        self.summary_cache[str(local_path)] = summary
        self.current_summary = summary
        self.tile_elapsed.set(format_duration(summary.duration))
        self.tile_size.set(format_bytes(summary.file_size))
        self.tile_packets.set(str(summary.packet_count), GREEN)
        self._set_session_state("完成", GREEN, "抓包文件已保存到电脑")
        self._set_header_state("设备在线", GREEN)
        self.remote_label.configure(text=str(local_path))
        self._log(
            "抓包完成：{} 包，{}，{}".format(
                summary.packet_count, format_bytes(summary.file_size), format_duration(summary.duration)
            ),
            "ok",
        )
        category_text = " / ".join(
            "{} {}".format(name, count) for name, count in sorted(summary.categories.items())
        )
        if category_text:
            self._log("帧统计：{}".format(category_text))
        if summary.ssids:
            self._log("发现 SSID：{}".format("、".join(summary.ssids[:10])))
        if summary.file_truncated:
            self._log("PCAP 末尾记录不完整，已解析到最后一个完整数据包", "warn")
        if result.get("deleted"):
            self._log("板端临时文件已清理")
        self.lbl_footer.configure(text="已保存：{}".format(local_path), fg=GREEN)
        self._show_summary(summary)
        self._scan_output_async(select_path=str(local_path))
        if self.var_open_wireshark.get():
            self.after(350, lambda: self._open_in_wireshark(str(local_path)))

    def _output_path(self) -> Path:
        return Path(self.var_output_dir.get()).expanduser()

    def _choose_output_dir(self) -> None:
        selected = filedialog.askdirectory(
            title="选择抓包文件保存目录",
            initialdir=str(self._output_path()),
            parent=self,
        )
        if not selected:
            return
        self.var_output_dir.set(selected)
        self.lbl_output_dir.configure(text=selected)
        self.settings.output_dir = selected
        self._save_settings_quietly()
        self._log("输出目录已切换：{}".format(selected))
        self._scan_output_async()

    def _open_output_dir(self) -> None:
        output = self._output_path()
        try:
            output.mkdir(parents=True, exist_ok=True)
            open_path(str(output))
        except OSError as exc:
            messagebox.showerror("无法打开目录", str(exc), parent=self)

    def _scan_output_async(self, select_path: Optional[str] = None, quiet: bool = False) -> None:
        if self.scan_inflight:
            if select_path:
                self.pending_select_path = select_path
            return
        self.scan_inflight = True
        output = self._output_path()
        if not quiet:
            self.lbl_records_summary.configure(text="正在扫描输出目录…", fg=MUTED)

        def worker() -> None:
            metas: List[PcapMeta] = []
            try:
                output.mkdir(parents=True, exist_ok=True)
                paths = sorted(
                    [path for path in output.iterdir() if path.is_file() and path.suffix.lower() in (".pcap", ".pcapng")],
                    key=lambda path: path.stat().st_mtime,
                    reverse=True,
                )[:200]
                for path in paths:
                    try:
                        metas.append(scan_pcap(path))
                    except OSError:
                        continue
            except Exception as exc:
                self._post(self._on_scan_error, str(exc), quiet)
                return
            self._post(self._apply_capture_scan, metas, select_path, quiet)

        threading.Thread(target=worker, daemon=True, name="scan-captures").start()

    def _on_scan_error(self, message: str, quiet: bool) -> None:
        self.scan_inflight = False
        self.lbl_records_summary.configure(text="扫描输出目录失败", fg=RED)
        if not quiet:
            self._log("扫描输出目录失败：{}".format(message), "error")

    def _apply_capture_scan(self, metas: List[PcapMeta], select_path: Optional[str], quiet: bool) -> None:
        self.scan_inflight = False
        clear_tree(self.tree_records)
        self.record_meta.clear()
        self.record_paths.clear()
        total_size = 0
        selection_iid = ""
        desired = select_path or getattr(self, "pending_select_path", None)
        self.pending_select_path = None
        for index, meta in enumerate(metas):
            iid = str(index)
            path_string = str(meta.path)
            self.record_meta[iid] = meta
            self.record_paths[iid] = path_string
            total_size += meta.file_size
            packets = str(meta.packet_count) if meta.supported else "—"
            self.tree_records.insert(
                "",
                "end",
                iid=iid,
                values=(
                    meta.path.name,
                    format_bytes(meta.file_size),
                    packets,
                    format_duration(meta.duration),
                    format_mtime(meta.path.stat().st_mtime),
                ),
            )
            if desired and Path(path_string) == Path(desired):
                selection_iid = iid
        if metas:
            self.lbl_records_summary.configure(
                text="{} 个抓包文件 · 共 {} · {}".format(len(metas), format_bytes(total_size), self._output_path()),
                fg=MUTED,
            )
        else:
            self.lbl_records_summary.configure(text="输出目录中没有 PCAP 文件", fg=MUTED)
        if selection_iid:
            self.tree_records.selection_set(selection_iid)
            self.tree_records.focus(selection_iid)
            self.tree_records.see(selection_iid)
        if not quiet:
            self._log("抓包记录已刷新：{} 个文件".format(len(metas)))

    def _selected_record_path(self) -> Optional[str]:
        selection = self.tree_records.selection()
        if not selection:
            return None
        return self.record_paths.get(selection[0])

    def _on_record_selected(self, _event=None) -> None:
        path = self._selected_record_path()
        if path:
            self._load_summary_async(path)

    def _load_summary_async(self, path: str, force: bool = False) -> None:
        if not force and path in self.summary_cache:
            self._show_summary(self.summary_cache[path])
            return
        if self.summary_inflight_path == path:
            return
        self.summary_inflight_path = path
        self.lbl_packets_summary.configure(text="正在解析 {}…".format(Path(path).name), fg=MUTED)

        def worker() -> None:
            try:
                summary = read_pcap(Path(path), detail_limit=10000)
            except Exception as exc:
                self._post(self._on_summary_error, path, str(exc))
                return
            self._post(self._apply_loaded_summary, summary)

        threading.Thread(target=worker, daemon=True, name="parse-capture").start()

    def _on_summary_error(self, path: str, message: str) -> None:
        if self.summary_inflight_path == path:
            self.summary_inflight_path = None
        self.lbl_packets_summary.configure(text="解析抓包文件失败", fg=RED)
        self._log("解析 {} 失败：{}".format(Path(path).name, message), "error")

    def _apply_loaded_summary(self, summary: PcapSummary) -> None:
        self.summary_inflight_path = None
        self.summary_cache[str(summary.path)] = summary
        self._show_summary(summary)

    def _show_summary(self, summary: PcapSummary) -> None:
        self.current_summary = summary
        self.summary_cache[str(summary.path)] = summary
        self._populate_packets()

    def _on_packet_filter_changed(self, _event=None) -> None:
        self._populate_packets()

    def _populate_packets(self) -> None:
        clear_tree(self.tree_packets)
        self.packet_by_iid.clear()
        summary = self.current_summary
        if summary is None:
            self.lbl_packets_summary.configure(text="选择抓包记录后可预览数据包", fg=MUTED)
            return
        search = self.var_search.get().strip().lower()
        category_filter = self.var_type_filter.get()
        shown = 0
        insert_limit = 5000
        for packet in summary.packets:
            if category_filter != "全部" and packet.category != category_filter:
                continue
            haystack = "{} {} {} {} {} {}".format(
                packet.number,
                packet.source,
                packet.destination,
                packet.bssid,
                packet.protocol,
                packet.info,
            ).lower()
            if search and search not in haystack:
                continue
            if shown >= insert_limit:
                break
            tag = {"管理帧": "mgmt", "控制帧": "ctrl", "数据帧": "data"}.get(packet.category, "other")
            iid = str(packet.number)
            self.tree_packets.insert(
                "",
                "end",
                iid=iid,
                tags=(tag,),
                values=(
                    packet.number,
                    packet.time_text,
                    packet.source or "—",
                    packet.destination or "—",
                    "{} · {}".format(packet.category, packet.protocol),
                    packet.length,
                    packet.info or "—",
                ),
            )
            self.packet_by_iid[iid] = packet
            shown += 1
        category_text = " / ".join(
            "{} {}".format(name, count) for name, count in sorted(summary.categories.items())
        )
        suffix = " · 仅显示前 {} 包".format(insert_limit) if len(summary.packets) > insert_limit else ""
        self.lbl_packets_summary.configure(
            text="{} · 显示 {}/{} 包 · {} · {}{}".format(
                summary.path.name,
                shown,
                summary.packet_count,
                format_duration(summary.duration),
                category_text or summary.link_name,
                suffix,
            ),
            fg=TEXT_SOFT,
        )
        if summary.details_truncated:
            self._log(
                "{} 数据包较多，界面仅解析前 {} 包；Wireshark 可查看完整内容".format(
                    summary.path.name, len(summary.packets)
                ),
                "warn",
            )

    def _on_packet_selected(self, _event=None) -> None:
        selection = self.tree_packets.selection()
        if not selection:
            return
        packet = self.packet_by_iid.get(selection[0])
        if packet is None:
            return
        lines = [
            "#{}  {}  {} bytes  {}".format(packet.number, packet.time_text, packet.length, packet.category),
            "{}  ·  {}".format(packet.protocol, packet.info or "无附加信息"),
            "源 {}  →  目的 {}    BSSID {}".format(
                packet.source or "—", packet.destination or "—", packet.bssid or "—"
            ),
        ]
        set_text(self.packet_detail, "\n".join(lines))

    def _open_selected_record(self) -> None:
        path = self._selected_record_path()
        if not path:
            messagebox.showinfo("未选择文件", "请先在抓包记录中选择一个文件。", parent=self)
            return
        self._open_in_wireshark(path)

    def _reveal_selected_record(self) -> None:
        path = self._selected_record_path()
        if not path:
            self._open_output_dir()
            return
        try:
            open_path(str(Path(path).parent))
        except OSError as exc:
            messagebox.showerror("无法打开目录", str(exc), parent=self)

    def _open_current_pcap(self) -> None:
        path = self._selected_record_path()
        if not path and self.current_summary is not None:
            path = str(self.current_summary.path)
        if not path:
            messagebox.showinfo("未选择文件", "请先选择一个抓包文件。", parent=self)
            return
        self._open_in_wireshark(path)

    def _open_in_wireshark(self, path: str) -> None:
        if not Path(path).is_file():
            messagebox.showerror("文件不存在", path, parent=self)
            return
        if open_wireshark(path):
            self._log("已使用 Wireshark 打开：{}".format(path), "ok")
        else:
            messagebox.showerror(
                "未找到 Wireshark",
                "未检测到 Wireshark，请先安装 Wireshark，或将 PCAP 文件手动拖入 Wireshark。",
                parent=self,
            )

    def _export_current_csv(self) -> None:
        if self.current_summary is None:
            messagebox.showinfo("没有数据", "请先选择并解析一个抓包文件。", parent=self)
            return
        default_name = self.current_summary.path.with_suffix(".csv").name
        path = filedialog.asksaveasfilename(
            title="导出数据包摘要 CSV",
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=default_name,
            initialdir=str(self.current_summary.path.parent),
            parent=self,
        )
        if not path:
            return
        try:
            export_packets_csv(self.current_summary, Path(path))
            self._log("CSV 已导出：{}".format(path), "ok")
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc), parent=self)

    def _save_settings_quietly(self) -> None:
        try:
            self.settings.channel = int(self.var_channel.get())
        except (ValueError, tk.TclError):
            pass
        try:
            self.settings.packet_count = int(self.var_count.get())
            self.settings.duration_sec = int(self.var_duration.get())
        except (ValueError, tk.TclError):
            pass
        self.settings.mode = self.var_mode.get()
        self.settings.bpf_filter = self.var_filter.get()
        self.settings.output_dir = self.var_output_dir.get()
        self.settings.delete_remote = bool(self.var_delete_remote.get())
        self.settings.open_wireshark = bool(self.var_open_wireshark.get())
        self.settings.restore_on_exit = bool(self.var_restore_exit.get())
        self.settings.stream_capture = bool(self.var_stream_capture.get())
        self.settings.serial = self.selected_serial
        try:
            save_settings(self.settings)
        except OSError:
            pass

    def _on_close(self) -> None:
        if self.closing:
            return
        if self.operation_busy or self.state in (STATE_STARTING, STATE_STOPPING, STATE_PROCESSING):
            messagebox.showinfo("请稍候", "当前操作尚未完成，请等待操作结束后再关闭。", parent=self)
            return
        if self.state == STATE_CAPTURING:
            if not messagebox.askyesno(
                "抓包进行中",
                "退出前会停止抓包、拉取已捕获的数据，并恢复设备。\n确定退出吗？",
                parent=self,
            ):
                return
        self._save_settings_quietly()
        if self.state == STATE_CAPTURING:
            self.state = STATE_STOPPING
            self.poll_token += 1
        serial = self.selected_serial
        needs_shutdown = self.state == STATE_STOPPING or bool(
            serial and self.var_restore_exit.get() and self.monitor_active
        )
        if not needs_shutdown:
            self.closing = True
            self.destroy()
            return
        self.operation_busy = True
        self._update_controls()
        self.lbl_footer.configure(text="正在停止抓包并恢复设备，请稍候…", fg=AMBER)
        self._set_session_state("退出中", AMBER, "正在保存数据并恢复 wlan0…")
        self._shutdown_async(serial)

    def _shutdown_async(self, serial: str) -> None:
        config = self.capture_config or CaptureConfig(channel=int(self.var_channel.get() or 6))
        should_pull = self.state == STATE_STOPPING
        should_restore = bool(self.var_restore_exit.get() and self.monitor_active)
        delete_remote = bool(self.var_delete_remote.get())
        stream_session = self.stream_session
        local_path = self.capture_local_path or (self._next_local_path(config) if should_pull else None)

        def worker() -> None:
            messages: List[str] = []
            try:
                if stream_session is not None:
                    self.controller.stop_stream_capture(serial, stream_session)
                    stream_session.wait(5)
                    if local_path is not None and stream_session.size >= 24:
                        trimmed = trim_incomplete_pcap_tail(local_path)
                        if trimmed:
                            messages.append("退出前已移除末尾未写完的 {} 字节".format(trimmed))
                        messages.append("退出前已保存实时抓包：{}".format(local_path))
                else:
                    status = self.controller.remote_status(serial)
                    if status.alive:
                        self.controller.stop_capture(serial)
                        status = self.controller.remote_status(serial)
                    if should_pull and status.size >= 24 and local_path is not None:
                        self.controller.pull_capture(serial, str(local_path), timeout=900)
                        messages.append("退出前已保存抓包：{}".format(local_path))
                        if delete_remote:
                            try:
                                self.controller.cleanup_remote(serial)
                            except Exception:
                                pass
                if should_restore:
                    self.controller.restore_device(serial)
                    messages.append("已恢复 wlan0 并删除 mon1")
            except Exception as exc:
                messages.append("退出清理异常：{}".format(exc))
            self._post(self._finalize_close, messages)

        threading.Thread(target=worker, daemon=True, name="shutdown").start()

    def _finalize_close(self, messages: List[str]) -> None:
        for message in messages:
            level = "warn" if "异常" in message else "ok"
            self._append_log(message, level)
        self.closing = True
        self.destroy()
