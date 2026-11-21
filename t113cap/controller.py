from __future__ import annotations

import re
import base64
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .adb import AdbClient, AdbError, CommandResult


INTERFACE = "mon1"
REMOTE_PCAP = "/tmp/t113_wifi_capture.pcap"
REMOTE_PID = "/tmp/t113_wifi_capture.pid"
REMOTE_LOG = "/tmp/t113_wifi_capture.log"
REMOTE_CAPTURE_SCRIPT = "/tmp/t113cap_tcpdump.sh"
REMOTE_STREAM_PID = "/tmp/t113_wifi_stream.pid"
REMOTE_STREAM_LOG = "/tmp/t113_wifi_stream.log"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class CaptureConfig:
    channel: int = 6
    mode: str = "manual"
    packet_count: int = 5000
    duration_sec: int = 30
    bpf_filter: str = ""
    interface: str = INTERFACE

    def validate(self) -> None:
        if not 1 <= int(self.channel) <= 196:
            raise ValueError("信道必须在 1-196 之间")
        if self.mode not in ("manual", "count", "duration"):
            raise ValueError("未知的抓包模式")
        if self.mode == "count" and int(self.packet_count) <= 0:
            raise ValueError("抓包包数必须大于 0")
        if self.mode == "duration" and int(self.duration_sec) <= 0:
            raise ValueError("抓包时长必须大于 0")
        if "\n" in self.bpf_filter or "\r" in self.bpf_filter or "\x00" in self.bpf_filter:
            raise ValueError("BPF 过滤表达式不能包含换行符")
        if not re.match(r"^[A-Za-z0-9_.-]+$", self.interface):
            raise ValueError("监听接口名称不合法")

    def tcpdump_limits(self) -> str:
        if self.mode == "count":
            return "-c {}".format(int(self.packet_count))
        if self.mode == "duration":
            return "-G {} -W 1".format(int(self.duration_sec))
        return ""


@dataclass
class CaptureStatus:
    pid: Optional[int] = None
    alive: bool = False
    size: int = 0
    log_tail: str = ""


class StreamCaptureSession:
    def __init__(self, process: subprocess.Popen, local_path: Path, encoded: bool = False):
        self.process = process
        self.local_path = Path(local_path)
        self.bytes_written = 0
        self.stderr_text = ""
        self.error = ""
        self.encoded = encoded
        self.done = threading.Event()
        self._thread = threading.Thread(target=self._copy_stream, daemon=True, name="pcap-stream")
        self._thread.start()

    def _copy_stream(self) -> None:
        try:
            self.local_path.parent.mkdir(parents=True, exist_ok=True)
            with self.local_path.open("wb") as output:
                if self.encoded:
                    self._copy_encoded(output)
                else:
                    while True:
                        chunk = self.process.stdout.read(64 * 1024) if self.process.stdout else b""
                        if not chunk:
                            break
                        output.write(chunk)
                        output.flush()
                        self.bytes_written += len(chunk)
            if self.process.stderr:
                self.stderr_text = self.process.stderr.read().decode("utf-8", "replace").strip()
            self.process.wait()
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.done.set()

    def _copy_encoded(self, output) -> None:
        pending = b""
        while True:
            chunk = self.process.stdout.read(64 * 1024) if self.process.stdout else b""
            if not chunk:
                break
            pending += chunk
            lines = pending.split(b"\n")
            pending = lines.pop()
            for line in lines:
                decoded = base64.b64decode(line.strip(), validate=False)
                if decoded:
                    output.write(decoded)
                    output.flush()
                    self.bytes_written += len(decoded)
        if pending.strip():
            decoded = base64.b64decode(pending.strip(), validate=False)
            output.write(decoded)
            output.flush()
            self.bytes_written += len(decoded)

    @property
    def alive(self) -> bool:
        return not self.done.is_set()

    @property
    def size(self) -> int:
        try:
            return self.local_path.stat().st_size
        except OSError:
            return self.bytes_written

    def status(self) -> CaptureStatus:
        return CaptureStatus(alive=self.alive, size=self.size, log_tail=self.stderr_text)

    def stop(self, grace_timeout: float = 12.0) -> None:
        if not self.alive:
            return
        self.done.wait(grace_timeout)
        if self.alive:
            self.process.terminate()
            self.done.wait(3)
        if self.alive:
            self.process.kill()
            self.done.wait(3)

    def wait(self, timeout: Optional[float] = None) -> None:
        self.done.wait(timeout)


@dataclass
class DeviceInfo:
    serial: str
    model: str = "未知"
    os_name: str = "未知"
    kernel: str = "未知"
    root: bool = False
    tcpdump: str = "未检测到"
    monitor_active: bool = False
    monitor_present: bool = False
    monitor_type: str = ""
    monitor_interface: str = ""
    channel: Optional[int] = None
    interfaces: List[str] = field(default_factory=list)
    raw_iw: str = ""


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _parse_int(value: str) -> Optional[int]:
    match = re.search(r"-?\d+", value or "")
    return int(match.group(0)) if match else None


def build_start_script(config: CaptureConfig) -> str:
    config.validate()
    limits = config.tcpdump_limits()
    filter_line = "FILTER={}\n".format(_shell_quote(config.bpf_filter)) if config.bpf_filter.strip() else "FILTER=''\n"
    return """#!/bin/sh
set -f
IFACE={interface}
REMOTE={remote}
LOG={log}
PIDFILE={pidfile}
CAPSCRIPT={caps}
rm -f "$REMOTE" "$LOG" "$PIDFILE" "$CAPSCRIPT"
cat > "$CAPSCRIPT" <<'T113CAP_SCRIPT'
#!/bin/sh
set -f
{filter_line}exec /usr/sbin/tcpdump -i {interface} -U -n -s 0 -w {remote} {limits} $FILTER > {log} 2>&1
T113CAP_SCRIPT
chmod 700 "$CAPSCRIPT"
if command -v start-stop-daemon >/dev/null 2>&1; then
    start-stop-daemon -S -b -m -p "$PIDFILE" -x /bin/sh -- "$CAPSCRIPT"
else
    /bin/sh "$CAPSCRIPT" &
    echo $! > "$PIDFILE"
fi
sleep 1
PID=$(cat "$PIDFILE" 2>/dev/null)
STARTED=0
if [ -n "$PID" ]; then
    if kill -0 "$PID" 2>/dev/null || [ -s "$REMOTE" ]; then
        STARTED=1
    fi
fi
if [ "$STARTED" -eq 1 ]; then
    echo "T113CAP_STARTED:$PID"
else
    echo "T113CAP_FAILED"
    cat "$LOG" 2>/dev/null
    exit 1
fi
""".format(
        interface=_shell_quote(config.interface),
        remote=_shell_quote(REMOTE_PCAP),
        log=_shell_quote(REMOTE_LOG),
        pidfile=_shell_quote(REMOTE_PID),
        caps=_shell_quote(REMOTE_CAPTURE_SCRIPT),
        filter_line=filter_line,
        limits=limits,
    )


def build_stream_command(config: CaptureConfig) -> str:
    config.validate()
    filter_line = "FILTER={}\n".format(_shell_quote(config.bpf_filter)) if config.bpf_filter.strip() else "FILTER=''\n"
    filter_text = "$FILTER" if config.bpf_filter.strip() else ""
    return "PIDFILE={pidfile}; echo $$ > \"$PIDFILE\"; {filter_line}/usr/sbin/tcpdump -i {interface} -U -n -s 0 -w - {limits} {filter_text} 2>{log} | base64".format(
        pidfile=_shell_quote(REMOTE_STREAM_PID),
        log=_shell_quote(REMOTE_STREAM_LOG),
        filter_line=filter_line,
        interface=_shell_quote(config.interface),
        limits=config.tcpdump_limits(),
        filter_text=filter_text,
    )


class T113Controller:
    def __init__(self, adb: AdbClient):
        self.adb = adb

    def _wait_for_online(self, serial: str, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                devices = self.adb.devices(timeout=5)
            except AdbError:
                devices = []
            if any(device.serial == serial and device.online for device in devices):
                return True
            time.sleep(0.5)
        return False

    def _restore_complete(self, serial: str, interface: str = INTERFACE) -> bool:
        script = """#!/bin/sh
MON=0
WLAN=0
if [ -d "/sys/class/net/{iface}" ]; then MON=1; fi
if [ -d /sys/class/net/wlan0 ] && ifconfig wlan0 2>/dev/null | grep -q "UP"; then WLAN=1; fi
echo "MON=$MON"
echo "WLAN=$WLAN"
""".format(iface=interface)
        result = self.adb.run_script(serial, script, timeout=15)
        if not result.ok:
            return False
        values: Dict[str, str] = {}
        for line in result.stdout.replace("\r", "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        return values.get("MON") == "0" and values.get("WLAN") == "1"

    def get_device_info(self, serial: str) -> DeviceInfo:
        command = r"""
printf 'MODEL='; tr -d '\000' </proc/device-tree/model 2>/dev/null; echo
printf 'OS='; ( . /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME" ); echo
printf 'KERNEL='; uname -r 2>/dev/null; echo
printf 'UID='; id -u 2>/dev/null; echo
printf 'TCPDUMP='; /usr/sbin/tcpdump --version 2>&1 | head -n 1
printf 'MON1_PRESENT='; if [ -d /sys/class/net/mon1 ]; then echo 1; else echo 0; fi
printf 'MON1_TYPE='; cat /sys/class/net/mon1/type 2>/dev/null; echo
printf 'MON1_OPERSTATE='; cat /sys/class/net/mon1/operstate 2>/dev/null; echo
printf 'NET_BEGIN\n'
for n in /sys/class/net/*; do printf '%s\n' "${n##*/}"; done 2>/dev/null
printf 'NET_END\n'
if [ ! -d /sys/class/net/mon1 ]; then
    printf 'IWDEV_BEGIN\n'
    iw dev 2>&1
    printf 'IWDEV_END\n'
fi
"""
        result = self.adb.shell(serial, command, timeout=20)
        if not result.ok:
            raise AdbError(result.combined or "读取设备信息失败")
        text = ANSI_RE.sub("", result.stdout.replace("\r", ""))
        info = DeviceInfo(serial=serial)
        iw_lines: List[str] = []
        net_interfaces: List[str] = []
        in_iw = False
        in_net = False
        for line in text.splitlines():
            if line == "IWDEV_BEGIN":
                in_iw = True
                continue
            if line == "IWDEV_END":
                in_iw = False
                continue
            if line == "NET_BEGIN":
                in_net = True
                continue
            if line == "NET_END":
                in_net = False
                continue
            if in_net:
                if line.strip():
                    net_interfaces.append(line.strip())
                continue
            if in_iw:
                iw_lines.append(line)
                continue
            if line.startswith("MODEL="):
                info.model = line[6:].strip() or "未知"
            elif line.startswith("OS="):
                info.os_name = line[3:].strip() or "未知"
            elif line.startswith("KERNEL="):
                info.kernel = line[7:].strip() or "未知"
            elif line.startswith("UID="):
                info.root = (line[4:].strip() == "0")
            elif line.startswith("TCPDUMP="):
                info.tcpdump = line[8:].strip() or "未检测到"
            elif line.startswith("MON1_PRESENT="):
                info.monitor_present = line[13:].strip() == "1"
            elif line.startswith("MON1_TYPE="):
                info.monitor_type = line[10:].strip()
        info.raw_iw = "\n".join(iw_lines)
        info.interfaces = net_interfaces
        self._populate_iw_state(info, iw_lines)
        return info

    @staticmethod
    def _populate_iw_state(info: DeviceInfo, lines: List[str]) -> None:
        current_name = ""
        current_type = ""
        current_channel: Optional[int] = None
        entries = []
        for line in lines + ["Interface __END__"]:
            stripped = line.strip()
            if stripped.startswith("Interface "):
                if current_name:
                    entries.append((current_name, current_type, current_channel))
                current_name = stripped.split(None, 1)[1]
                current_type = ""
                current_channel = None
            elif stripped.startswith("type ") and current_name:
                current_type = stripped[5:].strip()
            elif stripped.startswith("channel ") and current_name:
                current_channel = _parse_int(stripped[8:])
        if not info.interfaces:
            info.interfaces = [name for name, _kind, _channel in entries]
        if info.monitor_present:
            info.monitor_active = True
            info.monitor_interface = INTERFACE
            if INTERFACE not in info.interfaces:
                info.interfaces.append(INTERFACE)
            return
        for name, kind, channel in entries:
            if name == INTERFACE and kind == "monitor":
                info.monitor_active = True
                info.monitor_interface = name
                info.channel = channel
                break

    def prepare_monitor(self, serial: str, interface: str = INTERFACE) -> str:
        if not re.match(r"^[A-Za-z0-9_.-]+$", interface):
            raise ValueError("监听接口名称不合法")
        script = """#!/bin/sh
set -u
IFACE={iface}
ifconfig wlan0 down 2>/dev/null || true
sleep 1
if [ -d "/sys/class/net/$IFACE" ]; then
    ifconfig "$IFACE" down >/dev/null 2>&1 || true
    sleep 1
    iw dev "$IFACE" del >/dev/null 2>&1 || true
    sleep 1
fi
iw phy phy0 interface add "$IFACE" type monitor
sleep 1
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
ifconfig "$IFACE" up
sleep 1
if [ -d "/sys/class/net/$IFACE" ] && ifconfig "$IFACE" 2>/dev/null | grep -q "UP"; then
    echo T113CAP_MONITOR_READY
else
    echo T113CAP_MONITOR_FAILED
    ifconfig -a 2>&1
    exit 1
fi
""".format(iface=_shell_quote(interface))
        result = None
        error: Optional[BaseException] = None
        try:
            result = self.adb.run_script(serial, script, timeout=35)
            if result.ok and "T113CAP_MONITOR_READY" in result.stdout:
                return result.combined
            error = AdbError(result.combined or "监听模式初始化失败")
        except AdbError as exc:
            error = exc
        if self._wait_for_online(serial, timeout=30):
            try:
                info = self.get_device_info(serial)
            except AdbError as exc:
                error = exc
            else:
                if info.monitor_present:
                    detail = result.combined if result is not None else ""
                    return "{}\nADB 重连后已确认监听接口就绪".format(detail).strip()
        raise AdbError(str(error or "监听模式初始化失败"))

    def set_channel(self, serial: str, channel: int, interface: str = INTERFACE) -> str:
        channel = int(channel)
        if not 1 <= channel <= 196:
            raise ValueError("信道必须在 1-196 之间")
        result = self.adb.shell(
            serial,
            "iw dev {} set channel {}".format(interface, channel),
            timeout=15,
        )
        if not result.ok:
            raise AdbError(result.combined or "设置信道失败")
        return result.combined

    def start_capture(self, serial: str, config: CaptureConfig) -> int:
        script = build_start_script(config)
        result = self.adb.run_script(serial, script, timeout=20)
        match = re.search(r"T113CAP_STARTED:(\d+)", result.stdout)
        if not result.ok or not match:
            raise AdbError(result.combined or "tcpdump 启动失败")
        return int(match.group(1))

    def start_stream_capture(self, serial: str, config: CaptureConfig, local_path: str) -> StreamCaptureSession:
        process = self.adb.stream_shell(serial, build_stream_command(config))
        return StreamCaptureSession(process, Path(local_path), encoded=True)

    def stop_stream_capture(self, serial: str, session: StreamCaptureSession) -> None:
        try:
            self.adb.shell(
                serial,
                "PID=$(pidof tcpdump 2>/dev/null | head -n 1); if [ -n \"$PID\" ]; then kill -INT \"$PID\" 2>/dev/null || true; fi",
                timeout=10,
            )
        except AdbError:
            pass
        session.stop()

    def remote_status(self, serial: str) -> CaptureStatus:
        script = """#!/bin/sh
PID=$(cat {pidfile} 2>/dev/null)
ALIVE=0
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    ALIVE=1
fi
SIZE=$(wc -c < {remote} 2>/dev/null || echo 0)
LOG=$(tail -n 8 {log} 2>/dev/null | tr '\n' '|')
echo "PID=$PID"
echo "ALIVE=$ALIVE"
echo "SIZE=$SIZE"
echo "LOG=$LOG"
""".format(pidfile=_shell_quote(REMOTE_PID), remote=_shell_quote(REMOTE_PCAP), log=_shell_quote(REMOTE_LOG))
        result = self.adb.run_script(serial, script, timeout=15)
        if not result.ok:
            raise AdbError(result.combined or "读取抓包状态失败")
        values: Dict[str, str] = {}
        for line in result.stdout.replace("\r", "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        pid = _parse_int(values.get("PID", ""))
        size = _parse_int(values.get("SIZE", "0")) or 0
        return CaptureStatus(
            pid=pid,
            alive=values.get("ALIVE") == "1",
            size=size,
            log_tail=values.get("LOG", "").replace("|", "\n").strip(),
        )

    def stop_capture(self, serial: str, wait_seconds: float = 6.0) -> str:
        loops = max(1, int(wait_seconds))
        script = """#!/bin/sh
PID=$(cat {pidfile} 2>/dev/null)
if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    echo T113CAP_ALREADY_STOPPED
    exit 0
fi
kill -INT "$PID" 2>/dev/null || true
i=0
while kill -0 "$PID" 2>/dev/null && [ $i -lt {loops} ]; do
    sleep 1
    i=$((i+1))
done
if kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
    sleep 1
fi
if kill -0 "$PID" 2>/dev/null; then
    echo T113CAP_STILL_RUNNING
    exit 1
fi
echo T113CAP_STOPPED
tail -n 8 {log} 2>/dev/null
""".format(pidfile=_shell_quote(REMOTE_PID), loops=loops, log=_shell_quote(REMOTE_LOG))
        result = self.adb.run_script(serial, script, timeout=wait_seconds + 12)
        if not result.ok:
            raise AdbError(result.combined or "停止抓包失败")
        return result.combined

    def pull_capture(self, serial: str, local_path: str, timeout: float = 900) -> CommandResult:
        return self.adb.pull(serial, REMOTE_PCAP, local_path, timeout=timeout)

    def cleanup_remote(self, serial: str) -> None:
        self.adb.shell(
            serial,
            "rm -f {} {} {} {} {} {}".format(
                REMOTE_PCAP, REMOTE_PID, REMOTE_LOG, REMOTE_CAPTURE_SCRIPT, REMOTE_STREAM_PID, REMOTE_STREAM_LOG
            ),
            timeout=10,
        )

    def restore_device(self, serial: str, interface: str = INTERFACE) -> str:
        script = """#!/bin/sh
PID=$(cat {pidfile} 2>/dev/null)
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    kill -INT "$PID" 2>/dev/null || true
    sleep 1
fi
if [ -d "/sys/class/net/$IFACE" ]; then
    ifconfig "$IFACE" down >/dev/null 2>&1 || true
    sleep 1
    iw dev "$IFACE" del >/dev/null 2>&1 || true
fi
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
dmesg -n 7 2>/dev/null || true
ifconfig wlan0 up 2>/dev/null || true
sleep 1
echo T113CAP_RESTORED
""".format(pidfile=_shell_quote(REMOTE_PID), iface=_shell_quote(interface))
        last_error: Optional[BaseException] = None
        for attempt in range(3):
            if attempt and not self._wait_for_online(serial, timeout=30):
                break
            if attempt:
                try:
                    if self._restore_complete(serial, interface):
                        return "T113CAP_RESTORED\n恢复状态校验通过"
                except AdbError as exc:
                    last_error = exc
            try:
                result = self.adb.run_script(serial, script, timeout=25)
                if result.ok and "T113CAP_RESTORED" in result.stdout:
                    return result.combined
                last_error = AdbError(result.combined or "恢复设备失败")
            except AdbError as exc:
                last_error = exc
            if not self._wait_for_online(serial, timeout=30):
                break
            try:
                if self._restore_complete(serial, interface):
                    return "T113CAP_RESTORED\nADB 重连后已确认 wlan0 恢复"
            except AdbError as exc:
                last_error = exc
        raise AdbError(str(last_error or "恢复设备失败"))

    def wait_for_stop(self, serial: str, timeout: float = 6.0) -> CaptureStatus:
        deadline = time.monotonic() + timeout
        status = self.remote_status(serial)
        while status.alive and time.monotonic() < deadline:
            time.sleep(0.2)
            status = self.remote_status(serial)
        return status
