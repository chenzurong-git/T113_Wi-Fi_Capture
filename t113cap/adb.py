from __future__ import annotations

import base64
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class AdbError(RuntimeError):
    pass


@dataclass
class AdbDevice:
    serial: str
    state: str
    details: str = ""

    @property
    def online(self) -> bool:
        return self.state == "device"

    @property
    def display_name(self) -> str:
        suffix = "  · 在线" if self.online else "  · " + self.state
        return self.serial + suffix


@dataclass
class CommandResult:
    args: Sequence[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def combined(self) -> str:
        parts = [part.strip() for part in (self.stdout, self.stderr) if part and part.strip()]
        return "\n".join(parts)

    def raise_for_error(self, action: str) -> "CommandResult":
        if not self.ok:
            detail = self.combined or "命令返回码 {}".format(self.returncode)
            raise AdbError("{}失败：{}".format(action, detail))
        return self


def find_adb(explicit: Optional[str] = None) -> Optional[str]:
    candidates = []
    if explicit:
        candidates.append(explicit)
    env_path = os.environ.get("ADB")
    if env_path:
        candidates.append(env_path)
    which_path = shutil.which("adb")
    if which_path:
        candidates.append(which_path)
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        candidates.append(str(Path(local_appdata) / "Android" / "Sdk" / "platform-tools" / "adb.exe"))
    candidates.extend([
        r"C:\Android\platform-tools\adb.exe",
        r"C:\platform-tools\adb.exe",
    ])
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    return None


class AdbClient:
    def __init__(self, adb_path: Optional[str] = None):
        self.adb_path = find_adb(adb_path)

    @property
    def available(self) -> bool:
        return bool(self.adb_path)

    def _require_adb(self) -> str:
        if not self.adb_path:
            raise AdbError("未找到 adb.exe。请安装 Android Platform Tools，或设置 ADB 环境变量。")
        return self.adb_path

    def run(
        self,
        args: Sequence[str],
        timeout: float = 30,
        input_text: Optional[str] = None,
        check: bool = False,
    ) -> CommandResult:
        adb = self._require_adb()
        command = [adb] + list(args)
        kwargs = {
            "input": input_text,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": timeout,
        }
        if os.name == "nt":
            kwargs["creationflags"] = CREATE_NO_WINDOW
        try:
            proc = subprocess.run(command, **kwargs)
        except FileNotFoundError as exc:
            raise AdbError("adb.exe 不存在：{}".format(adb)) from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError("ADB 命令超时（{} 秒）".format(timeout)) from exc
        result = CommandResult(command, proc.returncode, proc.stdout or "", proc.stderr or "")
        if check:
            result.raise_for_error("ADB 命令")
        return result

    def devices(self, timeout: float = 15) -> List[AdbDevice]:
        result = self.run(["devices", "-l"], timeout=timeout)
        if not result.ok:
            raise AdbError(result.combined or "adb devices 执行失败")
        devices = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            fields = line.split()
            if len(fields) < 2:
                continue
            devices.append(AdbDevice(fields[0], fields[1], " ".join(fields[2:])))
        return devices

    def shell(self, serial: str, command: str, timeout: float = 30, check: bool = False) -> CommandResult:
        return self.run(["-s", serial, "shell", command], timeout=timeout, check=check)

    def stream_shell(self, serial: str, command: str) -> subprocess.Popen:
        adb = self._require_adb()
        args = [adb, "-s", serial, "shell", command]
        kwargs = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if os.name == "nt":
            kwargs["creationflags"] = CREATE_NO_WINDOW
        try:
            return subprocess.Popen(args, **kwargs)
        except FileNotFoundError as exc:
            raise AdbError("adb.exe 不存在：{}".format(adb)) from exc

    def run_script(self, serial: str, script: str, timeout: float = 30, check: bool = False) -> CommandResult:
        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        remote = "/tmp/t113cap_script.sh"
        command = "printf '%s' '{}' | base64 -d > {} && chmod 700 {} && {}".format(
            encoded, remote, remote, remote
        )
        return self.shell(serial, command, timeout=timeout, check=check)

    def pull(self, serial: str, remote: str, local: str, timeout: float = 900) -> CommandResult:
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        result = self.run(["-s", serial, "pull", remote, local], timeout=timeout)
        if not result.ok:
            raise AdbError(result.combined or "ADB 拉取文件失败")
        if not Path(local).is_file():
            raise AdbError("ADB 拉取结束后未找到本地文件：{}".format(local))
        return result

    def version(self) -> str:
        result = self.run(["version"], timeout=10)
        if not result.ok:
            return "unknown"
        lines = result.stdout.splitlines()
        return lines[0].strip() if lines else "unknown"
