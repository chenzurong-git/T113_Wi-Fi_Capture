from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Dict, List, Optional


SETTINGS_FILENAME = "T113Capture.settings.json"
SETTINGS_VERSION = 3


def application_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def default_output_dir() -> Path:
    return application_dir() / "captures"


def _ensure_writable_dir(candidate: Path) -> bool:
    try:
        candidate.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(str(candidate), os.W_OK)


def _default_output_dir() -> str:
    preferred = default_output_dir()
    candidates: List[Path] = [preferred]
    cwd_candidate = Path.cwd() / "captures"
    if cwd_candidate.resolve() != preferred.resolve():
        candidates.append(cwd_candidate)
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        candidates.append(Path(local_appdata) / "T113Capture" / "Captures")
    for candidate in candidates:
        if _ensure_writable_dir(candidate):
            return str(candidate)
    return str(preferred)


def portable_settings_path() -> Path:
    return application_dir() / SETTINGS_FILENAME


def legacy_settings_path() -> Path:
    base = os.environ.get("APPDATA")
    if base:
        return Path(base) / "T113Capture" / "settings.json"
    return Path.home() / ".t113capture" / "settings.json"


def _settings_candidates() -> List[Path]:
    candidates = [portable_settings_path(), legacy_settings_path()]
    unique: List[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if all(resolved != existing.resolve() for existing in unique):
            unique.append(candidate)
    return unique


def settings_path() -> Path:
    return portable_settings_path()


@dataclass
class AppSettings:
    serial: str = ""
    channel: int = 6
    mode: str = "manual"
    packet_count: int = 5000
    duration_sec: int = 30
    bpf_filter: str = ""
    output_dir: str = ""
    delete_remote: bool = True
    open_wireshark: bool = False
    restore_on_exit: bool = True
    stream_capture: bool = True
    adb_path: str = ""

    def __post_init__(self) -> None:
        if not self.output_dir:
            self.output_dir = _default_output_dir()


def _read_settings_file(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_settings() -> AppSettings:
    existing = [path for path in _settings_candidates() if path.is_file()]
    if not existing:
        return AppSettings()
    source = max(existing, key=lambda path: path.stat().st_mtime)
    data = _read_settings_file(source)
    if not data:
        return AppSettings()
    try:
        version = int(data.get("_settings_version", 1))
    except (TypeError, ValueError):
        version = 1
    allowed = {field.name for field in fields(AppSettings)}
    cleaned: Dict[str, Any] = {key: value for key, value in data.items() if key in allowed}
    try:
        settings = AppSettings(**cleaned)
    except (TypeError, ValueError):
        return AppSettings()
    if version < SETTINGS_VERSION:
        settings.output_dir = _default_output_dir()
        try:
            save_settings(settings)
        except OSError:
            pass
    return settings


def _write_settings(path: Path, settings: AppSettings) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(settings)
    payload["_settings_version"] = SETTINGS_VERSION
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def save_settings(settings: AppSettings) -> None:
    last_error: Optional[Exception] = None
    for path in _settings_candidates():
        try:
            _write_settings(path, settings)
            return
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
