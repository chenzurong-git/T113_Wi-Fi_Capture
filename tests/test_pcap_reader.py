from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from t113cap.pcap_reader import PcapError, format_bytes, read_pcap, scan_pcap, trim_incomplete_pcap_tail


def mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def build_beacon(ssid: str = "T113-Test", channel: int = 6) -> bytes:
    fc = 0x0080
    header = struct.pack("<H", fc) + b"\x00\x00"
    header += b"\xff" * 6
    ap = mac("02:11:22:33:44:55")
    header += ap + ap
    header += b"\x00\x00"
    fixed = b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0431)
    ssid_bytes = ssid.encode("utf-8")
    ies = bytes([0, len(ssid_bytes)]) + ssid_bytes + bytes([3, 1, channel])
    radiotap = b"\x00\x00\x08\x00" + b"\x00" * 4
    return radiotap + header + fixed + ies


def build_data_frame() -> bytes:
    fc = 0x0008
    header = struct.pack("<H", fc) + b"\x00\x00"
    dst = mac("aa:bb:cc:dd:ee:ff")
    src = mac("00:11:22:33:44:55")
    bssid = mac("02:11:22:33:44:55")
    header += dst + src + bssid + b"\x00\x00"
    payload = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + b"\x45" + b"\x00" * 40
    radiotap = b"\x00\x00\x08\x00" + b"\x00" * 4
    return radiotap + header + payload


def write_pcap(path: Path, frames: list) -> None:
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 127)
    with path.open("wb") as handle:
        handle.write(header)
        for index, frame in enumerate(frames):
            ts_sec = 1_700_000_000 + index
            record = struct.pack("<IIII", ts_sec, 250_000, len(frame), len(frame))
            handle.write(record)
            handle.write(frame)


class PcapReaderTests(unittest.TestCase):
    def test_parse_beacon_and_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.pcap"
            write_pcap(path, [build_beacon(), build_data_frame()])
            summary = read_pcap(path)
            self.assertEqual(summary.packet_count, 2)
            self.assertEqual(summary.categories.get("管理帧"), 1)
            self.assertEqual(summary.categories.get("数据帧"), 1)
            self.assertEqual(summary.packets[0].protocol, "Beacon")
            self.assertEqual(summary.packets[0].bssid, "02:11:22:33:44:55")
            self.assertIn("SSID=\"T113-Test\"", summary.packets[0].info)
            self.assertIn("CH=6", summary.packets[0].info)
            self.assertEqual(summary.ssids, ["T113-Test"])
            self.assertAlmostEqual(summary.duration, 1.0, places=3)

    def test_scan_meta(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.pcap"
            write_pcap(path, [build_beacon(), build_data_frame()])
            meta = scan_pcap(path)
            self.assertTrue(meta.supported)
            self.assertEqual(meta.packet_count, 2)
            self.assertEqual(meta.link_type, 127)

    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1536), "1.5 KB")

    def test_trim_incomplete_tail_preserves_complete_packets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "partial.pcap"
            write_pcap(path, [build_beacon(), build_data_frame()])
            complete_size = path.stat().st_size
            with path.open("ab") as handle:
                handle.write(struct.pack("<IIII", 0, 0, 256, 256) + b"\x01" * 31)
            removed = trim_incomplete_pcap_tail(path)
            self.assertEqual(path.stat().st_size, complete_size)
            self.assertEqual(removed, 47)
            summary = read_pcap(path)
            self.assertEqual(summary.packet_count, 2)
            self.assertFalse(summary.file_truncated)

    def test_trim_incomplete_tail_removes_partial_record_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "partial.pcap"
            write_pcap(path, [build_beacon()])
            complete_size = path.stat().st_size
            with path.open("ab") as handle:
                handle.write(b"\x00" * 7)
            removed = trim_incomplete_pcap_tail(path)
            self.assertEqual(path.stat().st_size, complete_size)
            self.assertEqual(removed, 7)
            self.assertFalse(read_pcap(path).file_truncated)

    def test_trim_complete_file_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "complete.pcap"
            write_pcap(path, [build_beacon(), build_data_frame()])
            original = path.read_bytes()
            self.assertEqual(trim_incomplete_pcap_tail(path), 0)
            self.assertEqual(path.read_bytes(), original)

    def test_trim_rejects_invalid_length_inside_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "damaged.pcap"
            write_pcap(path, [build_beacon(), build_data_frame()])
            data = bytearray(path.read_bytes())
            corrupt_at = 24 + 16 + len(build_beacon())
            data[corrupt_at + 8:corrupt_at + 12] = struct.pack("<I", 0xFFFFFFFF)
            path.write_bytes(bytes(data))
            original_size = path.stat().st_size
            with self.assertRaises(PcapError):
                trim_incomplete_pcap_tail(path)
            self.assertEqual(path.stat().st_size, original_size)


if __name__ == "__main__":
    unittest.main()
