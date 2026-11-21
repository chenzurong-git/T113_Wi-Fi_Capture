from __future__ import annotations

import csv
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class PcapError(RuntimeError):
    pass


MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

MGMT_NAMES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
}

CTRL_NAMES = {
    7: "Control Wrapper",
    8: "Block Ack Request",
    9: "Block Ack",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
    14: "CF-End",
    15: "CF-End + CF-Ack",
}

DATA_NAMES = {
    0: "Data",
    1: "Data + CF-ACK",
    2: "Data + CF-Poll",
    3: "Data + CF-Ack + CF-Poll",
    4: "Null",
    5: "CF-ACK",
    6: "CF-Poll",
    7: "CF-Ack + CF-Poll",
    8: "QoS Data",
    9: "QoS Data + CF-ACK",
    10: "QoS Data + CF-Poll",
    11: "QoS Data + CF-Ack + CF-Poll",
    12: "QoS Null",
    13: "QoS CF-ACK",
    14: "QoS CF-Poll",
    15: "QoS CF-Ack + CF-Poll",
}


@dataclass
class PacketInfo:
    number: int
    timestamp: float
    length: int
    captured_length: int
    category: str
    protocol: str
    source: str = ""
    destination: str = ""
    bssid: str = ""
    info: str = ""

    @property
    def time_text(self) -> str:
        try:
            return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]
        except (OSError, OverflowError, ValueError):
            return "{:.6f}".format(self.timestamp)


@dataclass
class PcapSummary:
    path: Path
    link_type: int
    packet_count: int
    file_size: int
    first_timestamp: Optional[float]
    last_timestamp: Optional[float]
    packets: List[PacketInfo] = field(default_factory=list)
    categories: Dict[str, int] = field(default_factory=dict)
    ssids: List[str] = field(default_factory=list)
    details_truncated: bool = False
    file_truncated: bool = False

    @property
    def duration(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return max(0.0, self.last_timestamp - self.first_timestamp)

    @property
    def link_name(self) -> str:
        return {
            1: "Ethernet",
            105: "IEEE 802.11",
            127: "IEEE 802.11 + Radiotap",
        }.get(self.link_type, "DLT {}".format(self.link_type))


@dataclass
class PcapMeta:
    path: Path
    link_type: int
    packet_count: int
    file_size: int
    first_timestamp: Optional[float]
    last_timestamp: Optional[float]
    supported: bool = True

    @property
    def duration(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return max(0.0, self.last_timestamp - self.first_timestamp)


def _read_header(handle) -> Tuple[str, int, int]:
    header = handle.read(24)
    if len(header) < 24:
        raise PcapError("文件太小，不是有效的 PCAP 文件")
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        raise PcapError("当前版本仅支持经典 PCAP，请用 Wireshark 打开 PCAPNG 文件")
    magic = MAGICS.get(header[:4])
    if not magic:
        raise PcapError("无法识别 PCAP 文件头")
    endian, units = magic
    link_type = struct.unpack(endian + "I", header[20:24])[0]
    return endian, units, link_type


def _read_record(handle, endian: str, units: int):
    record = handle.read(16)
    if not record:
        return None
    if len(record) < 16:
        raise PcapError("PCAP 记录头不完整")
    ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", record)
    if incl_len > 16 * 1024 * 1024 or orig_len > 32 * 1024 * 1024:
        raise PcapError("PCAP 记录长度异常：{} / {}".format(incl_len, orig_len))
    payload = handle.read(incl_len)
    if len(payload) < incl_len:
        raise PcapError("PCAP 数据包内容不完整")
    return ts_sec + (ts_frac / float(units)), incl_len, orig_len, payload


def scan_pcap(path: Path) -> PcapMeta:
    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as handle:
        try:
            endian, units, link_type = _read_header(handle)
        except PcapError as exc:
            return PcapMeta(path, -1, 0, size, None, None, False)
        count = 0
        first_ts = None
        last_ts = None
        try:
            while True:
                record = _read_record(handle, endian, units)
                if record is None:
                    break
                timestamp = record[0]
                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp
                count += 1
        except (PcapError, OSError):
            pass
    return PcapMeta(path, link_type, count, size, first_ts, last_ts, True)


def trim_incomplete_pcap_tail(path: Path) -> int:
    """Drop only incomplete records at the end of a classic PCAP file.

    An interrupted stream can leave a partial record header or payload. The
    complete packets before it remain valid, so truncating at the last record
    boundary keeps the file usable by Wireshark without hiding damage that
    occurs anywhere else in the capture.
    """
    path = Path(path)
    size = path.stat().st_size
    if size < 24:
        return 0

    with path.open("rb") as handle:
        endian, _units, _link_type = _read_header(handle)
        valid_end = 24
        while True:
            record_start = handle.tell()
            record = handle.read(16)
            if not record:
                break
            if len(record) < 16:
                valid_end = record_start
                break
            _ts_sec, _ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", record)
            if incl_len > 16 * 1024 * 1024 or orig_len > 32 * 1024 * 1024:
                raise PcapError("PCAP 记录长度异常：{} / {}".format(incl_len, orig_len))
            payload = handle.read(incl_len)
            if len(payload) < incl_len:
                valid_end = record_start
                break
            valid_end = handle.tell()

    if valid_end < size:
        with path.open("r+b") as handle:
            handle.truncate(valid_end)
        return size - valid_end
    return 0


def _mac(raw: bytes) -> str:
    if len(raw) < 6:
        return ""
    return ":".join("{:02x}".format(byte) for byte in raw[:6])


def _category_name(frame_type: int) -> str:
    return {0: "管理帧", 1: "控制帧", 2: "数据帧"}.get(frame_type, "其他")


def _subtype_name(frame_type: int, subtype: int) -> str:
    if frame_type == 0:
        return MGMT_NAMES.get(subtype, "Management {}".format(subtype))
    if frame_type == 1:
        return CTRL_NAMES.get(subtype, "Control {}".format(subtype))
    if frame_type == 2:
        return DATA_NAMES.get(subtype, "Data {}".format(subtype))
    return "802.11 Type {}".format(frame_type)


def _parse_ies(payload: bytes) -> Tuple[str, Optional[int]]:
    ssid = ""
    channel = None
    offset = 0
    while offset + 2 <= len(payload):
        element_id = payload[offset]
        length = payload[offset + 1]
        value = payload[offset + 2: offset + 2 + length]
        if len(value) < length:
            break
        if element_id == 0 and not ssid:
            ssid = value.decode("utf-8", errors="replace").replace("\x00", "").strip()
        elif element_id == 3 and value:
            channel = value[0]
        offset += 2 + length
    return ssid, channel


def _parse_80211(payload: bytes, number: int, timestamp: float, captured_length: int, original_length: int) -> PacketInfo:
    if len(payload) < 2:
        return PacketInfo(number, timestamp, original_length, captured_length, "其他", "802.11 短帧")
    frame_control = struct.unpack("<H", payload[:2])[0]
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    to_ds = bool(frame_control & 0x0100)
    from_ds = bool(frame_control & 0x0200)
    category = _category_name(frame_type)
    protocol = _subtype_name(frame_type, subtype)
    addr1 = payload[4:10]
    addr2 = payload[10:16]
    addr3 = payload[16:22]
    source = ""
    destination = ""
    bssid = ""
    info_parts: List[str] = []
    if frame_type == 0:
        destination = _mac(addr1)
        source = _mac(addr2)
        bssid = _mac(addr3)
        body = payload[24:]
        if subtype in (5, 8):
            ssid, channel = _parse_ies(body[12:])
            if ssid:
                info_parts.append("SSID=\"{}\"".format(ssid))
            if channel is not None:
                info_parts.append("CH={}".format(channel))
        elif subtype == 4:
            ssid, _channel = _parse_ies(body)
            if ssid:
                info_parts.append("SSID=\"{}\"".format(ssid))
        elif subtype in (10, 12) and len(body) >= 2:
            info_parts.append("原因={}".format(struct.unpack("<H", body[:2])[0]))
        elif subtype == 11 and len(body) >= 6:
            algorithm, sequence, status = struct.unpack("<HHH", body[:6])
            info_parts.append("算法={} 序号={} 状态={}".format(algorithm, sequence, status))
    elif frame_type == 1:
        if subtype in (11,):
            destination = _mac(addr1)
            source = _mac(addr2)
        else:
            destination = _mac(addr1)
        info_parts.append("RA={}".format(_mac(addr1)))
    elif frame_type == 2:
        if to_ds and from_ds and len(payload) >= 30:
            addr4 = payload[24:30]
            destination = _mac(addr3)
            source = _mac(addr4)
        elif to_ds:
            destination = _mac(addr3)
            source = _mac(addr2)
            bssid = _mac(addr1)
        elif from_ds:
            destination = _mac(addr1)
            source = _mac(addr3)
            bssid = _mac(addr2)
        else:
            destination = _mac(addr1)
            source = _mac(addr2)
            bssid = _mac(addr3)
        if to_ds or from_ds:
            info_parts.append("ToDS={} FromDS={}".format(int(to_ds), int(from_ds)))
    return PacketInfo(
        number=number,
        timestamp=timestamp,
        length=original_length,
        captured_length=captured_length,
        category=category,
        protocol=protocol,
        source=source,
        destination=destination,
        bssid=bssid,
        info=" · ".join(info_parts),
    )


def _parse_ethernet(payload: bytes, number: int, timestamp: float, captured_length: int, original_length: int) -> PacketInfo:
    if len(payload) < 14:
        return PacketInfo(number, timestamp, original_length, captured_length, "其他", "Ethernet 短帧")
    destination = _mac(payload[0:6])
    source = _mac(payload[6:12])
    ether_type = struct.unpack(">H", payload[12:14])[0]
    protocol = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(ether_type, "EtherType 0x{:04x}".format(ether_type))
    info = ""
    if ether_type == 0x0800 and len(payload) >= 34:
        header_len = (payload[14] & 0x0F) * 4
        proto = payload[23]
        src_ip = ".".join(str(byte) for byte in payload[26:30])
        dst_ip = ".".join(str(byte) for byte in payload[30:34])
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "IP/{}".format(proto))
        protocol = proto_name
        info = "{} -> {}".format(src_ip, dst_ip)
        if proto in (6, 17) and len(payload) >= 14 + header_len + 4:
            src_port, dst_port = struct.unpack(">HH", payload[14 + header_len: 14 + header_len + 4])
            info += "  {} -> {}".format(src_port, dst_port)
    return PacketInfo(number, timestamp, original_length, captured_length, "其他", protocol, source, destination, "", info)


def _parse_packet(payload: bytes, link_type: int, number: int, timestamp: float, captured_length: int, original_length: int) -> PacketInfo:
    if link_type == 127:
        if len(payload) < 8:
            return PacketInfo(number, timestamp, original_length, captured_length, "其他", "Radiotap 短帧")
        radiotap_length = struct.unpack("<H", payload[2:4])[0]
        if radiotap_length > len(payload):
            return PacketInfo(number, timestamp, original_length, captured_length, "其他", "Radiotap 异常")
        return _parse_80211(payload[radiotap_length:], number, timestamp, captured_length, original_length)
    if link_type == 105:
        return _parse_80211(payload, number, timestamp, captured_length, original_length)
    if link_type == 1:
        return _parse_ethernet(payload, number, timestamp, captured_length, original_length)
    return PacketInfo(number, timestamp, original_length, captured_length, "其他", "DLT {}".format(link_type))


def read_pcap(path: Path, detail_limit: int = 10000) -> PcapSummary:
    path = Path(path)
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        endian, units, link_type = _read_header(handle)
        count = 0
        first_ts = None
        last_ts = None
        packets: List[PacketInfo] = []
        categories: Dict[str, int] = {}
        ssids: List[str] = []
        file_truncated = False
        while True:
            try:
                record = _read_record(handle, endian, units)
            except PcapError:
                file_truncated = True
                break
            if record is None:
                break
            timestamp, incl_len, orig_len, payload = record
            count += 1
            if first_ts is None:
                first_ts = timestamp
            last_ts = timestamp
            if len(packets) < detail_limit:
                packet = _parse_packet(payload, link_type, count, timestamp, incl_len, orig_len)
                packets.append(packet)
                categories[packet.category] = categories.get(packet.category, 0) + 1
                if packet.protocol in ("Beacon", "Probe Response") and "SSID=\"" in packet.info:
                    ssid = packet.info.split("SSID=\"", 1)[1].split("\"", 1)[0]
                    if ssid and ssid not in ssids:
                        ssids.append(ssid)
    return PcapSummary(
        path=path,
        link_type=link_type,
        packet_count=count,
        file_size=file_size,
        first_timestamp=first_ts,
        last_timestamp=last_ts,
        packets=packets,
        categories=categories,
        ssids=ssids[:20],
        details_truncated=count > detail_limit,
        file_truncated=file_truncated,
    )


def format_bytes(value: int) -> str:
    size = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0 or unit == "GB":
            if unit == "B":
                return "{:.0f} {}".format(size, unit)
            return "{:.1f} {}".format(size, unit)
        size /= 1024.0
    return "{:.1f} GB".format(size)


def format_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return "{:.1f}s".format(seconds)
    minutes = int(seconds // 60)
    remain = seconds - minutes * 60
    if minutes < 60:
        return "{}m {:02.0f}s".format(minutes, remain)
    hours = minutes // 60
    return "{}h {:02d}m".format(hours, minutes % 60)


def export_packets_csv(summary: PcapSummary, path: Path) -> None:
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["序号", "时间", "类别", "协议", "源地址", "目的地址", "BSSID", "长度", "摘要"])
        for packet in summary.packets:
            writer.writerow([
                packet.number,
                packet.time_text,
                packet.category,
                packet.protocol,
                packet.source,
                packet.destination,
                packet.bssid,
                packet.length,
                packet.info,
            ])
