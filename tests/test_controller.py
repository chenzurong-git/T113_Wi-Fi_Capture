from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from t113cap.controller import CaptureConfig, StreamCaptureSession, build_start_script, build_stream_command


class ControllerScriptTests(unittest.TestCase):
    def test_manual_script_contains_monitor_and_output(self) -> None:
        script = build_start_script(CaptureConfig(channel=6))
        self.assertIn("/usr/sbin/tcpdump", script)
        self.assertIn("start-stop-daemon", script)
        self.assertIn("exec /usr/sbin/tcpdump", script)
        self.assertIn("-w '/tmp/t113_wifi_capture.pcap'", script)
        self.assertIn("T113CAP_STARTED", script)

    def test_count_and_duration_limits(self) -> None:
        count_script = build_start_script(CaptureConfig(mode="count", packet_count=321))
        self.assertIn("-c 321", count_script)
        duration_script = build_start_script(CaptureConfig(mode="duration", duration_sec=45))
        self.assertIn("-G 45 -W 1", duration_script)

    def test_filter_is_shell_quoted(self) -> None:
        script = build_start_script(CaptureConfig(bpf_filter="type mgt and wlan addr1 00:11:22:33:44:55"))
        self.assertIn("FILTER='type mgt and wlan addr1 00:11:22:33:44:55'", script)

    def test_stream_command_writes_pcap_to_stdout(self) -> None:
        command = build_stream_command(CaptureConfig(mode="count", packet_count=12))
        self.assertIn("-w -", command)
        self.assertIn("-c 12", command)
        self.assertIn("/usr/sbin/tcpdump", command)
        self.assertIn("| base64", command)

    def test_invalid_newline_filter_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_start_script(CaptureConfig(bpf_filter="type mgt\nrm -rf /tmp/x"))

    def test_stream_stop_waits_for_trailing_payload(self) -> None:
        payload = b"pcap-header-and-last-packet" * 8
        encoded = base64.b64encode(payload).decode("ascii")
        script = (
            "import base64,sys,time; "
            "data=base64.b64decode('{}'); "
            "sys.stdout.buffer.write(data[:37]); sys.stdout.buffer.flush(); "
            "time.sleep(1.0); "
            "sys.stdout.buffer.write(data[37:]); sys.stdout.buffer.flush()"
        ).format(encoded)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "stream.pcap"
            process = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            session = StreamCaptureSession(process, path)
            time.sleep(0.2)
            started = time.monotonic()
            session.stop(grace_timeout=3.0)
            elapsed = time.monotonic() - started
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
            self.assertGreaterEqual(elapsed, 0.7)
            self.assertEqual(path.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
