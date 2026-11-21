from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from t113cap import settings


class SettingsTests(unittest.TestCase):
    def test_default_output_is_beside_application(self) -> None:
        self.assertEqual(settings.default_output_dir(), settings.application_dir() / "captures")

    def test_legacy_output_path_is_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            portable = root / "T113Capture.settings.json"
            legacy = root / "legacy" / "settings.json"
            captures = root / "app" / "captures"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(
                json.dumps(
                    {
                        "serial": "20260630",
                        "channel": 11,
                        "output_dir": r"C:\Users\example\Documents\T113Captures",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(settings, "portable_settings_path", return_value=portable):
                with mock.patch.object(settings, "legacy_settings_path", return_value=legacy):
                    with mock.patch.object(settings, "_default_output_dir", return_value=str(captures)):
                        loaded = settings.load_settings()
            self.assertEqual(loaded.serial, "20260630")
            self.assertEqual(loaded.channel, 11)
            self.assertEqual(loaded.output_dir, str(captures))
            saved = json.loads(portable.read_text(encoding="utf-8"))
            self.assertEqual(saved["_settings_version"], settings.SETTINGS_VERSION)
            self.assertEqual(saved["output_dir"], str(captures))


if __name__ == "__main__":
    unittest.main()
