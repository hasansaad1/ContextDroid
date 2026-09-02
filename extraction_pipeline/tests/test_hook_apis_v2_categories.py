"""Verify hook_apis v2 categories count as meaningful in parse_logs quality gates."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from parse_logs import parse_frida_jsonl  # noqa: E402

V2_SAMPLE_EVENTS = [
    ("SharedPreferences.getString", "storage"),
    ("SQLiteDatabase.rawQuery", "database"),
    ("MediaPlayer.start", "media"),
    ("Context.startActivity", "navigation"),
    ("WebView.loadUrl", "webview"),
    ("NotificationManager.notify", "notifications"),
    ("ContentResolver.insert", "content_access"),
    ("retrofit2.OkHttpCall.execute", "network"),
]


class TestHookApisV2Categories(unittest.TestCase):
    def test_v2_categories_are_meaningful(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sample.jsonl"
            lines = [
                json.dumps(
                    {
                        "type": "event",
                        "timestamp": 1000 + i,
                        "api": api,
                        "category": category,
                        "args": {},
                    }
                )
                for i, (api, category) in enumerate(V2_SAMPLE_EVENTS)
            ]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            _events, quality = parse_frida_jsonl(log_path)

            self.assertEqual(quality["valid_events"], len(V2_SAMPLE_EVENTS))
            self.assertEqual(quality["meaningful_events"], len(V2_SAMPLE_EVENTS))
            self.assertGreaterEqual(quality["meaningful_categories"], 2)


if __name__ == "__main__":
    unittest.main()
