from pathlib import Path
import sqlite3

from modules.parsers.base_parser import BaseParser
from modules.utils.time_utils import TimeUtils


class BrowserParser(BaseParser):
    """
    Parser des bases History Chromium (Edge/Chrome).
    """

    def parse(self, artifact_path: Path) -> list[dict]:

        results = []

        conn = sqlite3.connect(artifact_path)

        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        browser = self._detect_browser(artifact_path)

        if browser == "firefox":
            try:
                return self._parse_firefox_history(cursor, artifact_path)
            finally:
                conn.close()

        # ==========================
        # HISTORY
        # ==========================

        cursor.execute("""

            SELECT

                urls.url,
                urls.title,
                urls.visit_count,
                urls.typed_count,
                urls.last_visit_time,

                visits.visit_time,
                visits.transition,
                visits.visit_duration

            FROM urls

            JOIN visits

            ON urls.id = visits.url

        """)

        for row in cursor.fetchall():

            results.append({

                "artifact_type": "browser",

                "browser": browser,

                "record_type": "history",

                "url": row["url"],

                "title": row["title"],

                "visit_count": row["visit_count"],

                "typed_count": row["typed_count"],

                "visit_time": TimeUtils.chrome_time_to_datetime(
                    row["visit_time"]
                ),

                "last_visit_time": TimeUtils.chrome_time_to_datetime(
                    row["last_visit_time"]
                ),

                "transition": row["transition"],

                "visit_duration": row["visit_duration"],

                "source_path": str(artifact_path)

            })

        # ==========================
        # DOWNLOADS
        # ==========================

        cursor.execute("""

            SELECT *

            FROM downloads

        """)

        for row in cursor.fetchall():

            results.append({

                "artifact_type": "browser",

                "browser": browser,

                "record_type": "download",

                "current_path": row["current_path"],

                "target_path": row["target_path"],

                "start_time": TimeUtils.chrome_time_to_datetime(
                    row["start_time"]
                ),

                "end_time": TimeUtils.chrome_time_to_datetime(
                    row["end_time"]
                ),

                "received_bytes": row["received_bytes"],

                "total_bytes": row["total_bytes"],

                "state": row["state"],

                "danger_type": row["danger_type"],

                "referrer": row["referrer"],

                "site_url": row["site_url"],

                "tab_url": row["tab_url"],

                "mime_type": row["mime_type"],

                "source_path": str(artifact_path)

            })

        conn.close()

        return results

    def _parse_firefox_history(self, cursor, artifact_path: Path) -> list[dict]:
        """Parse Firefox places.sqlite, whose tables differ from Chromium."""
        cursor.execute("""
            SELECT p.url, p.title, p.visit_count, p.typed, p.last_visit_date,
                   h.visit_date, h.visit_type
            FROM moz_places AS p
            JOIN moz_historyvisits AS h ON p.id = h.place_id
        """)
        return [{
            "artifact_type": "browser", "browser": "firefox", "record_type": "history",
            "url": row["url"], "title": row["title"],
            "visit_count": row["visit_count"], "typed_count": row["typed"],
            "visit_time": TimeUtils.unix_to_datetime(row["visit_date"] / 1_000_000) if row["visit_date"] else None,
            "last_visit_time": TimeUtils.unix_to_datetime(row["last_visit_date"] / 1_000_000) if row["last_visit_date"] else None,
            "transition": row["visit_type"], "visit_duration": None,
            "source_path": str(artifact_path),
        } for row in cursor.fetchall()]
    def _detect_browser(self, path: Path) -> str:

        p = str(path).lower()

        if "edge" in p:
            return "edge"

        if "chrome" in p:
            return "chrome"

        if "firefox" in p:
            return "firefox"

        return "unknown"