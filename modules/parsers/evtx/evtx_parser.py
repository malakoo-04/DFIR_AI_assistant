from pathlib import Path

from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime
from modules.parsers.base_parser import BaseParser


class EVTXParser(BaseParser):
    """
    Parser des journaux Windows (.evtx).
    """

    def parse(self, artifact_path: Path) -> list[dict]:
        events = []
        try:
            with Evtx(str(artifact_path)) as log:
                for chunk in log.chunks():
                    try:
                        for record in chunk.records():
                            try:
                                xml = record.xml()

                                root = ET.fromstring(xml)

                                ns = {
                                    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                                }

                                system = root.find("e:System", ns)

                                event_id = None
                                provider = None
                                timestamp = None
                                computer = None
                                channel = None

                                if system is not None:

                                    eid = system.find("e:EventID", ns)

                                    if eid is not None:
                                        event_id = int(eid.text)

                                    prov = system.find("e:Provider", ns)

                                    if prov is not None:
                                        provider = prov.attrib.get("Name")

                                    time = system.find("e:TimeCreated", ns)

                                    if time is not None:

                                        ts = time.attrib.get("SystemTime")

                                        if ts:
                                            timestamp = datetime.fromisoformat(
                                                ts.replace("Z", "+00:00")
                                            )

                                    comp = system.find("e:Computer", ns)

                                    if comp is not None:
                                        computer = comp.text

                                    chan = system.find("e:Channel", ns)

                                    if chan is not None:
                                        channel = chan.text

                                events.append({

                                    "artifact_type": "evtx",

                                    "source_path": str(artifact_path),

                                    "record_id": record.record_num(),

                                    "event_id": event_id,

                                    "provider": provider,

                                    "timestamp": timestamp,

                                    "computer": computer,

                                    "channel": channel,

                                    "xml": xml,

                                })
                            except Exception as e:
                                continue  # skip bad record, keep the rest
                    except Exception as e:
                        continue  # skip bad chunk, keep the rest
            return events
        except Exception as e:
            return self.handle_error(artifact_path, e)