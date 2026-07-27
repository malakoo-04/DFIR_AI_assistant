from pathlib import Path
import re
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
                                command_line = None

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

                                event_data = root.find("e:EventData", ns)

                                script_name = None
                                host_application = None
                                command_summary = None

                                if event_data is not None:

                                    for data in event_data.findall("e:Data", ns):

                                        if data.attrib.get("Name") == "CommandLine":
                                            command_line = data.text
                                            break

                                    # Event 800 ("PowerShell" provider, legacy
                                    # "Windows PowerShell" channel): its single
                                    # <Data> has no Name attribute at all, so
                                    # the loop above never matches it -- it
                                    # needs its own dedicated parser instead.
                                    if event_id == 800:
                                        data_el = event_data.find("e:Data", ns)
                                        if data_el is not None and data_el.text:
                                            details = self._parse_pipeline_execution_details(
                                                data_el.text
                                            )
                                            script_name = details.get("ScriptName") or None
                                            host_application = details.get("HostApplication")
                                            command_summary = details.get("command_summary")
                                            # Richer than the generic extraction
                                            # above, which never matches here.
                                            command_line = details.get("CommandLine") or command_line

                                events.append({

                                    "artifact_type": "evtx",

                                    "source_path": str(artifact_path),

                                    "record_id": record.record_num(),

                                    "event_id": event_id,

                                    "provider": provider,

                                    "timestamp": timestamp,

                                    "computer": computer,

                                    "channel": channel,

                                    "command_line": command_line,

                                    "script_name": script_name,

                                    "host_application": host_application,

                                    "command_summary": command_summary,

                                    "xml": xml,

                                })
                            except Exception as e:
                                continue  # skip bad record, keep the rest
                    except Exception as e:
                        continue  # skip bad chunk, keep the rest
            return events
        except Exception as e:
            return self.handle_error(artifact_path, e)

    @staticmethod
    def _parse_pipeline_execution_details(raw_text: str) -> dict:
        """Parse a PowerShell Event 800 payload.

        The raw <Data> text (no Name attribute -- legacy "PowerShell" provider,
        channel "Windows PowerShell") contains two <string>...</string> blocks
        as literal text, not real XML child nodes: the first is a one-line
        command summary, the second is a "Key=Value" block (one pair per
        line) with the fields Event Viewer renders as "Context Information".
        Returns {} if the expected shape isn't found, rather than raising.
        """
        if not raw_text:
            return {}

        blocks = re.findall(r"<string>(.*?)</string>", raw_text, re.DOTALL)
        if not blocks:
            return {}

        result = {"command_summary": blocks[0].strip()}

        if len(blocks) < 2:
            return result

        for match in re.finditer(
            r"^[ \t]*(\w+)=(.*?)(?=\n[ \t]*\w+=|\Z)", blocks[1], re.DOTALL | re.MULTILINE
        ):
            key, value = match.group(1), match.group(2).strip()
            if value:
                result[key] = value

        return result