from pathlib import Path

from modules.parsers.evtx.evtx_parser import EVTXParser

parser = EVTXParser()

events = parser.parse(
    Path("input/KAPE_OUTPUT/C/Windows/System32/winevt/Logs/Security.evtx")
)

print(len(events))
print(events[:10])





