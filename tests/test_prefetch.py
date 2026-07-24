from pathlib import Path

from modules.parsers.prefetch.prefetch_parser import PrefetchParser


parser = PrefetchParser()

records = parser.parse(

    Path("input/KAPE_OUTPUT/C/Windows/prefetch/APPLICATIONFRAMEHOST.EXE-CCEEF759.pf")

)

print(records)