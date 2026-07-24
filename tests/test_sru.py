from pathlib import Path

from modules.parsers.sru.sru_parser import SRUParser

parser = SRUParser()

records = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/Windows/System32/sru/SRUDB.dat"
    )

)

print("Nombre de records :", len(records))

for r in records[:5]:

    print(r)