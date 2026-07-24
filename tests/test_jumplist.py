from pathlib import Path

from modules.parsers.jumplist.jumplist_parser import JumpListParser


parser = JumpListParser()

records = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/Users/ahmed/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms"
    )

)

print(f"Nombre d'entrées : {len(records)}")

for entry in records:

    print(entry)