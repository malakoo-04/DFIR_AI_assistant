from pathlib import Path

from modules.parsers.browser.browser_parser import BrowserParser

parser = BrowserParser()

records = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/Users/ahmed/AppData/Local/Microsoft/Edge/User Data/Default/History"
    )

)

print(f"Nombre d'entrées : {len(records)}")

for r in records[:5]:

    print(r)
    