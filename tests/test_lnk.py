from pathlib import Path

from modules.parsers.lnk.lnk_parser import LNKParser


parser = LNKParser()

records = parser.parse(

    Path("input/KAPE_OUTPUT/C/Users/ahmed/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/OneDrive.lnk")

)

print(records)