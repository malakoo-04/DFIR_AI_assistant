
from dfir_ntfs import Attributes
from dfir_ntfs import USN
from pathlib import Path

from modules.parsers.usn import USNParser

parser = USNParser()

records = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/$Extend/$J"
    )

)

print(records)
    