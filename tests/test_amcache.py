from yarp import Registry
from pathlib import Path

from modules.parsers.amcache import AmcacheParser

parser = AmcacheParser()

records = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/Windows/AppCompat/Programs/Amcache.hve"
    )

)

print(records)
    