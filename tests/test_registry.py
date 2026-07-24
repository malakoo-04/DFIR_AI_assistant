from pathlib import Path
from datetime import datetime

from modules.parsers.registry.registry_parser import RegistryParser


parser = RegistryParser()

records = parser.parse(
    Path("input/KAPE_OUTPUT/C/Windows/System32/config/SYSTEM")
)

print(f"Nombre de clés : {len(records)}")

for record in records:

    ts = record["last_written"]

    if ts is not None:
        print("Key:", record["key_path"])
        print("Value:", ts)
        print("Type:", type(ts))
        print("Is datetime:", isinstance(ts, datetime))
        print("tzinfo:", ts.tzinfo)
        print("Timezone aware:", ts.tzinfo is not None)
        break