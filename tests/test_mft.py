from pathlib import Path

from modules.parsers.mft.mft_parser import MFTParser

parser = MFTParser()

records=parser.parse(

    Path("input/KAPE_OUTPUT/C/$MFT")

)
print(records)

print(f"Nombre total : {len(records)}")

print(
    f"Fichiers : {sum(r['is_file'] for r in records)}"
)

print(
    f"Dossiers : {sum(r['is_directory'] for r in records)}"
)

print(
    f"Supprimés : {sum(not r['in_use'] for r in records)}"
)