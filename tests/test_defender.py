from pathlib import Path

from modules.parsers.defender.defender_parser import DefenderParser


parser = DefenderParser()

# ==========================
# MPLog
# ==========================

results = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/ProgramData/Microsoft/Windows Defender/support/MPLog-20240502-104921.log"
    )

)

print("=" * 60)
print("MPLOG")
print("=" * 60)

print(f"Nombre d'événements : {len(results)}")

for record in results[:5]:
    print(record)


print()

# ==========================
# MPDetection
# ==========================

results = parser.parse(

    Path(
        "input/KAPE_OUTPUT/C/ProgramData/Microsoft/Windows Defender/support/MPDetection-20240502-104921.log"
    )

)

print("=" * 60)
print("MPDETECTION")
print("=" * 60)

print(f"Nombre d'événements : {len(results)}")

for record in results[:5]:
    print(record)