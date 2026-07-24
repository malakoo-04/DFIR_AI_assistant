import json
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import asdict, is_dataclass


class DateTimeEncoder(json.JSONEncoder):

    def default(self, obj):

        if isinstance(obj, datetime):
            return obj.isoformat()

        if isinstance(obj, Path):
            return str(obj)

        if isinstance(obj, Enum):
            return obj.value
        

        if isinstance(obj, bytes):
            try:
                return obj.decode("utf-8")
            except Exception:
                return obj.hex()
        
        if is_dataclass(obj) and not isinstance(obj, type):
                return asdict(obj)

        return super().default(obj)


def export_json(data, output_path):

    Path(output_path).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(output_path, "w", encoding="utf-8") as f:

        json.dump(
            data,
            f,
            cls=DateTimeEncoder,
            indent=4,
            ensure_ascii=False,
        )