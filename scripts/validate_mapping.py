"""CI check: the mapping file is valid and strictly 1:1. Exits non-zero on any problem."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mapping import MappingError, load_mapping  # noqa: E402


def main() -> int:
    try:
        mapping = load_mapping(ROOT / "mapping" / "mapping.json")
    except MappingError as exc:
        print("mapping.json is INVALID:")
        for problem in exc.problems:
            print(f"  - {problem}")
        return 1
    print(f"mapping.json OK: {len(mapping.mappings)} group(s)")
    for m in mapping.mappings:
        print(f"  {m.group} -> {m.permission_set_name} ({', '.join(m.managed_policies)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
