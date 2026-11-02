"""CI check: the mapping is valid, strictly 1:1, and passes the policy allow-list.

Exits non-zero on any problem, which stops the pull request.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from allowlist import load_allowlist, load_checked_mapping  # noqa: E402
from mapping import MappingError  # noqa: E402


def main() -> int:
    mapping_path = ROOT / "mapping" / "mapping.json"
    allowlist_path = ROOT / "mapping" / "policy-allowlist.json"
    try:
        mapping = load_checked_mapping(mapping_path, allowlist_path)
        allowlist = load_allowlist(allowlist_path)
    except MappingError as exc:
        print("mapping or allow-list is INVALID:")
        for problem in exc.problems:
            print(f"  - {problem}")
        return 1
    print(f"OK: {len(mapping.mappings)} rule(s), all policies allowed")
    for m in mapping.mappings:
        tiers = ", ".join(sorted({allowlist.policies[p].tier for p in m.managed_policies}))
        print(f"  {m.group} -> {m.permission_set_name} [{tiers}] {m.session_duration}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
