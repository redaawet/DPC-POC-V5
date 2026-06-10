from __future__ import annotations

from importlib import import_module
from pathlib import Path
import traceback
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


TESTS = [
    ("T1", "Max offline hops enforcement", "tests.t1_max_hops"),
    ("T2", "Wallet balance cap", "tests.t2_balance_cap"),
    ("T3", "Single-transaction value cap", "tests.t3_tx_value_cap"),
    ("T4", "Token TTL expiry", "tests.t4_ttl_expiry"),
    ("T5", "Proxy synchronization (TTL reset)", "tests.t5_proxy_sync"),
    ("T6", "Token lifecycle reset (circular spend)", "tests.t6_lifecycle_reset"),
    ("T7", "Swap protocol - change generation", "tests.t7_swap_change"),
    ("T8", "Double-spend prevention (first claim)", "tests.t8_double_spend"),
]


def main() -> int:
    results: list[tuple[str, str, bool]] = []
    for test_id, objective, module_name in TESTS:
        try:
            print(f"[Runner] Starting {test_id}: {objective}")
            passed = bool(import_module(module_name).run())
        except Exception:
            passed = False
            print(f"[Runner] {test_id} raised an exception:")
            print(traceback.format_exc())
        results.append((test_id, objective, passed))

    print("[Runner] Functional Test Summary")
    print("+------+-------------------------------------------+--------+")
    print("| Test | Objective                                 | Result |")
    print("+------+-------------------------------------------+--------+")
    for test_id, objective, passed in results:
        print(f"| {test_id:<4} | {objective:<41} | {'PASS' if passed else 'FAIL':<6} |")
    print("+------+-------------------------------------------+--------+")
    passed_count = sum(1 for _, _, passed in results if passed)
    print(f"[Runner] All {passed_count}/8 tests passed.")
    return 0 if passed_count == len(TESTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
