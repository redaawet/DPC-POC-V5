import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Ensure local ``token`` package is importable even if stdlib ``token`` was loaded first.
std_token = sys.modules.get("token")
if std_token is not None and not hasattr(std_token, "__path__"):
    del sys.modules["token"]
