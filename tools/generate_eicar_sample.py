from __future__ import annotations

import base64
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
OUT_PATH = BASE_DIR / "test_samples" / "eicar.com.txt"

# EICAR string encoded to avoid AV quarantine in-repo
EICAR_B64 = (
    "WDVPIVAlQEFQWzRcUFpYNTRQUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
)


def main() -> None:
    raw = base64.b64decode(EICAR_B64).decode("ascii")
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(raw + "\n", encoding="ascii")
    print(f"Wrote: {OUT_PATH}")
    print("Note: Some antivirus tools may quarantine this file immediately (expected).")


if __name__ == "__main__":
    main()

