from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
OUT_PATH = BASE_DIR / "test_samples" / "high_entropy.bin"


def main() -> None:
    # 1 MB random bytes (high entropy)
    size = 1 * 1024 * 1024
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_bytes(os.urandom(size))
    print(f"Wrote: {OUT_PATH} ({size} bytes)")


if __name__ == "__main__":
    main()

