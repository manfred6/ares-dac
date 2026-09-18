#!/use/bin/env python3

from __future__ import annotations
from pathlib import Path
import os
from linter import Linter

RULES_PATH = Path("./rules/")

def main():
    linter = Linter()

    files = RULES_PATH.rglob("metadata.yml")
    for file in files:
        if (len(os.listdir(Path(file.parent))) < 2):
            continue
        metadata = linter.load(file)
        if linter.validate(metadata):
            print(f"[+] -> Validated metadata [{file}]")
        else:
            print(f"[!] -> Failed to validate metadata [{file}]")

   if __name__ == "__main__":
    main()
