#!/use/bin/env python3

from __future__ import annotations
from pathlib import Path
import os
from linter import Linter

RULES_PATH = Path("./rules/")

def getRuleDirs():
    return [Path(x[0]) for x in os.walk(RULES_PATH)]

def getRuleFiles(dir):
    files = os.listdir(dir)
    return [
        Path(dir / f) for f in files if os.path.isfile(Path(dir / f))
    ]

def main():
    linter = Linter()
    dirs = getRuleDirs()
    for dir in dirs:
        files = getRuleFiles(dir)
        if len(files) < 2:
            continue
        if not Path(dir / "metadata.yml") in files:
            print(f"[!] -> Could not find metadata.yaml in {dir}")
            continue
        for file in files:
            if file.name == "metadata.yml":
                print(f"[i] -> Validating {file}")
                data = linter.load(file)
                if linter.validate(data):
                    print(f"[+] -> Validated {file}")
                else:
                    print(f"[!] -> Failed to validate {file}")

if __name__ == "__main__":
    main()
