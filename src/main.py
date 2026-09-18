#!/use/bin/env python3

from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass
import os
import logging

from linter import Linter
from utils import artifacts

def init_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

@dataclass
class RuleResult:
    name: str
    path: str
    rule_type: str
    lint: str
    #validation: str
    #tests: str

RULES_PATH = Path("./rules/")
MD_PATH = Path("./artifacts/")

def check_result(result):
    return "OK" if result else "ERR"

def lint(linter, file):
    metadata = linter.load(file)
    if linter.validate(metadata):
        logger.info(f"Validated metadata [{file}]")
        return True
    else:
        logger.warn(f"Failed to validate metadata [{file}]")
        return False

def main():
    linter = Linter()
    results = list()
    files = RULES_PATH.rglob("metadata.yml")
    for file in files:
        if (len(os.listdir(Path(file.parent))) < 2):
            logger.warn(f"Rule path [{Path(file.parent)}] has no rules in it")
            continue
        meta = artifacts.load(path = file, type = "yaml")
        linter_result = linter.validate(meta) 
        if linter_result:
            logger.info(f"Validated metadata.yml [{file}]")

        results.append(
            RuleResult(
                name=meta["name"],
                path=str(file.parent),
                rule_type="none",
                lint=check_result(linter_result)
            )
        )

    print(results)

if __name__ == "__main__":
    init_logging(logging.DEBUG)
    logger = logging.getLogger(__name__)
    main()
