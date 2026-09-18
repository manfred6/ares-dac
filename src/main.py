#!/use/bin/env python3

from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os
import logging

from linter import Linter
from validator import Validator
from utils import artifacts, Markdown

@dataclass
class RuleResult:
    name: str
    path: str
    rule_type: str
    lint: str
    validation: str
    #tests: str

CA_CERT = Path("./artifacts/ares.crt")
ARTIFACTS_JSON = Path("./artifacts/meta.json")
RULES_PATH = Path("./rules/")
MD_PATH = Path("./artifacts/")
SUPPORTED_RULES = [
        "esql"
]

load_dotenv()

def init_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

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
    results = list()
    linter = Linter()
    markdown = Markdown()
    validator = Validator()
    es_client = Elasticsearch(
        os.environ["ELASTIC_URL"],
        api_key=os.environ["ELASTIC_API_KEY"],
        ca_certs=CA_CERT
    )

    files = RULES_PATH.rglob("metadata.yml")
    for file in files:
        rules_path = Path(file.parent)
        if (len(os.listdir(Path(file.parent))) < 2):
            logger.warn(f"Rule path [{Path(file.parent)}] has no rules in it")
            continue
        meta = artifacts.load(path = file, type = "yaml")
        linter_result = linter.validate(meta) 
        if linter_result:
            logger.info(f"Validated metadata.yml [{file}]")

        for rule in rules_path.iterdir():
            rule_type = rule.suffix.lstrip(".")

            if rule_type in SUPPORTED_RULES:
                rule_indices = meta["indices"]
                rule_content = rule.read_text()
                assert(len(rule_content) > 1)
                validate_result = validator.validate(
                        es_client, 
                        rule_content, 
                        rule_type, 
                        rule_indices
                )
                results.append(
                    RuleResult(
                        name=meta["name"],
                        path=str(file.parent),
                        rule_type=rule_type,
                        lint=check_result(linter_result),
                        validation=check_result(validate_result)
                    )
                )

    md = markdown.generate(results)
    markdown.write(md, Path("./artifacts/README.md"))
    artifacts.emit(results, ARTIFACTS_JSON)


if __name__ == "__main__":
    init_logging(logging.DEBUG)
    logger = logging.getLogger(__name__)
    main()
