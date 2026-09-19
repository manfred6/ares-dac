#!/usr/bin/env python3

from __future__ import annotations
from dataclasses import dataclass
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from pathlib import Path
import json
import logging
import os

from kibana import Kibana
from linter import Linter
from validator import Validator
from utils import artifacts, Markdown

logger = logging.getLogger(__name__)

@dataclass
class RuleResult:
    uuid: str
    name: str
    path: str
    rule_type: str
    lint: str
    validation: str


CA_CERT = Path("./artifacts/ares.crt")
ATTACK_PATH = Path("./artifacts/enterprise-attack.json")
ARTIFACTS_JSON = Path("./artifacts/meta.json")
RULES_PATH = Path("./rules/")
README_PATH = Path("./artifacts/README.md")

SUPPORTED_RULES = [
    "esql",
]

load_dotenv()

def init_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

def check_result(result: bool) -> str:
    return "OK" if result else "ERR"

def find_rule_file(rule_dir: Path, rule_type: str) -> Path:
    if rule_type == "sigma":
        candidates = list(rule_dir.glob("*.sigma.yml"))
    else:
        candidates = list(rule_dir.glob(f"*.{rule_type}"))

    if len(candidates) != 1:
        raise RuntimeError(f"Expected exactly one [{rule_type}] rule in [{rule_dir}], found [{len(candidates)}]")

    return candidates[0]

def build_desired_rules(kibana: Kibana, manifest: list[dict]) -> dict[str, dict]:
    # build desired kibana state from artifacts/meta.json
    #    {
    #        "<rule UUID>": <kibana API payload>,
    #        ...
    #    }
    desired = {}
    for entry in manifest:
        if entry["lint"] != "OK":
            raise RuntimeError(f"Refusing to deploy lint-failing rule [name: {entry['name']}, uuid: {entry['uuid']}]")

        if entry["validation"] != "OK":
            raise RuntimeError(f"Refusing to deploy invalid rule [name: {entry['name']}, uuid: {entry['uuid']}]")

        rule_dir = Path(entry["path"])
        metadata_path = rule_dir / "metadata.yml"
        metadata = artifacts.load(metadata_path, type="yaml")
        rule_id = metadata["uuid"]
        rule_type = entry["rule_type"]

        if rule_id != entry["uuid"]:
            raise RuntimeError(f"UUID mismatch between metadata.yml and meta.json for [{rule_dir}]")

        if rule_id in desired:
            raise RuntimeError(f"Duplicate deployable UUID [{rule_id}]")

        rule_file = find_rule_file(rule_dir, rule_type)
        query = rule_file.read_text(encoding="utf-8")
        payload = kibana.format_rule(metadata=metadata, query=query, rule_type=rule_type) # build the rule
        desired[rule_id] = payload # add it to payload

    return desired

def needs_update(desired: dict, current: dict) -> bool:
    # check if a rule differs in meta.json vs kibana
    for field, desired_value in desired.items():
        current_value = current.get(field)

        if field in {"tags", "references"}:
            desired_value = sorted(desired_value or [])
            current_value = sorted(current_value or [])

        if desired_value != current_value:
            logger.debug(f"Rule [name: {desired['rule_id']}, name: {desired['name']}] differs on [{field}]: {current_value} -> {desired_value}")
            return True

    return False

def reconcile(kibana: Kibana):
    # reconcile state in kibana with meta.json
    logger.info(f"Reading desired state from [{ARTIFACTS_JSON}]")
    manifest = json.loads(ARTIFACTS_JSON.read_text(encoding="utf-8"))
    desired = build_desired_rules(kibana,manifest)

    current = {
        rule["rule_id"]: rule
        for rule in kibana.get_managed_rules()
    }

    if not desired and current:
        raise RuntimeError("Desired state is empty while managed kibana rules exist")

    desired_ids = set(desired)
    current_ids = set(current)
    create_ids = desired_ids - current_ids
    delete_ids = current_ids - desired_ids
    common_ids = desired_ids & current_ids

    update_ids = {
        rule_id for rule_id in common_ids
        if needs_update(desired[rule_id], current[rule_id])
    }

    unchanged_ids = common_ids - update_ids

    logger.info(f"Reconciliation plan:\n\tCreate: {len(create_ids)}\n\tUpdate: {len(update_ids)}\n\tUnchanged: {len(unchanged_ids)}\n\tDelete: {len(delete_ids)}")

    # CREATE
    for rule_id in sorted(create_ids):
        kibana.create_rule(desired[rule_id])

    # UPDATE
    for rule_id in sorted(update_ids):
        kibana.update_rule(desired[rule_id])

    # DELETE (only managed rules)
    for rule_id in sorted(delete_ids):
        kibana.delete_rule(rule_name=current[rule_id].get("name", "Unknown"), rule_id=rule_id)

def main():
    results = []

    linter = Linter()
    validator = Validator()
    markdown = Markdown()

    pipeline_failed = False

    # es is used for query validation.
    es_client = Elasticsearch(
        os.environ["ELASTIC_URL"],
        api_key=os.environ["ELASTIC_API_KEY"],
        ca_certs=CA_CERT,
    )

    # LINT + VALIDATE
    files = RULES_PATH.rglob("metadata.yml")

    for file in files:
        rule_dir = file.parent
        if len(list(rule_dir.iterdir())) < 2:
            logger.warning(f"Rule path [{rule_dir}] has no rules in it")
            continue

        metadata = artifacts.load(path=file, type="yaml")
        lint_result = linter.validate(metadata)
        if not lint_result:
            logger.error(f"Failed to lint [{file}]")

            # do NOT reconcile with an incomplete desired state.
            pipeline_failed = True
            continue

        logger.info(f"Validated metadata.yml [{file}]")

        for rule in rule_dir.iterdir():
            if not rule.is_file():
                continue

            rule_type = rule.suffix.lstrip(".")
            if rule_type not in SUPPORTED_RULES:
                logger.warn(f"Rule [{rule}] with type {rule_type} is not supported (supported: {SUPPORTED_RULES})")
                continue

            rule_content = rule.read_text(encoding="utf-8")
            if not rule_content.strip():
                logger.error(f"Rule [{rule}] is empty")
                pipeline_failed = True
                continue

            validation_result = validator.validate(es_client, rule_content, rule_type, metadata["indices"])
            if not validation_result:
                pipeline_failed = True

            results.append(
                RuleResult(
                    uuid=metadata["uuid"],
                    name=metadata["name"],
                    path=str(rule_dir),
                    rule_type=rule_type,
                    lint=check_result(lint_result),
                    validation=check_result(validation_result)
                )
            )

    # GENERATE ARTIFACTS
    md = markdown.generate(results)
    markdown.write(md, README_PATH)
    artifacts.emit(results, ARTIFACTS_JSON)
    
    # never reconcile if linting/validation was incomplete
    if pipeline_failed:
        logger.error("Linting or validation failed. Skipping Kibana reconciliation.")
        return 1
    
    # KIBANA RECONCILIATION
    kibana = Kibana(
        endpoint=os.environ["KIBANA_URL"],
        api_key=os.environ["KIBANA_API_KEY"],
        ca_certs=CA_CERT,
        attack_path=ATTACK_PATH,
    )

    reconcile(kibana)

    logger.info("DaC pipeline completed successfully")

    return 0

if __name__ == "__main__":
    init_logging(logging.DEBUG)
    raise SystemExit(main())

