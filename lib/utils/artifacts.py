#!/usr/bin/env python3

from __future__ import annotations
from typing import List, Dict, Any
from dataclasses import asdict
import os
import sys
import logging
import json
import yaml

logger = logging.getLogger(__name__)

def load(path, type = "yaml"):
    if type == "yaml":
        logger.debug(f"Attempting to load YAML from [{path}]")
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            logger.debug(f"Successfully loaded [{path}]")
            return data

    return None

def emit(data, path, type = "json"):
    if type == "json":
        logger.info(f"Attempting to emit artifacts json to {path}")
        with path.open("w", encoding="utf-8") as f:
            json.dump(
                [asdict(d) for d in data],
                f,
                indent=2,
            )

if __name__ == "__main__":
    print("[!] -> This module is meant to be imported")
    sys.exit(1)

