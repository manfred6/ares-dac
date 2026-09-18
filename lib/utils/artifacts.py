#!/usr/bin/env python3

from __future__ import annotations
from typing import List, Dict, Any
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

def emit(self, data, type = "json"):
    return

if __name__ == "__main__":
    print("[!] -> This module is meant to be imported")
    sys.exit(1)

