"""guard/policy_loader.py -- read the policy file (YAML or JSON) into a plain dict."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_policy(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml   # PyYAML: pip install pyyaml
        except ImportError as exc:
            raise RuntimeError("Reading YAML needs PyYAML: pip install pyyaml") from exc
        data = yaml.safe_load(text)    # safe_load: never executes anything from the file
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{p}: policy file must contain a mapping at the top level")
    return data
