# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os

import yaml

REQUIRED_COLLECTION_KEYS = {"meta", "credentials", "vscode", "git", "propagation", "environment"}


def load_collection(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"collection.json inválido: {e}") from e
    except PermissionError as e:
        raise PermissionError(
            f"Sem permissão para ler {path!r} — "
            f"verifique se o arquivo pertence ao usuário correto: {e}"
        ) from e
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Arquivo não encontrado: {path!r}: {e}") from e
    except OSError as e:
        raise OSError(f"Erro de I/O ao ler {path!r}: {e}") from e

    missing = REQUIRED_COLLECTION_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"collection.json sem chaves obrigatórias: {', '.join(sorted(missing))}")

    return data


def _load_yaml(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Definição YAML inválida {path!r}: {e}") from e
    except PermissionError as e:
        raise PermissionError(
            f"Sem permissão para ler {path!r} — "
            f"verifique se o arquivo pertence ao usuário correto: {e}"
        ) from e
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Arquivo de definições não encontrado: {path!r}: {e}") from e
    except OSError as e:
        raise OSError(f"Erro de I/O ao ler {path!r}: {e}") from e


def load_definitions(definitions_dir: str) -> dict:
    creds_path = os.path.join(definitions_dir, "credentials.yaml")
    prop_path = os.path.join(definitions_dir, "propagation.yaml")

    creds = _load_yaml(creds_path)
    prop = _load_yaml(prop_path)

    return {"credentials": creds.get("credentials", []), "propagation": prop.get("propagation", {})}
