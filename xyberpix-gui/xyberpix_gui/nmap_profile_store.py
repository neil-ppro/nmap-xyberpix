"""Saved Nmap scan profiles (JSON in QSettings)."""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import QSettings

_STORE_KEY = "nmap/profiles_v2"


def _empty_store() -> dict[str, Any]:
    return {"order": [], "profiles": {}}


def load_store(settings: QSettings) -> dict[str, Any]:
    raw = settings.value(_STORE_KEY, "", str)
    if not raw.strip():
        return _empty_store()
    try:
        d = json.loads(raw)
        if not isinstance(d, dict):
            return _empty_store()
        d.setdefault("order", [])
        d.setdefault("profiles", {})
        if not isinstance(d["order"], list):
            d["order"] = []
        if not isinstance(d["profiles"], dict):
            d["profiles"] = {}
        return d
    except json.JSONDecodeError:
        return _empty_store()


def save_store(settings: QSettings, store: dict[str, Any]) -> None:
    settings.setValue(_STORE_KEY, json.dumps(store, separators=(",", ":")))


def list_names(settings: QSettings) -> list[str]:
    store = load_store(settings)
    return [n for n in store["order"] if n in store["profiles"]]


def get_profile(settings: QSettings, name: str) -> dict[str, Any] | None:
    store = load_store(settings)
    p = store["profiles"].get(name)
    return dict(p) if isinstance(p, dict) else None


def put_profile(settings: QSettings, name: str, state: dict[str, Any]) -> None:
    store = load_store(settings)
    name = name.strip()
    if not name:
        return
    if name not in store["order"]:
        store["order"].append(name)
    store["profiles"][name] = state
    save_store(settings, store)


def delete_profile(settings: QSettings, name: str) -> None:
    store = load_store(settings)
    store["order"] = [n for n in store["order"] if n != name]
    store["profiles"].pop(name, None)
    save_store(settings, store)
