from copy import deepcopy
from typing import Dict, Any

BASE_THRESHOLD_PROFILE: Dict[str, Dict[str, Any]] = {
    "keystroke": {
        "idle_mouse_seconds": 120,
        "fast_typing_kpm": 300,
        "continuous_typing_seconds": 600,
        "pause_reset_seconds": 3,
        "hidden_input_check_interval": 2,
    },
    "application": {
        "app_cpu_percent": 80,
        "app_cpu_duration_seconds": 30,
        "background_cpu_percent": 50,
        "process_count": 100,
        "system_cpu_percent": 90,
        "system_cpu_duration_seconds": 60,
        "spyglass_cpu_percent": 10,
    },
    "screenshot": {
        "screenshots_per_minute": 5,
    },
    "privacy": {
        "simultaneous_heavy_features": 3,
    },
    "alerting": {
        "cooldown_seconds": 30,
    },
}

PROFILE_OVERRIDES: Dict[str, Dict[str, Dict[str, Any]]] = {
    "LOW": {
        "keystroke": {
            "idle_mouse_seconds": 180,
            "fast_typing_kpm": 400,
            "continuous_typing_seconds": 900,
        },
        "application": {
            "app_cpu_percent": 90,
            "app_cpu_duration_seconds": 45,
            "background_cpu_percent": 60,
            "process_count": 125,
            "system_cpu_percent": 95,
            "system_cpu_duration_seconds": 75,
            "spyglass_cpu_percent": 15,
        },
        "alerting": {
            "cooldown_seconds": 45,
        },
    },
    "MEDIUM": {},
    "HIGH": {
        "keystroke": {
            "idle_mouse_seconds": 90,
            "fast_typing_kpm": 250,
            "continuous_typing_seconds": 480,
            "pause_reset_seconds": 2,
        },
        "application": {
            "app_cpu_percent": 70,
            "app_cpu_duration_seconds": 20,
            "background_cpu_percent": 45,
            "process_count": 90,
            "system_cpu_percent": 85,
            "system_cpu_duration_seconds": 45,
            "spyglass_cpu_percent": 8,
        },
        "alerting": {
            "cooldown_seconds": 20,
        },
    },
}


def deep_update(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_update(base[key], value)
        else:
            base[key] = value
    return base


class ThresholdEngine:
    def __init__(self, monitoring_level: str = "MEDIUM", overrides: Dict[str, Any] | None = None):
        self.monitoring_level = (monitoring_level or "MEDIUM").upper()
        self.overrides = overrides or {}

    def get_thresholds(self) -> Dict[str, Dict[str, Any]]:
        profile = deepcopy(BASE_THRESHOLD_PROFILE)
        deep_update(profile, PROFILE_OVERRIDES.get(self.monitoring_level, {}))
        deep_update(profile, self.overrides)
        return profile
