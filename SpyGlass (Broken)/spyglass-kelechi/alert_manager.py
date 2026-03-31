import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class AlertEvent:
    category: str
    message: str
    severity: str
    module: str
    user_id: str
    app_name: str = "Unknown"
    exe_path: str = "Unknown"
    threshold_name: Optional[str] = None
    threshold_value: Optional[float] = None
    observed_value: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


class AlertManager:
    def __init__(self, database=None, user_id: Optional[str] = None, cooldown_seconds: int = 30, popup_enabled: bool = True):
        self.database = database
        self.user_id = user_id or "unknown_user"
        self.cooldown_seconds = max(int(cooldown_seconds), 1)
        self.popup_enabled = popup_enabled
        self._last_alert_times: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def update_context(self, *, database=None, user_id: Optional[str] = None, cooldown_seconds: Optional[int] = None) -> None:
        if database is not None:
            self.database = database
        if user_id:
            self.user_id = user_id
        if cooldown_seconds is not None:
            self.cooldown_seconds = max(int(cooldown_seconds), 1)

    def trigger_alert(
        self,
        *,
        category: str,
        message: str,
        severity: str = "medium",
        module: str = "system",
        key: Optional[str] = None,
        app_name: str = "Unknown",
        exe_path: str = "Unknown",
        threshold_name: Optional[str] = None,
        threshold_value: Optional[float] = None,
        observed_value: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        now = datetime.now()
        alert_key = key or f"{module}:{category}:{app_name}"

        with self._lock:
            previous = self._last_alert_times.get(alert_key)
            if previous and (now - previous).total_seconds() < self.cooldown_seconds:
                return False
            self._last_alert_times[alert_key] = now

        event = AlertEvent(
            category=category,
            message=message,
            severity=severity,
            module=module,
            user_id=self.user_id,
            app_name=app_name or "Unknown",
            exe_path=exe_path or "Unknown",
            threshold_name=threshold_name,
            threshold_value=threshold_value,
            observed_value=observed_value,
            metadata=metadata or {},
        )

        logging.warning(
            "[%s] %s | module=%s | app=%s | observed=%s | threshold=%s",
            event.severity.upper(),
            event.message,
            event.module,
            event.app_name,
            event.observed_value,
            event.threshold_value,
        )
        self._persist_event(event)
        self._show_popup(event)
        return True

    def _persist_event(self, event: AlertEvent) -> None:
        if not self.database or not getattr(self.database, "connection", None):
            return

        try:
            cursor = self.database.connection.cursor()
            cursor.execute(
                """
                INSERT INTO application (appName, executablePath, vendor)
                VALUES (?, ?, ?)
                ON CONFLICT(executablePath) DO UPDATE SET
                    appName = excluded.appName,
                    vendor = excluded.vendor
                """,
                (event.app_name, event.exe_path, "Spyglass Monitor"),
            )
            self.database.connection.commit()

            cursor.execute(
                "SELECT appID FROM application WHERE executablePath = ? LIMIT 1",
                (event.exe_path,),
            )
            app_row = cursor.fetchone()
            if not app_row:
                cursor.close()
                return
            app_id = int(app_row[0])

            threshold_id = self._ensure_threshold(cursor, app_id, event.threshold_name, event.threshold_value)

            cursor.execute(
                """
                INSERT INTO alert (userID, appID, thresholdID, alertType, severity, dismissed, resolved)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event.user_id, app_id, threshold_id, event.category, event.severity, None, 0),
            )
            cursor.execute(
                """
                INSERT INTO activity_log (userID, appID, action, category, reason, duration)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event.user_id, app_id, "threshold_alert", event.module, event.message, None),
            )
            self.database.connection.commit()
            cursor.close()
        except Exception as exc:
            logging.error("Failed to persist alert to database: %s", exc, exc_info=True)

    def _ensure_threshold(self, cursor, app_id: int, threshold_name: Optional[str], threshold_value: Optional[float]) -> int:
        threshold_name = threshold_name or "generic_threshold"
        threshold_value_int = int(threshold_value) if threshold_value is not None else None

        if threshold_name in {"fast_typing_kpm"}:
            max_keystrokes_per_min = threshold_value_int
            max_screen_access_per_hour = None
            max_runtime_minutes = None
        elif threshold_name in {"screenshots_per_minute"}:
            max_keystrokes_per_min = None
            max_screen_access_per_hour = threshold_value_int * 60 if threshold_value_int is not None else None
            max_runtime_minutes = None
        elif threshold_name in {"app_cpu_duration_seconds", "system_cpu_duration_seconds", "continuous_typing_seconds"}:
            max_keystrokes_per_min = None
            max_screen_access_per_hour = None
            max_runtime_minutes = max(1, int((threshold_value or 0) / 60)) if threshold_value is not None else None
        else:
            max_keystrokes_per_min = None
            max_screen_access_per_hour = None
            max_runtime_minutes = None

        cursor.execute(
            """
            INSERT INTO privacy_threshold (appID, maxKeystrokesPerMin, maxScreenAccessPerHour, maxRuntimeMinutes)
            VALUES (?, ?, ?, ?)
            """,
            (app_id, max_keystrokes_per_min, max_screen_access_per_hour, max_runtime_minutes),
        )
        return int(cursor.lastrowid)

    def _show_popup(self, event: AlertEvent) -> None:
        if not self.popup_enabled:
            return

        def _popup() -> None:
            try:
                import ctypes

                text = (
                    f"SpyGlass Alert\n\n"
                    f"Category: {event.category}\n"
                    f"Severity: {event.severity.upper()}\n"
                    f"Module: {event.module}\n"
                    f"Application: {event.app_name}\n\n"
                    f"{event.message}"
                )
                ctypes.windll.user32.MessageBoxW(0, text, "SpyGlass Alert", 0x1000)
            except Exception:
                logging.info("Popup unavailable; alert shown in console/log only.")

        threading.Thread(target=_popup, daemon=True).start()
