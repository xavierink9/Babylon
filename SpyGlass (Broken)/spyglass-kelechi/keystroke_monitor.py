import datetime
import logging
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, Optional

from pynput import keyboard, mouse


class KeystrokeMonitor:
    # Monitor keystrokes
    def __init__(
        self,
        time_interval: int = 60,
        log_file: str = "keystrokes.log",
        alert_manager=None,
        thresholds: Optional[Dict[str, Dict[str, Any]]] = None,
        active_app_provider: Optional[Callable[[], bool]] = None,
    ):
        print("Initializing KeystrokeMonitor...")
        self.running = False
        self.time_interval = time_interval
        self.log_file = log_file
        self.keystrokes: Dict[str, int] = {}
        self.lock = threading.Lock()
        self.interval_start = datetime.datetime.now()
        self.listener: Optional[keyboard.Listener] = None
        self.mouse_listener: Optional[mouse.Listener] = None
        self.last_key: Optional[str] = None
        self.alert_manager = alert_manager
        self.thresholds = thresholds or {}
        self.active_app_provider = active_app_provider

        self.key_timestamps = deque()
        now = time.time()
        self.last_keypress_time = now
        self.continuous_typing_start = now
        self.last_mouse_activity = now
        self.last_visibility_check = 0.0

    def configure(self, alert_manager=None, thresholds: Optional[Dict[str, Dict[str, Any]]] = None, active_app_provider=None) -> None:
        if alert_manager is not None:
            self.alert_manager = alert_manager
        if thresholds is not None:
            self.thresholds = thresholds
        if active_app_provider is not None:
            self.active_app_provider = active_app_provider

    def on_press(self, key):
        timestamp = time.time()
        try:
            keyStr = key.char
        except AttributeError:
            keyStr = str(key)

        with self.lock:
            self.keystrokes[keyStr] = self.keystrokes.get(keyStr, 0) + 1
            self.last_key = keyStr

        self.key_timestamps.append(timestamp)
        while self.key_timestamps and timestamp - self.key_timestamps[0] > 60:
            self.key_timestamps.popleft()

        self._update_continuous_typing(timestamp)
        self._evaluate_thresholds(timestamp)

    def on_click(self, x, y, button, pressed):
        self.last_mouse_activity = time.time()
        if pressed:
            with self.lock:
                self.keystrokes['Mouse Click'] = self.keystrokes.get('Mouse Click', 0) + 1

    def on_move(self, x, y):
        self.last_mouse_activity = time.time()

    def on_scroll(self, x, y, dx, dy):
        self.last_mouse_activity = time.time()

    def _update_continuous_typing(self, timestamp: float) -> None:
        keystroke_thresholds = self.thresholds.get("keystroke", {})
        pause_reset_seconds = keystroke_thresholds.get("pause_reset_seconds", 3)
        if timestamp - self.last_keypress_time > pause_reset_seconds:
            self.continuous_typing_start = timestamp
        self.last_keypress_time = timestamp

    def _evaluate_thresholds(self, timestamp: float) -> None:
        if not self.alert_manager:
            return

        keystroke_thresholds = self.thresholds.get("keystroke", {})
        if not keystroke_thresholds:
            return

        idle_mouse_seconds = keystroke_thresholds.get("idle_mouse_seconds", 120)
        if timestamp - self.last_mouse_activity >= idle_mouse_seconds:
            self.alert_manager.trigger_alert(
                category="Suspicious Activity",
                severity="high",
                module="keystroke_monitor",
                key="idle_typing",
                app_name="Keyboard Input",
                exe_path="INTERNAL::KEYSTROKE",
                threshold_name="idle_mouse_seconds",
                threshold_value=idle_mouse_seconds,
                observed_value=round(timestamp - self.last_mouse_activity, 1),
                message="Typing was detected while the system appeared idle with no mouse movement.",
            )

        current_kpm = len(self.key_timestamps)
        fast_typing_limit = keystroke_thresholds.get("fast_typing_kpm", 300)
        if current_kpm >= fast_typing_limit:
            self.alert_manager.trigger_alert(
                category="Automation / Bot Behavior",
                severity="high",
                module="keystroke_monitor",
                key="fast_typing_kpm",
                app_name="Keyboard Input",
                exe_path="INTERNAL::KEYSTROKE",
                threshold_name="fast_typing_kpm",
                threshold_value=fast_typing_limit,
                observed_value=current_kpm,
                message=f"Typing speed reached {current_kpm} keystrokes per minute.",
            )

        continuous_typing_seconds = keystroke_thresholds.get("continuous_typing_seconds", 600)
        continuous_duration = timestamp - self.continuous_typing_start
        if continuous_duration >= continuous_typing_seconds:
            self.alert_manager.trigger_alert(
                category="Abnormal Usage",
                severity="medium",
                module="keystroke_monitor",
                key="continuous_typing",
                app_name="Keyboard Input",
                exe_path="INTERNAL::KEYSTROKE",
                threshold_name="continuous_typing_seconds",
                threshold_value=continuous_typing_seconds,
                observed_value=round(continuous_duration, 1),
                message="Continuous typing was detected for an extended period without pause.",
            )

        visibility_interval = keystroke_thresholds.get("hidden_input_check_interval", 2)
        if self.active_app_provider and (timestamp - self.last_visibility_check) >= visibility_interval:
            self.last_visibility_check = timestamp
            try:
                visible_app_present = bool(self.active_app_provider())
            except Exception:
                visible_app_present = True
            if not visible_app_present:
                self.alert_manager.trigger_alert(
                    category="Hidden Input Activity",
                    severity="high",
                    module="keystroke_monitor",
                    key="hidden_input_activity",
                    app_name="Keyboard Input",
                    exe_path="INTERNAL::KEYSTROKE",
                    threshold_name="visible_active_application",
                    threshold_value=1,
                    observed_value=0,
                    message="Keystrokes were detected without a visible active application.",
                )

    def updateLog(self, string: str):
        self.interval_start = datetime.datetime.now()
        with open(self.log_file, 'a', encoding='utf-8') as l:
            l.write(f"{self.interval_start} - {string}\n")

    def updateDatabase(self, key):
        # update database with summary keystroke log
        with self.lock:
            self.keystrokes.clear()
            self.key_timestamps.clear()

    # requires admin privileges to run
    def startLog(self) -> bool:
        if self.running:
            print("Keystroke Monitor is already running.")
            return False
        print("Starting Keystroke Monitor...")
        self.running = True
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.mouse_listener = mouse.Listener(on_move=self.on_move, on_click=self.on_click, on_scroll=self.on_scroll)
        self.listener.start()
        self.mouse_listener.start()
        return True

    def stopLog(self):
        if not self.running:
            print("Keystroke Monitor is not running.")
            return

        print("Stopping Keystroke Monitor...")
        self.running = False
        if self.listener:
            self.listener.stop()
        if self.mouse_listener:
            self.mouse_listener.stop()
        self.updateLog(f"Keystrokes: {self.keystrokes}")
        self.updateDatabase(self.keystrokes)
        print("Keystroke Monitor stopped and data logged.")
