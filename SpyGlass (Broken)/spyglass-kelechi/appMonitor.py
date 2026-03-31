import logging
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

import psutil
import winreg

from database import updateAppTable


class AppMonitor:
    def __init__(
        self,
        poll_interval: float = 15.0,
        alert_manager=None,
        thresholds: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.current_process: Optional[Dict[str, Any]] = None
        self.last_update: Optional[datetime] = None
        self.poll_interval = poll_interval
        self.alert_manager = alert_manager
        self.thresholds = thresholds or {}
        self.known_apps: Set[str] = set()
        self.high_cpu_start: Dict[int, float] = {}
        self.system_high_cpu_start: Optional[float] = None
        self.process_cpu_tracker_started = False

    def configure(self, alert_manager=None, thresholds: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        if alert_manager is not None:
            self.alert_manager = alert_manager
        if thresholds is not None:
            self.thresholds = thresholds

    def start_monitoring(self) -> bool:
        if self.thread and self.thread.is_alive():
            print("Process monitoring is already running.")
            return True

        try:
            self.is_running = True
            self._prime_cpu_counters()
            self.thread = threading.Thread(target=self.monitor_loop, daemon=True, name="AppMonitor")
            self.thread.start()
            logging.info("App monitor thread started")
            return True
        except Exception as e:
            logging.error(f"Failed to start app monitor thread: {e}")
            return False

    def stop_monitoring(self) -> None:
        logging.info("Stopping app monitor...")
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=5)
            logging.info("App monitor thread stopped")

    def monitor_loop(self) -> None:
        logging.info("Entering app monitor loop")
        while self.is_running:
            try:
                foreground = self.get_foreground_window()
                if foreground and foreground != self.current_process:
                    self.current_process = foreground
                    self.last_update = datetime.now()
                    logging.info(
                        "Active app changed: %s | %s",
                        foreground["name"],
                        foreground["window_title"],
                    )

                running_apps = self.get_running_apps()
                self.evaluate_thresholds(running_apps, foreground)
                threading.Event().wait(self.poll_interval)
            except Exception as e:
                logging.error(f"Error in app monitor loop: {e}", exc_info=True)

    def _prime_cpu_counters(self) -> None:
        try:
            psutil.cpu_percent(interval=None)
            for process in psutil.process_iter(["pid"]):
                try:
                    process.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.process_cpu_tracker_started = True
        except Exception as exc:
            logging.debug("Unable to prime CPU counters: %s", exc)

    def get_foreground_window(self) -> Optional[Dict[str, Any]]:
        try:
            if sys.platform != "win32":
                return None

            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if hwnd == 0:
                return None

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

            length = user32.GetWindowTextLengthW(hwnd) + 1
            title_buffer = ctypes.create_unicode_buffer(length)
            user32.GetWindowTextW(hwnd, title_buffer, length)
            window_title = title_buffer.value

            process = psutil.Process(pid.value)
            return {
                "pid": process.pid,
                "name": process.name(),
                "exe_path": process.exe() if process.exe() else "Unknown",
                "window_title": window_title,
                "timestamp": datetime.now(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as e:
            logging.error(f"Failed to get foreground window: {e}")
            return None

    def get_running_apps(self) -> List[Dict[str, Any]]:
        running_apps: List[Dict[str, Any]] = []

        try:
            for process in psutil.process_iter(["pid", "name", "exe", "status", "memory_info"]):
                try:
                    info = process.info
                    running_apps.append(
                        {
                            "pid": info.get("pid"),
                            "name": info.get("name") or "Unknown",
                            "exe_path": info.get("exe") or "Unknown",
                            "status": info.get("status") or "unknown",
                            "memory_mb": round((info.get("memory_info").rss / (1024 * 1024)), 2)
                            if info.get("memory_info")
                            else 0.0,
                            "cpu_percent": float(process.cpu_percent(interval=None) or 0.0),
                            "window_title": "",
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            return running_apps
        except Exception as e:
            logging.error(f"Error getting running apps: {e}")
            return running_apps

    def get_installed_apps(self) -> List[Dict[str, Any]]:
        installed_apps: List[Dict[str, Any]] = []

        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hkey, path in registry_paths:
            try:
                registry_key = winreg.OpenKey(hkey, path)
                for i in range(winreg.QueryInfoKey(registry_key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        subkey = winreg.OpenKey(registry_key, subkey_name)

                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        except FileNotFoundError:
                            winreg.CloseKey(subkey)
                            continue

                        try:
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        except FileNotFoundError:
                            version = "Unknown"

                        try:
                            vendor = winreg.QueryValueEx(subkey, "Publisher")[0]
                        except FileNotFoundError:
                            vendor = "Unknown"

                        try:
                            install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                        except FileNotFoundError:
                            install_location = "Unknown"

                        installed_apps.append(
                            {
                                "name": name,
                                "version": version,
                                "vendor": vendor,
                                "install_location": install_location,
                            }
                        )

                        winreg.CloseKey(subkey)
                    except Exception:
                        continue

                winreg.CloseKey(registry_key)
            except Exception:
                continue

        return installed_apps

    def scan_and_log_installed_apps(self) -> int:
        installed_apps = self.get_installed_apps()
        logged_count = 0
        self.known_apps = {app["name"].lower() for app in installed_apps if app.get("name")}

        for app in installed_apps:
            try:
                executable_path = app["install_location"]
                if not executable_path or executable_path == "Unknown":
                    executable_path = f"UNKNOWN::{app['name']}"

                if updateAppTable(
                    appName=app["name"],
                    executablePath=executable_path,
                    vendor=app["vendor"],
                ):
                    logged_count += 1
            except Exception as e:
                logging.debug(f"Failed to log app {app.get('name', 'Unknown')}: {e}")

        logging.info(f"Logged {logged_count}/{len(installed_apps)} installed apps")
        return logged_count

    def log_apps(self) -> int:
        return self.scan_and_log_installed_apps()

    def is_visible_app_present(self) -> bool:
        foreground = self.get_foreground_window()
        return bool(foreground and (foreground.get("name") or foreground.get("window_title")))

    def evaluate_thresholds(self, running_apps: List[Dict[str, Any]], foreground: Optional[Dict[str, Any]]) -> None:
        if not self.alert_manager:
            return

        application_thresholds = self.thresholds.get("application", {})
        if not application_thresholds:
            return

        process_count_limit = application_thresholds.get("process_count", 100)
        if len(running_apps) > process_count_limit:
            self.alert_manager.trigger_alert(
                category="System Overload",
                severity="medium",
                module="application_monitor",
                key="process_count_limit",
                app_name="System",
                exe_path="INTERNAL::SYSTEM",
                threshold_name="process_count",
                threshold_value=process_count_limit,
                observed_value=len(running_apps),
                message=f"{len(running_apps)} processes are running simultaneously.",
            )

        total_cpu = psutil.cpu_percent(interval=None)
        self._check_total_cpu(total_cpu, application_thresholds)

        foreground_pid = foreground.get("pid") if foreground else None
        for app in running_apps:
            self._check_process_thresholds(app, foreground_pid, application_thresholds)

    def _check_total_cpu(self, total_cpu: float, thresholds: Dict[str, Any]) -> None:
        cpu_limit = thresholds.get("system_cpu_percent", 90)
        duration_limit = thresholds.get("system_cpu_duration_seconds", 60)
        now = time.time()

        if total_cpu > cpu_limit:
            if self.system_high_cpu_start is None:
                self.system_high_cpu_start = now
            elif now - self.system_high_cpu_start >= duration_limit:
                self.alert_manager.trigger_alert(
                    category="System Performance Risk",
                    severity="high",
                    module="application_monitor",
                    key="system_cpu_high",
                    app_name="System",
                    exe_path="INTERNAL::SYSTEM",
                    threshold_name="system_cpu_duration_seconds",
                    threshold_value=duration_limit,
                    observed_value=round(total_cpu, 2),
                    message=f"Overall CPU usage has remained above {cpu_limit}% for at least {duration_limit} seconds.",
                )
        else:
            self.system_high_cpu_start = None

    def _check_process_thresholds(self, app: Dict[str, Any], foreground_pid: Optional[int], thresholds: Dict[str, Any]) -> None:
        pid = int(app.get("pid") or 0)
        app_name = app.get("name") or "Unknown"
        exe_path = app.get("exe_path") or "Unknown"
        cpu_percent = float(app.get("cpu_percent") or 0.0)
        now = time.time()

        app_cpu_limit = thresholds.get("app_cpu_percent", 80)
        app_cpu_duration = thresholds.get("app_cpu_duration_seconds", 30)
        if cpu_percent > app_cpu_limit:
            started = self.high_cpu_start.setdefault(pid, now)
            if now - started >= app_cpu_duration:
                self.alert_manager.trigger_alert(
                    category="Performance Risk",
                    severity="high",
                    module="application_monitor",
                    key=f"app_cpu_high:{pid}",
                    app_name=app_name,
                    exe_path=exe_path,
                    threshold_name="app_cpu_duration_seconds",
                    threshold_value=app_cpu_duration,
                    observed_value=round(cpu_percent, 2),
                    message=f"{app_name} has exceeded {app_cpu_limit}% CPU for at least {app_cpu_duration} seconds.",
                )
        else:
            self.high_cpu_start.pop(pid, None)

        bg_cpu_limit = thresholds.get("background_cpu_percent", 50)
        if foreground_pid and pid != foreground_pid and cpu_percent > bg_cpu_limit:
            self.alert_manager.trigger_alert(
                category="Hidden Activity",
                severity="high",
                module="application_monitor",
                key=f"background_cpu:{pid}",
                app_name=app_name,
                exe_path=exe_path,
                threshold_name="background_cpu_percent",
                threshold_value=bg_cpu_limit,
                observed_value=round(cpu_percent, 2),
                message=f"Background process {app_name} is using {cpu_percent:.1f}% CPU.",
            )

        is_unknown = self._is_unknown_app(app_name, exe_path)
        if is_unknown:
            self.alert_manager.trigger_alert(
                category="Suspicious Application",
                severity="medium",
                module="application_monitor",
                key=f"unknown_app:{exe_path}",
                app_name=app_name,
                exe_path=exe_path,
                threshold_name="unknown_application_detected",
                observed_value=1,
                message=f"Unknown or unrecognized application detected: {app_name}.",
            )
            if cpu_percent > app_cpu_limit:
                self.alert_manager.trigger_alert(
                    category="Potential Malware",
                    severity="critical",
                    module="application_monitor",
                    key=f"unknown_high_cpu:{exe_path}",
                    app_name=app_name,
                    exe_path=exe_path,
                    threshold_name="combined_high_cpu_unknown_app",
                    threshold_value=app_cpu_limit,
                    observed_value=round(cpu_percent, 2),
                    message=f"High CPU usage combined with unknown application activity detected for {app_name}.",
                )

        if self._is_spyglass_process(app_name, exe_path):
            spyglass_limit = thresholds.get("spyglass_cpu_percent", 10)
            if cpu_percent > spyglass_limit:
                self.alert_manager.trigger_alert(
                    category="Application Performance Issue",
                    severity="medium",
                    module="application_monitor",
                    key=f"spyglass_cpu:{pid}",
                    app_name=app_name,
                    exe_path=exe_path,
                    threshold_name="spyglass_cpu_percent",
                    threshold_value=spyglass_limit,
                    observed_value=round(cpu_percent, 2),
                    message=f"SpyGlass is using {cpu_percent:.1f}% CPU, exceeding the configured threshold.",
                )

    def _is_unknown_app(self, app_name: str, exe_path: str) -> bool:
        app_name_l = (app_name or "").lower()
        exe_path_l = (exe_path or "").lower()
        if not app_name_l:
            return False
        if app_name_l in self.known_apps:
            return False
        if exe_path_l in {"unknown", ""}:
            return True
        if "\\windows\\" in exe_path_l or exe_path_l.startswith("c:\\program files") or exe_path_l.startswith("c:\\program files (x86)"):
            return False
        return True

    def _is_spyglass_process(self, app_name: str, exe_path: str) -> bool:
        app_name_l = (app_name or "").lower()
        exe_path_l = (exe_path or "").lower()
        return "spyglass" in app_name_l or "spyglass" in exe_path_l

    def cleanup(self) -> None:
        if self.is_running:
            self.stop_monitoring()
