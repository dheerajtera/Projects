import win32serviceutil
import win32service
import win32event
import servicemanager
import psutil
import time
import traceback
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------
# SETTINGS
# ---------------------------------
CPU_THRESHOLD = 70
MEMORY_THRESHOLD = 300
CHECK_INTERVAL = 2
LOG_FILE = r"C:\ThreatMonitor\threat_log.txt"
SUSPICIOUS_KEYWORDS = [
    "mimikatz",
    "meterpreter",
    "powershell -enc",
    "nc.exe",
    "netcat",
    "unknown",
    "hack",
    "exploit",
]

# ---------------------------------
# LOGGING
# ---------------------------------
def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"

    with open(LOG_FILE, "a", encoding="utf-8", errors="ignore") as f:
        f.write(line + "\n")

# ---------------------------------
# Threat Monitor Loop
# ---------------------------------
def monitor_system():
    log_event("Threat Monitoring Service Started...")

    # Warm-up CPU counters
    for p in psutil.process_iter():
        try: p.cpu_percent(interval=None)
        except: pass

    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info']):
                try:
                    name = proc.info.get('name', "unknown")
                    pid = proc.pid
                    cmdline = " ".join(proc.info.get('cmdline') or [])
                    cpu = proc.cpu_percent(interval=0.1)
                    mem_info = proc.info.get('memory_info')
                    mem_mb = mem_info.rss / (1024*1024) if mem_info else 0

                    if cpu > CPU_THRESHOLD:
                        log_event(f"CPU Spike: {name} ({pid}) using {cpu}%")

                    if mem_mb > MEMORY_THRESHOLD:
                        log_event(f"Memory Spike: {name} ({pid}) using {mem_mb:.2f} MB")

                    combined = f"{name} {cmdline}".lower()
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw.lower() in combined:
                            log_event(f"Suspicious Process: {name} ({pid}) matched '{kw}'")

                except Exception:
                    continue

            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            log_event("ERROR: " + str(e))
            log_event(traceback.format_exc())
            time.sleep(2)

# ---------------------------------
# Windows Service Class
# ---------------------------------
class ThreatService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ThreatDetectionService"
    _svc_display_name_ = "Threat Detection Monitor"
    _svc_description_ = "Monitors suspicious processes, spikes, and logs threats."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.running = False
        win32event.SetEvent(self.hWaitStop)
        log_event("Threat Detection Service Stopped.")

    def SvcDoRun(self):
        log_event("Threat Detection Service Starting...")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        monitor_system()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(ThreatService)


Review this code and add a button for ending the process.