import subprocess
import os
import signal
import time
import platform
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ScannerCore:
    def __init__(self):
        self.current_process = None
        self.is_windows = platform.system() == "Windows"

    def is_tool_installed(self, tool):
        """Check if a tool is available in the system PATH."""
        cmd = "where" if self.is_windows else "command -v"
        try:
            subprocess.run(f"{cmd} {tool}", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def rotate_ip(self):
        """Attempts to rotate IP using Tor. This is experimental and system-dependent."""
        logger.info("Attempting IP rotation...")
        try:
            if self.is_windows:
                # Windows might need a different approach, e.g., restarting a service if it exists
                # For now, we'll try to find if tor.exe is running and maybe restart it if it's a service
                # subprocess.run(["net", "stop", "tor"], check=False)
                # subprocess.run(["net", "start", "tor"], check=False)
                logger.warning("IP rotation via 'service' is not directly supported on Windows. Please ensure Tor is configured manually.")
            else:
                subprocess.run(["sudo", "service", "tor", "restart"], check=True)
                time.sleep(5)
            logger.info("IP rotation command executed.")
        except Exception as e:
            logger.error(f"IP rotation failed: {e}")

    def is_host_up(self, target):
        """Check if the target host is reachable using nmap."""
        try:
            result = subprocess.run(["nmap", "-sn", target], capture_output=True, text=True, check=False)
            return "Host is up" in result.stdout
        except Exception as e:
            logger.error(f"Error checking host status: {e}")
            return False

    def run_scan(self, command, target, output_file=None, callback=None):
        """Execute a scan command and yield output."""
        if not self.is_tool_installed(command[0]):
            yield f"[!] Error: {command[0]} is not installed.\n"
            return

        yield f"[*] Starting execution: {' '.join(command)}\n"
        
        try:
            # Platform specific process creation
            kwargs = {}
            if not self.is_windows:
                kwargs['preexec_fn'] = os.setsid
            
            self.current_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                **kwargs
            )

            for line in self.current_process.stdout:
                yield line
                if callback:
                    callback(line)

            self.current_process.wait()
            
            if output_file:
                # This would normally be handled by the caller who consumes the generator
                pass

        except Exception as e:
            yield f"[!] An unexpected error occurred: {e}\n"
        finally:
            self.current_process = None

    def stop_scan(self):
        """Terminate the currently running scan."""
        if self.current_process:
            try:
                if self.is_windows:
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.current_process.pid)])
                else:
                    os.killpg(os.getpgid(self.current_process.pid), signal.SIGTERM)
                return True
            except Exception as e:
                logger.error(f"Failed to stop process: {e}")
                return False
        return False

# Scan Command Definitions
SCAN_COMMANDS = {
    "Quick": lambda t: ["nmap", "-T4", "-F", "--spoof-mac", "random", "-sS", t],
    "Full": lambda t: ["nmap", "-p-", "--script", "firewalk", "-sS", t],
    "Intense": lambda t: ["nmap", "-T4", "-A", "-v", "--spoof-mac", "random", t],
    "CVE Scan": lambda t: ["nmap", "--script", "vulners", "-sV", "--spoof-mac", "random", t],
}
