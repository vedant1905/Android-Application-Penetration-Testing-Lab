"""
ADB (Android Debug Bridge) utility functions.
Provides helpers for device communication, file operations, and shell commands.
"""

import subprocess
import shutil


def check_adb():
    """Check if ADB is available on the system PATH."""
    return shutil.which("adb") is not None


def _run_adb(args, device=None):
    """Run an ADB command and return (returncode, stdout, stderr)."""
    cmd = ["adb"]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", "ADB not found. Please install Android SDK platform-tools."


def get_connected_devices():
    """List connected Android devices/emulators."""
    code, stdout, stderr = _run_adb(["devices"])
    if code != 0:
        return []
    devices = []
    for line in stdout.split("\n")[1:]:
        line = line.strip()
        if line and "device" in line and "List" not in line:
            parts = line.split("\t")
            if len(parts) >= 2:
                devices.append({"id": parts[0], "state": parts[1]})
    return devices


def get_installed_packages(device=None):
    """List installed packages on the device."""
    code, stdout, _ = _run_adb(["shell", "pm", "list", "packages"], device)
    if code != 0:
        return []
    return [line.replace("package:", "").strip() for line in stdout.split("\n") if line.strip()]


def get_package_path(package_name, device=None):
    """Get the APK path on the device for a given package."""
    code, stdout, _ = _run_adb(["shell", "pm", "path", package_name], device)
    if code != 0:
        return None
    return stdout.replace("package:", "").strip()


def pull_file(remote_path, local_path, device=None):
    """Pull a file from the device to local filesystem."""
    code, stdout, stderr = _run_adb(["pull", remote_path, local_path], device)
    return code == 0


def run_shell_command(command, device=None):
    """Run a shell command on the device via ADB."""
    code, stdout, stderr = _run_adb(["shell", command], device)
    return stdout if code == 0 else stderr


def get_app_data_dir(package_name, device=None):
    """Get the data directory for an app."""
    return f"/data/data/{package_name}"


def check_root(device=None):
    """Check if the device is rooted (has su binary)."""
    code, stdout, _ = _run_adb(["shell", "which", "su"], device)
    return code == 0 and "su" in stdout


def get_logcat(tag=None, lines=100, device=None):
    """Get logcat output, optionally filtered by tag."""
    args = ["logcat", "-d", "-t", str(lines)]
    if tag:
        args.extend(["-s", tag])
    code, stdout, _ = _run_adb(["shell"] + args, device)
    return stdout if code == 0 else ""
