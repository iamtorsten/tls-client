import ctypes
import platform
from typing import Tuple

dependency_filenames = {
    ('windows', '32'): "tls-client-windows-32.dll",
    ('windows', '64'): "tls-client-windows-64.dll",
    ('darwin', 'arm64'): "tls-client-darwin-arm64.dylib",
    ('darwin', 'amd64'): "tls-client-darwin-amd64.dylib",
    ('linux', 'ubuntu-amd64'): "tls-client-linux-ubuntu-amd64.so",
    ('linux', 'alpine-amd64'): "tls-client-linux-alpine-amd64.so",
    ('linux', 'arm64'): "tls-client-linux-arm64.so",
    ('linux', 'armv7'): "tls-client-linux-armv7.so",
}


def get_system_info() -> Tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == 'darwin':
        return 'darwin', 'arm64' if machine == 'arm64' else 'amd64'
    elif system in ('windows', 'win32', 'cygwin'):
        return 'windows', '64' if 8 == ctypes.sizeof(ctypes.c_voidp) else '32'
    else:  # Assume Linux
        if machine == 'aarch64':
            return 'linux', 'arm64'
        elif machine == 'armv7l':
            return 'linux', 'armv7'
        elif 'x86_64' in machine:
            return 'linux', 'ubuntu-amd64'  # Assuming Ubuntu for x86_64
        else:
            return 'linux', 'alpine-amd64'  # Default to Alpine for unknown architectures


def get_dependency_filename():
    system, arch = get_system_info()
    return dependency_filenames.get((system, arch))
