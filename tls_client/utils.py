from sys import platform
from platform import machine
import ctypes


def get_dependency_filename():
    if platform == 'darwin':
        file_ext = '-arm64.dylib' if machine() == "arm64" else '-x86.dylib'
    elif platform in ('win32', 'cygwin'):
        file_ext = '-64.dll' if 8 == ctypes.sizeof(ctypes.c_voidp) else '-32.dll'
    else:
        if machine() == "aarch64":
            file_ext = '-arm64.so'
        elif "x86" in machine():
            file_ext = '-x86.so'
        else:
            file_ext = '-amd64.so'

    return f'tls-client{file_ext}'
