#!/usr/bin/env python3
"""
mona_cli.py — Usa mona.py desde la terminal sin abrir Huginn.

Uso:
    python3 mona_cli.py pattern_create 200
    python3 mona_cli.py bytearray -cpb 0x00 0x0a
    python3 mona_cli.py pattern_offset 0x41306341
    python3 mona_cli.py help
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from plugins.mona.bridge import _ensure_immlib_stub, get_mona


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 mona_cli.py <comando> [args...]")
        print("  Ejemplos:")
        print("    python3 mona_cli.py pattern_create 200")
        print("    python3 mona_cli.py bytearray -cpb 0x00 0x0a")
        print("    python3 mona_cli.py pattern_offset 0x41306341")
        sys.exit(1)

    _ensure_immlib_stub()
    m = get_mona()
    m.arch = 64

    def log(msg="", *a, **kw):
        print(msg)

    # Minimal bridge: solo logging, sin sesión activa
    class CliDbg:
        def log(self, msg="", *a, **kw):   print(msg)
        def logLines(self, msg, **kw):
            for line in str(msg).split("\n"):
                print(line)
        def error(self, msg, **kw):         print(f"[ERR] {msg}", file=sys.stderr)
        def getDebuggedName(self):          return "cli"
        def getDebuggedPid(self):           return 0
        def getOsVersion(self):             return "lin"
        def getRegs(self):                  return {}
        def getAllModules(self):             return {}
        def getModule(self, n):             return None
        def getAddress(self, a):            return None
        def readMemory(self, a, s):         return b"\x00" * s
        def getPageSize(self):              return 4096
        def searchCommands(self, *a):       return []
        def isHEAPBlock(self, a):           return False
        def getJmp(self, a):                return None
        def createLogWindow(self):          pass
        def setStatusBar(self, m):          pass
        def createTable(self, *a, **kw):    return None
        def nativeCommand(self, c):         return ""

    m.dbg = CliDbg()
    m.main(sys.argv[1:])


if __name__ == "__main__":
    main()
