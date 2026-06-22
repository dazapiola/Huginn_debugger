# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com).
Versiones siguiendo [Semantic Versioning](https://semver.org).

## [Unreleased]

_(próximos cambios van acá)_

---

## [1.1.0] - 2026-06-22

### Added
- Módulo `exploit/`: `ExploitContext` — pwntools ELF + ROP chain builder + helpers `p8/p16/p32/p64`, `u8/u16/u32/u64`, `asm`, `shellcraft`
- **ROP Panel**: escáner ROPgadget en background con clasificación ROP/JOP/SYS, filtro de texto y tipo, doble-click navega al disasm
- **Exploit Console**: REPL Python embebido con namespace pwntools pre-cargado; `send()` para enviar bytes al proceso inferior via PTY; historial de comandos navegable con ↑↓; `Ctrl+Enter` para ejecutar
- **Shellcraft Panel**: 12 templates curados (sh, execve, cat, exit, nop, trap, pause, connect, bindsh, dup2, read, write); form dinámico de argumentos; preview de asm y hex; "→ Console" inyecta el shellcode en el namespace del REPL
- Dependencias: `pwntools>=4.15.0`, `ropgadget>=7.7`

---

## [1.0.0] - 2026-05-01

### Added
- Core engine: parseo ELF/PE con LIEF (`BinaryInfo`), disassembly con Capstone, CFG con networkx
- Backend GDB/MI: spawn y attach de procesos (PIE y non-PIE), breakpoints por dirección, step / step-over / continue, lectura de registros x86_64
- PTY separado para I/O del inferior (evita que el `read()` del proceso consuma los comandos GDB/MI)
- Paneles UI: Disassembly, Registers, Stack, Hex Dump, CFG, Breakpoints, Log
- Plugin Analysis: labels de funciones automáticos + detección de loop headers
- Process Picker: diálogo para buscar y attachear a procesos corriendo por nombre/PID
- About dialog con logo
- Soporte para abrir binario desde línea de comandos: `python3 main.py /ruta/binario`
