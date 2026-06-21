# Huginn — Backlog

## Pendiente

### Stdin interactivo para el proceso
El inferior puede hacer `read(0, ...)` (por ej. un crackme que pide contraseña) y el usuario
necesita enviarle input. Actualmente el output del proceso se ve en el log panel (líneas `OUT`
vía PTY master), pero no hay forma de escribirle al proceso.

**Fix propuesto**: agregar un `QLineEdit` al final del `LogPanel` que escriba al
`backend._inf_master_fd` cuando el backend es `GDBBackend`.
```python
text = self._input.text() + "\n"
os.write(backend._inf_master_fd, text.encode())
self._input.clear()
```

### Errores Pyright pre-existentes

**LIEF sin type stubs**
LIEF no publica stubs de tipos completos para Pyright. Los atributos `.format`, `.segments`,
`.type` y otros existen en runtime pero Pyright los marca como `reportMissingImports`.
Fix: generar stubs parciales o añadir `# type: ignore` con comentario en esas líneas.

**`menuBar()` anotado como `Optional`**
PyQt6 anota `QMainWindow.menuBar()` como `Optional[QMenuBar]` aunque nunca retorna `None`.
Afecta: toda la construcción del menú en `_create_menus`.
Fix: `mb = self.menuBar(); assert mb is not None`.

---

## Resueltos

### ~~BUG-0: Reemplazar FridaBackend con GDBBackend~~ ✓ RESUELTO
Frida es un framework de instrumentación, no un debugger interactivo. `recv('continue').wait()`
bloqueaba el thread JS; `Interceptor.attach` parchea bytes con JMP trampoline rompiendo el step;
el modelo de eventos era incompatible con debugging interactivo.
**Fix**: nuevo `backends/gdb_backend.py` usando GDB/MI protocol (subprocess + MI2 interpreter).
Token-based sync commands, reader thread, `_startup_handler` para coordinar el doble stop del
spawn PIE (starti → runtime base → entry bp). PIE y non-PIE soportados nativamente por GDB.

### ~~BUG-1: Continue bloqueaba el UI~~ ✓ RESUELTO
`_do_continue` llamaba `continue_()` en el main thread Qt. `_cmd("-exec-continue")` bloqueaba
esperando `^running`, congelando el event loop.
**Fix**: `_do_continue` usa `_DebugWorker(QThread)` igual que `step()` y `step_over()`.

### ~~BUG-2: Inferior consumía comandos GDB/MI~~ ✓ RESUELTO
El inferior (crackme que hace `read(0,...)`) y GDB compartían el mismo stdin PIPE. El `read()`
del inferior consumía los comandos `-exec-continue` enviados por nosotros → GDB nunca los recibía
→ timeout/hang.
**Fix**: PTY dedicado para el inferior. `pty.openpty()` crea el par master/slave; GDB recibe
`set inferior-tty /dev/pts/N`; el master fd se lee en `_inf_reader` thread y el output aparece
como líneas `OUT` en el log panel.

### ~~BUG-3: Attach fallaba con error de permiso genérico~~ ✓ RESUELTO
`os.readlink("/proc/PID/exe")` requiere root para procesos de otro usuario. El error no se
mostraba correctamente.
**Fix**: manejo específico por tipo de excepción (`FileNotFoundError`, `PermissionError`, `OSError`).
En `PermissionError` se ofrece: seleccionar binario manualmente con file picker, o attachear sin
símbolos. El attach sin símbolos usa GDB igualmente — funcionalidad reducida pero operativo.

### ~~BUG-4: Breakpoints no paran la ejecución~~ ✓ RESUELTO (era BUG-1 de Frida)
### ~~BUG-5: Disasm no navega al breakpoint~~ ✓ RESUELTO
### ~~BUG-6: Step/Step Over deshabilitados~~ ✓ RESUELTO
Todos resueltos al migrar a GDB/MI backend (ver BUG-0).
