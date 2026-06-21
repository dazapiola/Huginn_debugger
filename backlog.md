# Huginn — Backlog

## Errores Pyright pre-existentes

### `main_window.py` — LIEF sin type stubs
LIEF no publica stubs de tipos completos para Pyright. Los atributos `.format`, `.segments`, `.type` y `.imports` existen en runtime pero Pyright no los reconoce.
Afecta: función `_check_dynamic_compatible`.
Fix: generar stubs parciales para los atributos usados, o añadir `# type: ignore` con comentario en esas líneas.

### `main_window.py` — `menuBar()` anotado como `Optional`
PyQt6 anota `QMainWindow.menuBar()` como `Optional[QMenuBar]` aunque nunca retorna `None`.
Afecta: toda la construcción del menú en `_create_menus`.
Fix: asignar y assertar (`mb = self.menuBar(); assert mb is not None`) como se hizo con `verticalHeader()` / `horizontalHeader()`.

## Bugs de runtime

### ~~BUG-0: Reemplazar FridaBackend con GDBBackend~~ ✓ RESUELTO
Frida es un framework de instrumentación, no un debugger interactivo. `recv('continue').wait()` bloquea el thread JS impidiendo operaciones concurrentes; `Interceptor.attach` parchea bytes de entrada con JMP trampoline, rompiendo el step; el modelo de eventos es incompatible con debugging interactivo.
Fix: nuevo `backends/gdb_backend.py` usando GDB/MI protocol (subprocess + MI2 interpreter). Token-based sync commands, reader thread, `_startup_handler` para coordinar el doble stop del spawn PIE (starti → runtime base → entry bp). `_to_runtime`/`_to_static` para traducción de direcciones. `_start_dynamic` en `main_window.py` ahora usa `GDBBackend`. Soporta binarios PIE y no-PIE, step/step-over/continue/breakpoints/read_memory/registers vía GDB nativo.

### ~~BUG-1: Breakpoints no paran la ejecución~~ ✓ RESUELTO
Root cause: `FridaBackend.set_breakpoint()` pasaba la dirección estática directamente al agente Frida, que espera direcciones runtime. Para PIE, la dirección estática (RVA) caía en la null page y fallaba silenciosamente. También, `_on_message` pasaba el RIP runtime a `_stop_callback`, por lo que `session.current_address` quedaba en runtime → `is_pc` nunca matcheaba en el disasm.
Fix: `FridaBackend` es ahora el único punto de traducción. `_load_agent()` cachea `_runtime_base` (funciona para spawn y attach). `_to_runtime()` y `_to_static()` traducen en la frontera. `set_breakpoint/remove_breakpoint` traducen estático→runtime. `_on_message` traduce RIP runtime→estático antes de llamar a `_stop_callback`. Todo el sistema arriba del backend trabaja con direcciones estáticas.

### ~~BUG-2: Disasm no navega al breakpoint al parar~~ ✓ RESUELTO (por BUG-1)
Con BUG-1 resuelto, `session.current_address` es siempre dirección estática. El disasm recarga desde esa dirección y `row_for_address` la encuentra. El QTimer fix (ya aplicado) garantiza que `scrollTo` se ejecuta después del re-layout del viewport.

### ~~BUG-3: Step / Step Over no funcionan~~ ✓ RESUELTO
Root cause: `step()` llamaba `read_memory(rip, 15)` que lee memoria viva. Cuando el breakpoint era del tipo `Interceptor.attach` (Frida parchea los primeros bytes de la función con un JMP trampoline), capstone desensambla el JMP y calcula una dirección destino incorrecta. El BP temporal se ponía en la dirección interna de Frida, el proceso nunca llegaba, y `_bp_event.wait(5.0)` hacía timeout silencioso.
Fix: nuevo método `_original_bytes_at(static_addr, size)` que lee desde el binario estático (segmentos LOAD → secciones → fallback a memoria viva). `step()` traduce `rip` a estático para la lectura, pero le pasa el `rip` runtime a capstone, así los `next_addrs` computados siguen siendo direcciones runtime correctas.

### ~~Step/Step Over deshabilitados después de breakpoint~~ ✓ RESUELTO
`spawn()` seteaba el breakpoint de entry point usando la dirección estática del binario (`binary_info.entry_point`). Para binarios PIE con ASLR, esa dirección es el RVA (ej: `0x1060`), no la dirección runtime (ej: `0x555555555060`). El proceso nunca paraba, `_on_process_stopped` nunca se llamaba, y los botones step quedaban deshabilitados.
Fix: `_resolve_runtime_entry()` en `FridaBackend` consulta los módulos via `_rpc.get_modules()` antes del `device.resume()`, calcula `rva = entry - base_static` y retorna `runtime_base + rva`.
Fix adicional: `_start_dynamic` ahora conecta `worker.finished` → `_on_spawn_running()` para habilitar Stop y actualizar el status a "running" cuando el proceso arranca.

### ~~Disasm no navega al breakpoint~~ ✓ RESUELTO
`refresh()` llamaba `scrollTo` inmediatamente después de `endResetModel()`. Qt schedula el re-layout del viewport de forma asíncrona, así que `scrollTo` llegaba antes de que las posiciones estuvieran calculadas y no hacía nada.
Fix: `QTimer.singleShot(0, ...)` para diferir el scroll al siguiente tick del event loop, más `PositionAtTop` hint en lugar de `EnsureVisible` para forzar que la instrucción actual quede en la parte superior de la vista.

## Errores Pyright pre-existentes

### ~~`frida_backend.py` — keystone no instalado~~ ✓ RESUELTO
Import lazy con `ImportError` separado y mensaje claro. `# type: ignore[import-untyped]` en el import.

### ~~`frida_backend.py` — stubs de Frida incompletos~~ ✓ RESUELTO
Agregados `# type: ignore[arg-type]` en `script.on("message", ...)` (línea 87) y en `device.spawn()` (línea 46). `exports_sync` ya tenía `# type: ignore[attr-defined]`.
