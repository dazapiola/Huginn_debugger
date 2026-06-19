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

### `frida_backend.py` — keystone no instalado
`keystone-engine` no está en el entorno activo, por eso el import falla en análisis estático.
Afecta: método `assemble()`.
Fix: agregar `keystone-engine` a `requirements.txt` e instalarlo, o hacer el import lazy dentro del método con mensaje de error claro si no está disponible.

### `frida_backend.py` — stubs de Frida incompletos
Los stubs de tipos de `frida` no modelan bien `exports_sync`, el callback de `script.on("message")` ni el argumento de `device.spawn()`.
Fix: ignorar con `# type: ignore` puntual en esas líneas, o contribuir stubs al paquete `frida-tools`.
