<p align="center">
  <img src="logo/cuervo_huginn.png" alt="Huginn" width="560"/>
</p>

# Huginn Debugger `v1.1.0`

Huginn es un debugger para análisis de binarios y desarrollo de exploits, orientado a seguridad ofensiva y reverse engineering.
Soporta análisis estático, debugging dinámico via GDB/MI, y un módulo completo de exploit development con pwntools integrado.

El nombre viene de uno de los cuervos de Odín — el que representa el pensamiento y la observación.

**Autor:** Alejandro Zapiola — **Co-autor:** Claude (Anthropic)

---

## ¿Para qué sirve?

**Reverse Engineering**
- Cargar y analizar binarios ELF/PE sin ejecutarlos
- Disassembly con colores por tipo de instrucción y labels de funciones automáticos
- Vista hex+ASCII, CFG interactivo
- Registros y stack en tiempo real durante debugging

**Debugging dinámico**
- Spawn de binarios (PIE y non-PIE, estáticos y dinámicos) o attach a procesos corriendo
- Breakpoints, step, step-over, continue
- Output del proceso en el Log panel; envío de stdin al proceso desde la consola

**Exploit Development** _(módulo `exploit/`)_
- Escáner de gadgets ROP/JOP/SYS con filtrado en tiempo real
- REPL Python con namespace pwntools pre-cargado (`elf`, `rop`, `p64`, `shellcraft`, …)
- Generador de shellcode con preview de asm e inyección directa al REPL

---

## Stack tecnológico

| Componente | Librería |
|---|---|
| Parsing de binarios (ELF/PE) | [LIEF](https://lief.re/) |
| Disassembly | [Capstone](https://www.capstone-engine.org/) |
| Debugging dinámico | GDB/MI (`gdb --interpreter=mi2`) |
| Grafo de flujo de control | [networkx](https://networkx.org/) |
| Exploit framework | [pwntools](https://github.com/Gallopsled/pwntools) |
| ROP/JOP/SYS scanner | [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) |
| UI | [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) |

---

## Instalación

**Requisitos**: Python 3.11+, GDB (`apt install gdb`)

```bash
cd hacking/Huginn
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pwntools ropgadget
```

---

## Uso

### Abrir desde línea de comandos

```bash
source .venv/bin/activate
python3 main.py /ruta/al/binario
```

### Abrir desde la interfaz

```bash
python3 main.py
```

Luego: **File → Open binary…** (`Ctrl+O`)

### Correr como root (necesario para attach a procesos ajenos)

GDB necesita privilegios de ptrace para attachear a procesos que no son del usuario actual.

```bash
sudo .venv/bin/python3 main.py
```

Para no tener que escribirlo cada vez:

```bash
alias huginn='sudo /ruta/a/Huginn/.venv/bin/python3 /ruta/a/Huginn/main.py'
```

---

## Interfaz

```
┌──────────────────────────────────────────────────────────────────────┐
│  File  Debug  View  Plugins                    [toolbar]             │
├─────────────────────────────┬────────────────────────────────────────┤
│  Disassembly                │  Registers / Stack / Breakpoints       │
│                             │  (tabs)                                │
│  ● 0x401000  push rbp       │  RAX  0x0000000000000000               │
│    0x401001  mov rbp, rsp   │  RBX  0x0000000000000000               │
│  > 0x401004  jne → 0x410c   │  RIP  0x0000000000401004               │
│                             │                                        │
├─────────────────────────────┴────────────────────────────────────────┤
│  Hex Dump / CFG / Log / ROP Gadgets / Exploit Console / Shellcraft   │
│  (tabs)                                                              │
│                                                                      │
│  11:23:01 EVT  Stopped at 0x401110  (_start)                         │
│  11:23:04 GDB  Temporary breakpoint 1, 0x401110 in _start ()        │
│  11:23:08 OUT  Enter password:                                       │
└──────────────────────────────────────────────────────────────────────┘
│  dynamic  ·  PID 12345  ·  @ 0x401110  ·  crackme · ELF · x64      │
└──────────────────────────────────────────────────────────────────────┘
```

### Paneles

| Panel | Descripción |
|---|---|
| **Disassembly** | Instrucciones del binario con colores y labels. Click en `●` para toggle breakpoint. |
| **Registers** | Valores de registros x86_64. Se actualiza en cada pausa; resalta en amarillo los que cambiaron. |
| **Stack** | Contenido del stack relativo a RSP. Disponible en modo dinámico. |
| **Hex Dump** | Vista hex+ASCII del binario. Se sincroniza al hacer click en disassembly. |
| **CFG** | Grafo de flujo de control. Zoom con rueda, pan arrastrando. |
| **Breakpoints** | Lista de BPs activos. Click → navega al disasm. Delete → elimina. |
| **Log** | Output del proceso (OUT), mensajes GDB (GDB), eventos (EVT), errores (ERR). |
| **ROP Gadgets** | Escáner de gadgets ROP/JOP/SYS con filtro de texto y tipo. |
| **Exploit Console** | REPL Python con pwntools pre-cargado y `send()` para enviar al proceso. |
| **Shellcraft** | Generador de shellcode con preview de asm e inyección al REPL. |

### Atajos de teclado

| Tecla | Acción |
|---|---|
| `F5` | Run / Spawn |
| `F7` | Step Into |
| `F8` | Step Over |
| `F9` | Continue |
| `F12` | Stop |
| `Ctrl+O` | Abrir binario |
| `Ctrl+P` | Attach a proceso |
| `Ctrl+R` | Restart |
| `Ctrl+G` | Ir a dirección |

---

## Módulo Exploit Development

Al cargar un binario, Huginn inicializa automáticamente un `ExploitContext` que usa pwntools para parsear el ELF y construir un objeto ROP. Este contexto alimenta los tres paneles de exploit.

### ROP Gadgets

**Cómo usarlo:**
1. Cargar un binario (`Ctrl+O`)
2. Abrir el tab **ROP Gadgets** en la barra inferior
3. Hacer click en **Scan** — el escaneo corre en background (ROPgadget)
4. Filtrar por texto o tipo

**Tipos de gadgets:**

| Tipo | Color | Descripción |
|---|---|---|
| **ROP** | Rojo | Terminan en `ret` — para ROP chains clásicas |
| **JOP** | Naranja | Terminan en `jmp reg` / `call reg` — Jump-Oriented Programming |
| **SYS** | Mauve | Contienen `syscall`, `int 0x80` o `sysenter` |

**Ejemplos de filtros:**

```
pop rdi ; ret          → gadget para cargar el primer argumento (x64 calling convention)
pop rsp ; ret          → stack pivot
xor eax, eax ; ret     → zero out RAX
leave ; ret            → epilogo de función
```

Doble-click en cualquier gadget navega al address en el panel **Disassembly**.

---

### Exploit Console

REPL Python embebido. Al cargar un binario, el namespace se pre-carga automáticamente.

**Variables disponibles en el REPL:**

| Variable | Tipo | Descripción |
|---|---|---|
| `elf` | `pwntools.ELF` | Binario parseado: símbolos, GOT, PLT, secciones |
| `rop` | `pwntools.ROP` | Objeto ROP listo para construir chains |
| `context` | `pwntools.context` | Configuración de arch/endian |
| `p8/p16/p32/p64` | `func` | Pack entero → bytes (little-endian) |
| `u8/u16/u32/u64` | `func` | Unpack bytes → entero |
| `asm(src)` | `func` | Ensamblar código → bytes |
| `disasm(b)` | `func` | Desensamblar bytes → string |
| `shellcraft` | `module` | Generador de shellcode |
| `flat(*args)` | `func` | Serializar lista de ints/bytes |
| `send(data)` | `func` | Enviar bytes al proceso inferior (GDB activo) |

**Atajos:**
- `Ctrl+Enter` — ejecutar código
- `↑ / ↓` — navegar historial (hasta 100 entradas)
- Botón **Reload NS** — refrescar namespace si se cargó un binario nuevo

**Ejemplos:**

```python
# Inspeccionar el binario
print(hex(elf.entry))
print(hex(elf.symbols['main']))
print(elf.got)           # dict de GOT entries
print(elf.plt)           # dict de PLT stubs
print(elf.libc)          # path de la libc linkeada (si disponible)

# Packing / unpacking
payload = b"A" * 40
payload += p64(0xdeadbeef)
print(payload.hex())

# Leer dirección de función y packearla
win_addr = elf.symbols.get('win', elf.symbols.get('flag'))
payload = b"A" * 72 + p64(win_addr)
print(f"payload ({len(payload)} bytes):", payload.hex())
```

```python
# ROP chain con pwntools
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]           # stack alignment

rop.raw(pop_rdi)
rop.raw(next(elf.search(b'/bin/sh')))
rop.raw(ret)
rop.raw(elf.plt['system'])

chain = rop.chain()
print(f"ROP chain ({len(chain)} bytes):", chain.hex())

payload = b"A" * 40 + chain
```

```python
# Enviar payload al proceso (requiere F5 spawn activo)
send(b"A" * 40 + p64(win_addr) + b"\n")
```

```python
# Usar shellcode generado en el panel Shellcraft
# (se inyecta como variable `sh` al hacer click en → Console)
payload = b"\x90" * 16 + sh         # NOP sled + shellcode
send(payload)
```

```python
# Shellcraft directo desde el REPL
sc = asm(shellcraft.sh())
print(f"shellcode: {len(sc)} bytes")
print(sc.hex())

# execve personalizado
sc = asm(shellcraft.execve('/bin/sh', [], []))
```

---

### Shellcraft

Generador visual de shellcode con 12 templates curados para amd64 e i386.

**Workflow:**
1. Seleccionar **Arch** (amd64 / i386)
2. Seleccionar **Template** en el combo
3. Completar argumentos en el formulario (si aplica)
4. Click **Generate** — el panel muestra el assembly y los bytes en hex
5. Click **Copy hex** para copiar al clipboard
6. Click **→ Console** para inyectar la variable en el Exploit Console

**Templates disponibles:**

| Template | Argumentos | Descripción |
|---|---|---|
| `sh` | — | Ejecuta `/bin/sh` |
| `execve` | `path, argv, envp` | `execve()` genérico |
| `cat` | `filename, fd=1` | Lee archivo y lo escribe a un fd |
| `exit` | `status=0` | Llama a `exit()` |
| `nop` | — | Una instrucción NOP (para NOP sleds, combinar con `* N`) |
| `trap` | — | `int3` — breakpoint de software |
| `pause` | — | `pause()` — suspende el proceso |
| `connect` | `host, port` | Conexión TCP saliente |
| `bindsh` | `port` | Shell en puerto local (bind shell) |
| `dup2` | `fd, fd2` | Duplica un file descriptor |
| `read` | `fd, buffer, count` | `read()` syscall |
| `write` | `fd, buf, n` | `write()` syscall |

**Ejemplo — NOP sled + execve:**
```python
# En el Exploit Console, después de generar execve con → Console:
nop_sled = asm(shellcraft.nop()) * 64    # 64 NOPs
payload  = b"A" * 40 + p64(buf_addr) + nop_sled + execve
send(payload + b"\n")
```

---

## Estructura del proyecto

```
Huginn/
├── main.py                        ← entry point
├── requirements.txt
├── backlog.md
├── core/
│   ├── binary.py                  ← parseo ELF/PE con LIEF (BinaryInfo)
│   ├── disasm.py                  ← disassembly con Capstone
│   ├── cfg.py                     ← construcción del CFG con networkx
│   └── session.py                 ← estado global: backend, binary, breakpoints, exploit_ctx
├── backends/
│   ├── base.py                    ← interfaz abstracta DebuggerBackend
│   ├── static_backend.py          ← backend de solo lectura (archivo en disco)
│   └── gdb_backend.py             ← GDB/MI: spawn, attach, PTY, breakpoints, registros
├── exploit/                       ← módulo de exploit development
│   ├── context.py                 ← ExploitContext: pwntools ELF + ROP + helpers
│   ├── gadget_worker.py           ← GadgetWorker(QThread): escanea con ROPgadget
│   └── repl_worker.py             ← REPLWorker(QThread): ejecuta código, captura stdout
├── ui/
│   ├── theme.py                   ← dark theme (Catppuccin Mocha)
│   ├── main_window.py             ← ventana principal con docks
│   ├── process_picker.py          ← diálogo de selección de proceso
│   └── panels/
│       ├── disasm_panel.py
│       ├── hex_panel.py
│       ├── registers_panel.py
│       ├── stack_panel.py
│       ├── cfg_panel.py
│       ├── breakpoints_panel.py
│       ├── log_panel.py
│       ├── rop_panel.py           ← ROP/JOP/SYS gadget scanner
│       ├── exploit_console.py     ← REPL Python con namespace pwntools
│       └── shellcraft_panel.py    ← generador de shellcode visual
└── plugins/
    ├── __init__.py
    └── analysis/                  ← labels de funciones + detección de loops
        ├── __init__.py
        ├── engine.py
        └── panel.py
```

---

## Estado de desarrollo

| Módulo | Descripción | Estado |
|---|---|---|
| **Core engine** | LIEF + Capstone + CFG + Session | ✅ Completo |
| **UI estática** | Ventana Qt con paneles de análisis | ✅ Completo |
| **Backend GDB/MI** | Spawn/attach, breakpoints, registros, PIE | ✅ Completo |
| **Live panels** | Registros, stack, breakpoints, log en tiempo real | ✅ Completo |
| **Polish** | Toolbar, process picker, export, status bar, About | ✅ Completo |
| **Plugin Analysis** | Function labels + loop detection | ✅ Completo |
| **ExploitContext** | pwntools ELF + ROP + helpers por binario | ✅ Completo |
| **ROP Panel** | Scanner ROPgadget, filtro texto/tipo, navigate_to | ✅ Completo |
| **Exploit Console** | REPL Python + pwntools + send() al proceso | ✅ Completo |
| **Shellcraft Panel** | 12 templates, preview asm/hex, → Console | ✅ Completo |
| **Plugin mona** | Corelan exploiting tools integradas | ⏳ Pendiente |

---

## Verificación rápida

```bash
# Análisis estático
python3 test_phase1.py

# Debugging dinámico
sudo .venv/bin/python3 main.py ./crackme_pwn
# → F5 para spawn → para en _start
# → F9 Continue → proceso corre
# → Ves output del proceso en Log panel (OUT)

# Exploit workflow completo
# 1. Abrir binario vulnerable
# 2. Tab ROP Gadgets → Scan → filtrar "pop rdi ; ret"
# 3. Tab Exploit Console → escribir payload con p64(), rop.chain()
# 4. F5 Spawn → send(payload + b"\n")
```
