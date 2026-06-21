# Huginn Debugger

Huginn es un debugger para análisis de binarios orientado a seguridad ofensiva y reverse engineering.
Soporta análisis estático y debugging dinámico de procesos vivos via GDB/MI.

El nombre viene de uno de los cuervos de Odín — el que representa el pensamiento y la observación.

---

## ¿Para qué sirve?

- Cargar y analizar binarios ELF/PE sin ejecutarlos
- Disassembly con colores por tipo de instrucción y labels de funciones automáticos
- Vista hex+ASCII, CFG interactivo, registros y stack en tiempo real
- Debugging dinámico: breakpoints, step, step-over, continue
- Spawn de binarios (PIE y non-PIE, estáticos y dinámicos) o attach a procesos corriendo
- Panel de logs: output del proceso, mensajes GDB, eventos del debugger
- Panel de breakpoints: lista de BPs activos con navegación rápida

---

## Stack tecnológico

| Componente | Librería |
|---|---|
| Parsing de binarios (ELF/PE) | [LIEF](https://lief.re/) |
| Disassembly | [Capstone](https://www.capstone-engine.org/) |
| Debugging dinámico | GDB/MI (`gdb --interpreter=mi2`) |
| Grafo de flujo de control | [networkx](https://networkx.org/) |
| UI | [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) |

---

## Instalación

**Requisitos**: Python 3.11+, GDB instalado (`apt install gdb`)

```bash
cd hacking/Huginn
pip install -r requirements.txt
```

---

## Uso

### Abrir desde línea de comandos

```bash
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
sudo /ruta/al/python3 main.py
```

Si Python está en un entorno virtual:

```bash
sudo /home/lodeale/miniconda3/bin/python3 main.py
```

Para no tener que escribirlo cada vez:

```bash
alias huginn='sudo /home/lodeale/miniconda3/bin/python3 /ruta/a/Huginn/main.py'
```

---

## Interfaz

```
┌──────────────────────────────────────────────────────────────────┐
│  File  Debug  View  Plugins               [toolbar]              │
├────────────────────────────┬─────────────────────────────────────┤
│  Disassembly               │  Registers / Stack / Breakpoints    │
│                            │  (tabs)                             │
│  ● 0x401000  push rbp      │  RAX  0x0000000000000000            │
│    0x401001  mov rbp, rsp  │  RBX  0x0000000000000000            │
│  > 0x401004  jne → 0x410c  │  RIP  0x0000000000401004            │
│                            │                                      │
├────────────────────────────┴─────────────────────────────────────┤
│  Hex Dump / CFG / Log (tabs)                                     │
│                                                                  │
│  11:23:01 EVT  Stopped at 0x401110  (_start)                     │
│  11:23:04 GDB  Temporary breakpoint 1, 0x401110 in _start ()     │
│  11:23:08 OUT  Enter password:                                   │
└──────────────────────────────────────────────────────────────────┘
│  dynamic  ·  PID 12345  ·  @ 0x401110  ·  crackme · ELF · x64  │
└──────────────────────────────────────────────────────────────────┘
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
| **Log** | Output del proceso (OUT), mensajes GDB (GDB), eventos del debugger (EVT), errores (ERR). |

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

## Estructura del proyecto

```
Huginn/
├── main.py                      ← entry point
├── requirements.txt
├── backlog.md
├── core/
│   ├── binary.py                ← parseo ELF/PE con LIEF
│   ├── disasm.py                ← disassembly con Capstone
│   ├── cfg.py                   ← construcción del CFG con networkx
│   └── session.py               ← estado global: backend, binary, breakpoints, logs
├── backends/
│   ├── base.py                  ← interfaz abstracta DebuggerBackend
│   ├── static_backend.py        ← backend de solo lectura (archivo en disco)
│   └── gdb_backend.py           ← GDB/MI: spawn, attach, PTY, breakpoints, registros
├── ui/
│   ├── theme.py                 ← dark theme (Catppuccin Mocha)
│   ├── main_window.py           ← ventana principal con docks
│   ├── process_picker.py        ← diálogo de selección de proceso
│   └── panels/
│       ├── disasm_panel.py
│       ├── hex_panel.py
│       ├── registers_panel.py
│       ├── stack_panel.py
│       ├── cfg_panel.py
│       ├── breakpoints_panel.py
│       └── log_panel.py
└── plugins/
    ├── __init__.py
    └── analysis/                ← labels de funciones + detección de loops
        ├── __init__.py
        ├── engine.py
        └── panel.py
```

---

## Estado de desarrollo

| Fase | Descripción | Estado |
|---|---|---|
| **Fase 1** | Core engine: LIEF + Capstone + CFG + Session | ✅ Completa |
| **Fase 2** | UI estática: ventana Qt con los paneles | ✅ Completa |
| **Fase 3** | Backend GDB/MI: spawn/attach, breakpoints, registros, PIE | ✅ Completa |
| **Fase 4** | Live panels: registros, stack, breakpoints, log en tiempo real | ✅ Completa |
| **Fase 5** | Polish: toolbar, attach con process picker, export, status bar | ✅ Completa |
| **Fase 7** | Plugin Analysis: function labels + loop detection | ✅ Completa |
| **Fase 6** | Plugin mona (Corelan): exploiting tools integradas | ⏳ Pendiente |

---

## Verificación rápida

```bash
# Análisis estático
python3 test_phase1.py

# Debugging dinámico
sudo python3 main.py crackme_pwn
# → F5 para spawn → para en _start
# → F9 Continue → proceso corre
# → Ves output del proceso en el log panel (OUT)
```
