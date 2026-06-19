# Huginn Debugger

Huginn es un debugger multiplataforma para análisis de binarios orientado a seguridad ofensiva y reverse engineering. Soporta análisis estático (sin ejecutar el binario) y, en versiones futuras, debugging dinámico de procesos vivos.

El nombre viene de uno de los cuervos de Odín — el que representa el pensamiento y la observación.

---

## ¿Para qué sirve?

- Cargar y analizar binarios ELF (Linux) y PE (Windows) sin ejecutarlos
- Ver el disassembly con colores por tipo de instrucción
- Inspeccionar el contenido en hexadecimal
- Visualizar el grafo de flujo de control (CFG) de funciones
- (próximamente) Debuggear procesos vivos con breakpoints, step, registros y stack en tiempo real
- (próximamente) Integración con **mona** de Corelan para tareas de exploiting

---

## Stack tecnológico

| Componente | Librería |
|---|---|
| Parsing de binarios (ELF/PE) | [LIEF](https://lief.re/) |
| Disassembly | [Capstone](https://www.capstone-engine.org/) |
| Grafo de flujo de control | [networkx](https://networkx.org/) |
| Debugging dinámico | [Frida](https://frida.re/) *(Fase 3)* |
| Assembler | [Keystone](https://www.keystone-engine.org/) *(Fase 6)* |
| UI | [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) |

---

## Instalación

**Requisitos**: Python 3.11+

```bash
cd hacking/Huginn
pip install -r requirements.txt
```

---

## Uso

### Abrir un binario desde la línea de comandos

```bash
python3 main.py /ruta/al/binario
```

### Abrir desde la interfaz

```bash
python3 main.py
```

Luego: **File → Open binary…** (`Ctrl+O`)

### Correr como root (necesario para attach a procesos)

Frida requiere privilegios de root para inyectarse en procesos ajenos. Si los paquetes están instalados en un entorno de usuario (conda, venv, pyenv), `sudo python3` no los encuentra porque usa el Python del sistema.

Usá el path absoluto al intérprete de tu entorno:

```bash
sudo /home/lodeale/miniconda3/bin/python3 main.py
```

Para no tener que escribirlo cada vez, agregá un alias a tu `~/.bashrc` o `~/.zshrc`:

```bash
alias huginn='sudo /home/lodeale/miniconda3/bin/python3 /ruta/completa/a/Huginn/main.py'
```

> Si tu entorno no es conda, reemplazá la ruta con la salida de `which python3` corriendo sin sudo.

---

## Interfaz

```
┌──────────────────────────────────────────────────────────────────┐
│  File  Debug  View  Plugins               [toolbar]              │
├────────────────────────────┬─────────────────────────────────────┤
│  Disassembly               │  Registers  /  Stack (tabs)         │
│                            │                                      │
│  ● 0x401000  push rbp      │  RAX  0x0000000000000000            │
│    0x401001  mov rbp, rsp  │  RBX  0x0000000000000000            │
│  > 0x401004  jne → 0x410c  │  RIP  0x0000000000401004            │
│                            │                                      │
├────────────────────────────┴─────────────────────────────────────┤
│  Hex Dump  /  CFG (tabs)                                         │
│                                                                  │
│  0x401000  55 48 89 e5 ...  |UH..|   [CFG graph view]            │
└──────────────────────────────────────────────────────────────────┘
│  static  ·  @ 0x401000  ·  binary.elf · ELF · x86_64/64bit      │
└──────────────────────────────────────────────────────────────────┘
```

### Paneles

| Panel | Descripción |
|---|---|
| **Disassembly** | Instrucciones del binario con colores. Click en la columna `●` para toggle breakpoint. Click en una fila para sincronizar el hex dump a esa dirección. |
| **Registers** | Valores de todos los registros x86_64. En modo dinámico se actualiza en cada pausa y resalta en amarillo los que cambiaron. |
| **Stack** | Contenido del stack relativo a RSP. Disponible en modo dinámico. |
| **Hex Dump** | Vista hex+ASCII del binario. Se sincroniza al hacer click en el panel de disassembly. |
| **CFG** | Grafo de flujo de control de la función actual. Zoom con la rueda del mouse, pan arrastrando. Aristas verdes = branch verdadero, rojas = branch falso. |

### Colores del disassembly

| Color | Tipo de instrucción |
|---|---|
| Azul | Instrucción general |
| Naranja | Jump condicional / incondicional |
| Verde | Call |
| Rojo | Return |
| Cyan | Dirección |
| Gris | Bytes raw |

---

## Estructura del proyecto

```
Huginn/
├── main.py                  ← entry point
├── requirements.txt
├── .plan                    ← plan de desarrollo completo
├── core/
│   ├── binary.py            ← parseo de ELF/PE con LIEF
│   ├── disasm.py            ← disassembly con Capstone
│   ├── cfg.py               ← construcción del CFG con networkx
│   └── session.py           ← estado global: backend, binary, breakpoints
├── backends/
│   ├── base.py              ← interfaz abstracta DebuggerBackend
│   ├── static_backend.py    ← backend de solo lectura (archivo en disco)
│   └── frida_backend.py     ← (Fase 3) attach/spawn a procesos vivos
├── ui/
│   ├── theme.py             ← dark theme (Catppuccin Mocha)
│   ├── main_window.py       ← ventana principal con docks
│   └── panels/
│       ├── disasm_panel.py
│       ├── hex_panel.py
│       ├── registers_panel.py
│       ├── stack_panel.py
│       └── cfg_panel.py
└── plugins/
    └── mona/                ← (Fase 6) integración con mona de Corelan
```

---

## Estado de desarrollo

| Fase | Descripción | Estado |
|---|---|---|
| **Fase 1** | Core engine: LIEF + Capstone + CFG + Session | ✅ Completa |
| **Fase 2** | UI estática: ventana Qt con los 5 paneles | ✅ Completa |
| **Fase 3** | Backend Frida: attach/spawn, breakpoints, registros | ✅ Completa |
| **Fase 4** | Live panels: registros y stack en tiempo real | ⏳ Pendiente |
| **Fase 5** | Polish: toolbar completo, menú Debug habilitado | ⏳ Pendiente |
| **Fase 6** | Plugin mona (Corelan): exploiting tools integradas | ⏳ Pendiente |

---

## Verificación rápida

```bash
# Fase 1 — core engine (static analysis)
python3 test_phase1.py

# Fase 3 — Frida dynamic backend
python3 test_phase3.py
```

`test_phase1.py` carga `../clase1/crackme` y verifica disassembly, CFG y hex dump por consola.  
`test_phase3.py` requiere `../clase1/crackme_dyn` (compilado con `gcc -g -O0`): spawn, módulos, lectura de memoria, breakpoints y registros en tiempo real.

> **Nota**: Frida requiere que el target sea un binario dinámicamente linkeado. El `crackme` original (estático) no es compatible con la inyección de Frida.
