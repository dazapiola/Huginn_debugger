"""Shellcraft Panel — pwntools shellcode generator with asm preview."""
from __future__ import annotations
import ast
import inspect
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QTextEdit, QLineEdit, QComboBox, QPushButton, QLabel,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QGuiApplication

from ui import theme

# ── curated template list ─────────────────────────────────────────────────────
# (display label, shellcraft attribute name)
_TEMPLATES: list[tuple[str, str]] = [
    ("sh          — /bin/sh",           "sh"),
    ("execve      — execute binary",    "execve"),
    ("cat         — read file to fd",   "cat"),
    ("exit        — exit(status)",      "exit"),
    ("nop         — NOP sled",          "nop"),
    ("trap        — int3 / break",      "trap"),
    ("pause       — pause syscall",     "pause"),
    ("connect     — TCP connect",       "connect"),
    ("bindsh      — bind shell",        "bindsh"),
    ("dup2        — dup fd",            "dup2"),
    ("read        — read(fd, buf, n)",  "read"),
    ("write       — write(fd, buf, n)", "write"),
]

_ARCHS = ["amd64", "i386"]

_ARCH_TO_PWNTOOL = {"amd64": "amd64", "i386": "i386"}


def _parse_arg(raw: str):
    """Convert a QLineEdit string to a Python value for shellcraft."""
    raw = raw.strip()
    if not raw or raw.lower() == "none":
        return None
    try:
        return ast.literal_eval(raw)
    except Exception:
        return raw  # treat as plain string


class ShellcraftPanel(QWidget):
    """Generate shellcode with pwntools shellcraft and preview the output."""

    shellcode_ready = pyqtSignal(bytes, str)  # (shellcode_bytes, template_name)

    def __init__(self, session) -> None:
        super().__init__()
        self._session      = session
        self._shellcode_bytes: bytes = b""
        self._arg_edits:  list[tuple[str, QLineEdit]] = []   # (param_name, edit)
        self._build_ui()
        self._on_template_changed()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── toolbar ──
        toolbar = QWidget()
        toolbar.setStyleSheet(
            f"background:{theme.BG_ALT}; border-bottom:1px solid {theme.BORDER};"
        )
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(6, 4, 6, 4)
        tl.setSpacing(6)

        tl.addWidget(QLabel("Arch:"))
        self._arch_combo = QComboBox()
        self._arch_combo.setFixedHeight(22)
        self._arch_combo.setFixedWidth(80)
        self._arch_combo.addItems(_ARCHS)
        self._arch_combo.setStyleSheet(_combo_style())
        self._arch_combo.currentTextChanged.connect(self._on_arch_changed)
        tl.addWidget(self._arch_combo)

        self._tmpl_combo = QComboBox()
        self._tmpl_combo.setFixedHeight(22)
        self._tmpl_combo.setFixedWidth(230)
        for label, _ in _TEMPLATES:
            self._tmpl_combo.addItem(label)
        self._tmpl_combo.setStyleSheet(_combo_style())
        self._tmpl_combo.currentIndexChanged.connect(self._on_template_changed)
        tl.addWidget(self._tmpl_combo)

        tl.addStretch()

        self._gen_btn = QPushButton("Generate")
        self._gen_btn.setFixedHeight(22)
        self._gen_btn.setStyleSheet(_btn_style(theme.ACCENT))
        self._gen_btn.clicked.connect(self._generate)
        tl.addWidget(self._gen_btn)

        self._copy_btn = QPushButton("Copy hex")
        self._copy_btn.setFixedHeight(22)
        self._copy_btn.setEnabled(False)
        self._copy_btn.setStyleSheet(_btn_style(theme.FG_DIM))
        self._copy_btn.clicked.connect(self._copy_hex)
        tl.addWidget(self._copy_btn)

        self._inject_btn = QPushButton("→ Console")
        self._inject_btn.setFixedHeight(22)
        self._inject_btn.setEnabled(False)
        self._inject_btn.setStyleSheet(_btn_style(theme.GREEN))
        self._inject_btn.clicked.connect(self._inject)
        tl.addWidget(self._inject_btn)

        root.addWidget(toolbar)

        # ── args area (scrollable) ──
        self._args_outer = QWidget()
        self._args_outer.setStyleSheet(
            f"background:{theme.BG_ALT}; border-bottom:1px solid {theme.BORDER};"
        )
        self._args_outer.setFixedHeight(72)
        args_wrap = QVBoxLayout(self._args_outer)
        args_wrap.setContentsMargins(8, 4, 8, 4)
        args_wrap.setSpacing(0)

        self._args_label = QLabel("Arguments")
        self._args_label.setStyleSheet(
            f"color:{theme.FG_DIM}; font-size:10px; font-weight:600;"
            f"text-transform:uppercase; letter-spacing:0.5px;"
        )
        args_wrap.addWidget(self._args_label)

        self._form_widget = QWidget()
        self._form_layout = QFormLayout(self._form_widget)
        self._form_layout.setContentsMargins(0, 0, 0, 0)
        self._form_layout.setSpacing(4)
        self._form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        args_wrap.addWidget(self._form_widget)
        root.addWidget(self._args_outer)

        # ── asm preview ──
        self._preview = QTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setFont(theme.mono_font(10))
        self._preview.setPlaceholderText("Assembly preview…")
        self._preview.setStyleSheet(
            f"background:{theme.BG}; color:{theme.FG}; border:none;"
        )
        root.addWidget(self._preview)

        # ── hex footer ──
        footer = QWidget()
        footer.setStyleSheet(
            f"background:{theme.BG_ALT}; border-top:1px solid {theme.BORDER};"
        )
        footer.setFixedHeight(28)
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(8, 4, 8, 4)
        fl.setSpacing(6)

        self._hex_label = QLabel("—")
        self._hex_label.setFont(theme.mono_font(9))
        self._hex_label.setStyleSheet(f"color:{theme.FG_DIM};")
        fl.addWidget(self._hex_label, stretch=1)

        self._size_label = QLabel("")
        self._size_label.setStyleSheet(
            f"color:{theme.ACCENT}; font-size:11px; font-weight:600;"
        )
        fl.addWidget(self._size_label)
        root.addWidget(footer)

    # ── slots ─────────────────────────────────────────────────────────────────

    def _on_arch_changed(self, arch: str) -> None:
        self._on_template_changed()

    def _on_template_changed(self) -> None:
        idx  = self._tmpl_combo.currentIndex()
        if idx < 0:
            return
        _, attr = _TEMPLATES[idx]
        fn = self._get_fn(attr)
        self._rebuild_args_form(fn)
        # Reset output
        self._preview.clear()
        self._hex_label.setText("—")
        self._size_label.setText("")
        self._shellcode_bytes = b""
        self._copy_btn.setEnabled(False)
        self._inject_btn.setEnabled(False)

    def _generate(self) -> None:
        import pwn
        idx  = self._tmpl_combo.currentIndex()
        _, attr = _TEMPLATES[idx]
        arch  = self._arch_combo.currentText()

        pwn.context.arch      = _ARCH_TO_PWNTOOL[arch]
        pwn.context.os        = "linux"
        pwn.context.log_level = "error"

        fn = self._get_fn(attr)
        if fn is None:
            self._preview.setPlainText(f"[!] '{attr}' not available for {arch}")
            return  # arch defined above, used in error message

        # Build positional args from the form
        kwargs: dict = {}
        for pname, edit in self._arg_edits:
            val = _parse_arg(edit.text())
            if val is not None:
                kwargs[pname] = val

        try:
            asm_source = fn(**kwargs)
        except Exception as exc:
            self._preview.setPlainText(f"[!] shellcraft error:\n{exc}")
            return

        # Multiply nop sled if count arg present
        try:
            self._shellcode_bytes = pwn.asm(asm_source)
        except Exception as exc:
            self._preview.setPlainText(f"[!] asm() error:\n{exc}")
            return

        self._preview.setPlainText(asm_source)
        n = len(self._shellcode_bytes)
        hex_str = self._shellcode_bytes.hex()
        display = " ".join(hex_str[i:i+2] for i in range(0, min(len(hex_str), 80), 2))
        if len(hex_str) > 80:
            display += " …"
        self._hex_label.setText(display)
        self._size_label.setText(f"{n} bytes")
        self._copy_btn.setEnabled(True)
        self._inject_btn.setEnabled(True)

    def _copy_hex(self) -> None:
        if not self._shellcode_bytes:
            return
        cb = QGuiApplication.clipboard()
        assert cb is not None
        cb.setText(self._shellcode_bytes.hex())
        self._copy_btn.setText("Copied!")
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(1500, lambda: self._copy_btn.setText("Copy hex"))

    def _inject(self) -> None:
        if not self._shellcode_bytes:
            return
        idx = self._tmpl_combo.currentIndex()
        _, attr = _TEMPLATES[idx]
        self.shellcode_ready.emit(self._shellcode_bytes, attr)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_fn(self, attr: str):
        """Return the shellcraft function for current arch, or None."""
        try:
            import pwn
            arch = self._arch_combo.currentText()
            pwn.context.arch      = _ARCH_TO_PWNTOOL[arch]
            pwn.context.log_level = "error"
            return getattr(pwn.shellcraft, attr, None)
        except Exception:
            return None

    def _rebuild_args_form(self, fn) -> None:
        """Repopulate the args form from the function signature."""
        # Clear old widgets
        while self._form_layout.rowCount():
            self._form_layout.removeRow(0)
        self._arg_edits.clear()

        if fn is None:
            self._args_label.setText("Arguments — not available for this arch")
            return

        try:
            sig = inspect.signature(fn)
        except (ValueError, TypeError):
            self._args_label.setText("Arguments")
            return

        params = [
            (name, p)
            for name, p in sig.parameters.items()
            if name not in ("args", "kwargs")
            and p.kind not in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
        ]

        if not params:
            self._args_label.setText("Arguments — none")
            return

        self._args_label.setText("Arguments")
        for name, param in params:
            edit = QLineEdit()
            edit.setFixedHeight(20)
            edit.setFont(theme.mono_font(10))
            edit.setStyleSheet(
                f"background:{theme.BG_SURFACE}; color:{theme.FG};"
                f"border:1px solid {theme.BORDER}; border-radius:3px; padding:0 4px;"
                f"font-size:10px;"
            )
            default = param.default
            if default is not inspect.Parameter.empty:
                edit.setText(str(default))
                edit.setPlaceholderText(f"default: {default!r}")
            else:
                edit.setPlaceholderText("required")

            lbl = QLabel(f"{name}:")
            lbl.setStyleSheet(f"color:{theme.FG_DIM}; font-size:10px;")
            self._form_layout.addRow(lbl, edit)
            self._arg_edits.append((name, edit))

    def refresh_arch(self) -> None:
        """Sync arch selector to the currently loaded binary."""
        b = self._session.binary
        if b is None:
            return
        arch_map = {"x86_64": "amd64", "x86": "i386"}
        pwn_arch = arch_map.get(b.arch)
        if pwn_arch and pwn_arch in _ARCHS:
            self._arch_combo.setCurrentText(pwn_arch)


# ── style helpers ──────────────────────────────────────────────────────────────

def _combo_style() -> str:
    return (
        f"font-size:11px; background:{theme.BG_SURFACE};"
        f"color:{theme.FG}; border:1px solid {theme.BORDER}; border-radius:3px;"
    )


def _btn_style(colour: str) -> str:
    return (
        f"font-size:11px; padding:0 8px; font-weight:600;"
        f"background:{theme.BG_SURFACE}; color:{colour};"
        f"border:1px solid {theme.BORDER}; border-radius:3px;"
    )
