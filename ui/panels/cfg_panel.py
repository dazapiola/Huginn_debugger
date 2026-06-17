"""CFG panel — draggable QGraphicsItem blocks with live-updating arrows."""
from __future__ import annotations
import math
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QGraphicsView, QGraphicsScene,
    QGraphicsRectItem, QGraphicsTextItem, QGraphicsItem,
)
from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import (
    QColor, QPen, QBrush, QPainter, QWheelEvent,
)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

# ── geometry constants ────────────────────────────────────────────────────────

_NODE_W       = 460   # wide enough for long operands
_NODE_PADDING = 8
_LINE_H       = 16
_H_GAP        = 80    # horizontal gap between sibling blocks
_V_GAP        = 50    # vertical gap between layers

# Column x-offsets inside a block (pixels from block left edge)
_X_ADDR = 4
_X_MNEM = 148   # after "  0x<12 hex chars>  " @ ~6px/char
_X_OPS  = 220   # after typical 5-char mnemonic

# ── colours ───────────────────────────────────────────────────────────────────

_C_NODE_BG    = QColor(theme.BG_SURFACE)
_C_NODE_BOR   = QColor(theme.BORDER)
_C_NODE_BOR_A = QColor(theme.ACCENT)
_C_EDGE_JMP   = QColor(theme.FG_DIM)
_C_EDGE_TRUE  = QColor(theme.GREEN)
_C_EDGE_FALSE = QColor(theme.RED)
_C_EDGE_FALL  = QColor(theme.FG_DIM)
_C_ADDR       = QColor(theme.COL_ADDR)
_C_FG         = QColor(theme.FG)
_C_MNEM_J     = QColor(theme.COL_JUMP)
_C_MNEM_C     = QColor(theme.COL_CALL)
_C_MNEM_R     = QColor(theme.COL_RET)


# ── arrow item (live-updating when blocks are dragged) ────────────────────────

class _ArrowItem(QGraphicsItem):
    """Arrow from the bottom-center of src to the top-center of dst.
    Redraws itself automatically when either block is moved."""

    def __init__(self, src: "_BlockItem", dst: "_BlockItem",
                 colour: QColor) -> None:
        super().__init__()
        self._src    = src
        self._dst    = dst
        self._colour = colour
        self._pen    = QPen(colour, 1.4, Qt.PenStyle.SolidLine)
        self._pen.setCosmetic(True)
        self.setZValue(-1)
        src.register_arrow(self)
        dst.register_arrow(self)

    # QGraphicsItem protocol ──────────────────────────────────────────────────

    def boundingRect(self) -> QRectF:
        sp, dp = self._endpoints()
        r = QRectF(
            min(sp.x(), dp.x()),
            min(sp.y(), dp.y()),
            abs(dp.x() - sp.x()),
            abs(dp.y() - sp.y()),
        )
        return r.adjusted(-12, -12, 12, 12)

    def paint(self, painter: QPainter, _option, _widget=None) -> None:
        sp, dp = self._endpoints()
        painter.setPen(self._pen)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.drawLine(sp, dp)
        # Arrowhead at dst
        angle = math.atan2(dp.y() - sp.y(), dp.x() - sp.x())
        size  = 9
        p1 = QPointF(dp.x() - size * math.cos(angle - math.pi / 6),
                     dp.y() - size * math.sin(angle - math.pi / 6))
        p2 = QPointF(dp.x() - size * math.cos(angle + math.pi / 6),
                     dp.y() - size * math.sin(angle + math.pi / 6))
        painter.drawLine(dp, p1)
        painter.drawLine(dp, p2)

    # Called by blocks on move ────────────────────────────────────────────────

    def notify_block_moved(self) -> None:
        self.prepareGeometryChange()
        self.update()

    # Helpers ─────────────────────────────────────────────────────────────────

    def _endpoints(self) -> tuple[QPointF, QPointF]:
        sr = self._src.sceneBoundingRect()
        dr = self._dst.sceneBoundingRect()
        return (
            QPointF(sr.center().x(), sr.bottom()),
            QPointF(dr.center().x(), dr.top()),
        )


# ── block item ────────────────────────────────────────────────────────────────

class _BlockItem(QGraphicsRectItem):
    """A draggable basic-block node."""

    def __init__(self, block, is_active: bool = False) -> None:
        n_insns = len(block.instructions)
        height  = _NODE_PADDING * 2 + (n_insns + 1) * _LINE_H  # +1 header row
        super().__init__(0, 0, _NODE_W, height)

        bor = _C_NODE_BOR_A if is_active else _C_NODE_BOR
        self.setPen(QPen(bor, 1.5))
        self.setBrush(QBrush(_C_NODE_BG))

        # Make the block draggable and emit position-changed events
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)

        self._arrows: list[_ArrowItem] = []

        # Header row
        hdr = QGraphicsTextItem(f"  0x{block.start_addr:016x}", self)
        hdr.setDefaultTextColor(_C_ADDR)
        hdr.setFont(theme.mono_font(9))
        hdr.setPos(_X_ADDR, _NODE_PADDING)

        # Instruction rows
        for idx, insn in enumerate(block.instructions):
            y = _NODE_PADDING + _LINE_H + idx * _LINE_H

            addr_t = QGraphicsTextItem(f"  {hex(insn.address)}", self)
            addr_t.setDefaultTextColor(_C_ADDR)
            addr_t.setFont(theme.mono_font(9))
            addr_t.setPos(_X_ADDR, y)

            if insn.is_ret:    mc = _C_MNEM_R
            elif insn.is_call: mc = _C_MNEM_C
            elif insn.is_jump: mc = _C_MNEM_J
            else:              mc = _C_FG

            mnem_t = QGraphicsTextItem(insn.mnemonic, self)
            mnem_t.setDefaultTextColor(mc)
            mnem_t.setFont(theme.mono_font(9))
            mnem_t.setPos(_X_MNEM, y)

            ops_t = QGraphicsTextItem(insn.op_str, self)
            ops_t.setDefaultTextColor(QColor(theme.COL_OPS))
            ops_t.setFont(theme.mono_font(9))
            ops_t.setPos(_X_OPS, y)

    # Arrow registry ──────────────────────────────────────────────────────────

    def register_arrow(self, arrow: _ArrowItem) -> None:
        self._arrows.append(arrow)

    # Notify connected arrows on drag ─────────────────────────────────────────

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for arrow in self._arrows:
                arrow.notify_block_moved()
        return super().itemChange(change, value)


# ── layout ────────────────────────────────────────────────────────────────────

def _block_height(block) -> float:
    return _NODE_PADDING * 2 + (len(block.instructions) + 1) * _LINE_H


def _layout_dag(G) -> dict[int, tuple[float, float]]:
    """
    Top-down layered layout.
    Returns {node_addr: (x, y)} for the top-left corner of each block.
    """
    import networkx as nx

    if G.number_of_nodes() == 0:
        return {}

    try:
        order = list(nx.topological_sort(G))
    except nx.NetworkXUnfeasible:
        order = list(G.nodes)

    # Assign each node to a layer (longest path from entry)
    layers: dict[int, int] = {}
    for node in order:
        preds = list(G.predecessors(node))
        layers[node] = max((layers.get(p, 0) for p in preds), default=-1) + 1

    # Group nodes by layer
    by_layer: dict[int, list[int]] = {}
    for node, layer in layers.items():
        by_layer.setdefault(layer, []).append(node)

    # Compute cumulative y per layer (use actual rendered block heights)
    layer_y: dict[int, float] = {}
    current_y = 0.0
    for layer_idx in sorted(by_layer.keys()):
        layer_y[layer_idx] = current_y
        max_h = max(
            _block_height(G.nodes[n]["block"])
            for n in by_layer[layer_idx]
        )
        current_y += max_h + _V_GAP

    # Assign x positions (center the layer horizontally)
    positions: dict[int, tuple[float, float]] = {}
    for layer_idx, nodes in sorted(by_layer.items()):
        count    = len(nodes)
        total_w  = count * _NODE_W + (count - 1) * _H_GAP
        start_x  = -total_w / 2.0
        y        = layer_y[layer_idx]
        for i, node in enumerate(sorted(nodes)):
            x = start_x + i * (_NODE_W + _H_GAP)
            positions[node] = (x, y)

    return positions


# ── view ──────────────────────────────────────────────────────────────────────

class CfgView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene) -> None:
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor(theme.BG_ALT)))

    def wheelEvent(self, event: QWheelEvent) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)


# ── panel ─────────────────────────────────────────────────────────────────────

class CfgPanel(QWidget):
    def __init__(self, session) -> None:
        super().__init__()
        self._session      = session
        self._active_addr: int | None = None
        self._scene = QGraphicsScene()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._view = CfgView(self._scene)
        layout.addWidget(self._view)

    def refresh(self, addr: int | None = None) -> None:
        b = self._session.binary
        if b is None:
            return

        target = addr or self._session.current_address or b.entry_point
        G = self._session.build_cfg_at(target, max_bytes=0x1000)
        if G is None or G.number_of_nodes() == 0:
            return

        self._scene.clear()
        positions = _layout_dag(G)

        # Create block items
        block_items: dict[int, _BlockItem] = {}
        for node_addr, (x, y) in positions.items():
            block   = G.nodes[node_addr]["block"]
            is_act  = (node_addr == self._active_addr)
            item    = _BlockItem(block, is_act)
            item.setPos(x, y)
            self._scene.addItem(item)
            block_items[node_addr] = item

        # Create arrow items (they self-register on both endpoints)
        _edge_colours = {
            "true":  _C_EDGE_TRUE,
            "false": _C_EDGE_FALSE,
            "jmp":   _C_EDGE_JMP,
            "fall":  _C_EDGE_FALL,
        }
        for src, dst, data in G.edges(data=True):
            if src not in block_items or dst not in block_items:
                continue
            colour = _edge_colours.get(data.get("kind", "fall"), _C_EDGE_FALL)
            arrow  = _ArrowItem(block_items[src], block_items[dst], colour)
            self._scene.addItem(arrow)

        self._view.fitInView(self._scene.itemsBoundingRect(),
                             Qt.AspectRatioMode.KeepAspectRatio)

    def highlight_block(self, addr: int) -> None:
        self._active_addr = addr
        self.refresh(addr)
