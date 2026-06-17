"""CFG panel — QGraphicsScene graph of BasicBlocks with branch arrows."""
from __future__ import annotations
import math
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QGraphicsView, QGraphicsScene,
    QGraphicsRectItem, QGraphicsTextItem,
)
from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import (
    QColor, QPen, QBrush, QPainter, QWheelEvent,
)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

_NODE_W       = 280
_NODE_PADDING = 8
_LINE_H       = 16
_H_GAP        = 60
_V_GAP        = 40

_COL_NODE_BG    = QColor(theme.BG_SURFACE)
_COL_NODE_BOR   = QColor(theme.BORDER)
_COL_NODE_BOR_A = QColor(theme.ACCENT)       # active block border
_COL_EDGE_JMP   = QColor(theme.FG_DIM)
_COL_EDGE_TRUE  = QColor(theme.GREEN)
_COL_EDGE_FALSE = QColor(theme.RED)
_COL_EDGE_FALL  = QColor(theme.FG_DIM)
_COL_ADDR       = QColor(theme.COL_ADDR)
_COL_INSN       = QColor(theme.FG)
_COL_MNEM_J     = QColor(theme.COL_JUMP)
_COL_MNEM_C     = QColor(theme.COL_CALL)
_COL_MNEM_R     = QColor(theme.COL_RET)


class _BlockItem(QGraphicsRectItem):
    def __init__(self, block, is_active: bool = False) -> None:
        lines = [f"  {hex(i.address):<12s}  {i.mnemonic} {i.op_str}" for i in block.instructions]
        height = _NODE_PADDING * 2 + len(lines) * _LINE_H + _LINE_H  # header row
        super().__init__(0, 0, _NODE_W, height)

        bor = _COL_NODE_BOR_A if is_active else _COL_NODE_BOR
        self.setPen(QPen(bor, 1.5))
        self.setBrush(QBrush(_COL_NODE_BG))

        # Header
        header = QGraphicsTextItem(f"  0x{block.start_addr:x}", self)
        header.setDefaultTextColor(_COL_ADDR)
        header.setFont(theme.mono_font(10))
        header.setPos(_NODE_PADDING, _NODE_PADDING)

        # Instructions
        for idx, insn in enumerate(block.instructions):
            y = _NODE_PADDING + _LINE_H + idx * _LINE_H
            addr_txt = QGraphicsTextItem(f"  {hex(insn.address):<12s}", self)
            addr_txt.setDefaultTextColor(QColor(theme.COL_ADDR))
            addr_txt.setFont(theme.mono_font(9))
            addr_txt.setPos(0, y)

            if insn.is_ret:   mnem_col = _COL_MNEM_R
            elif insn.is_call: mnem_col = _COL_MNEM_C
            elif insn.is_jump: mnem_col = _COL_MNEM_J
            else:              mnem_col = _COL_INSN

            mnem_txt = QGraphicsTextItem(f"  {insn.mnemonic}", self)
            mnem_txt.setDefaultTextColor(mnem_col)
            mnem_txt.setFont(theme.mono_font(9))
            mnem_txt.setPos(100, y)

            ops_txt = QGraphicsTextItem(f"  {insn.op_str}", self)
            ops_txt.setDefaultTextColor(QColor(theme.COL_OPS))
            ops_txt.setFont(theme.mono_font(9))
            ops_txt.setPos(160, y)


def _arrow(scene: QGraphicsScene, src: QPointF, dst: QPointF, colour: QColor) -> None:
    """Draw a line with a small arrowhead at dst."""
    pen = QPen(colour, 1.2, Qt.PenStyle.SolidLine)
    pen.setCosmetic(True)

    line = scene.addLine(src.x(), src.y(), dst.x(), dst.y(), pen)
    line.setZValue(-1)

    # Arrowhead
    angle = math.atan2(dst.y() - src.y(), dst.x() - src.x())
    size  = 8
    p1 = QPointF(
        dst.x() - size * math.cos(angle - math.pi / 6),
        dst.y() - size * math.sin(angle - math.pi / 6),
    )
    p2 = QPointF(
        dst.x() - size * math.cos(angle + math.pi / 6),
        dst.y() - size * math.sin(angle + math.pi / 6),
    )
    scene.addLine(dst.x(), dst.y(), p1.x(), p1.y(), pen)
    scene.addLine(dst.x(), dst.y(), p2.x(), p2.y(), pen)


def _layout_dag(G) -> dict[int, tuple[float, float]]:
    """
    Simple top-down layered layout.
    Returns {node_addr: (x, y)} positions for the top-left corner of each block.
    """
    import networkx as nx

    if G.number_of_nodes() == 0:
        return {}

    # Topological sort for layering (handle cycles with a simple BFS)
    try:
        order = list(nx.topological_sort(G))
    except nx.NetworkXUnfeasible:
        order = list(G.nodes)

    layers: dict[int, int] = {}
    for node in order:
        preds = list(G.predecessors(node))
        layers[node] = max((layers.get(p, 0) for p in preds), default=-1) + 1

    # Group by layer
    by_layer: dict[int, list[int]] = {}
    for node, layer in layers.items():
        by_layer.setdefault(layer, []).append(node)

    # Assign x/y
    positions: dict[int, tuple[float, float]] = {}
    block_heights: dict[int, float] = {
        addr: G.nodes[addr]["block"].size * _LINE_H + _NODE_PADDING * 2 + _LINE_H
        for addr in G.nodes
    }

    for layer, nodes in sorted(by_layer.items()):
        total_w = len(nodes) * _NODE_W + (len(nodes) - 1) * _H_GAP
        start_x = -total_w / 2
        y = layer * (max(block_heights.get(n, 80) for n in nodes) + _V_GAP)
        for i, node in enumerate(nodes):
            x = start_x + i * (_NODE_W + _H_GAP)
            positions[node] = (x, y)

    return positions


class CfgView(QGraphicsView):
    """Zoom with wheel, pan with middle-button or right-button drag."""

    def __init__(self, scene: QGraphicsScene) -> None:
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor(theme.BG_ALT)))

    def wheelEvent(self, event: QWheelEvent) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)


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

        # Draw nodes
        node_rects: dict[int, QRectF] = {}
        for node_addr, (x, y) in positions.items():
            block    = G.nodes[node_addr]["block"]
            is_active = (node_addr == self._active_addr)
            item      = _BlockItem(block, is_active)
            item.setPos(x, y)
            self._scene.addItem(item)
            node_rects[node_addr] = QRectF(x, y, _NODE_W, item.rect().height())

        # Draw edges
        for src, dst, data in G.edges(data=True):
            if src not in node_rects or dst not in node_rects:
                continue
            kind    = data.get("kind", "fall")
            colour  = {
                "true":  _COL_EDGE_TRUE,
                "false": _COL_EDGE_FALSE,
                "jmp":   _COL_EDGE_JMP,
                "fall":  _COL_EDGE_FALL,
            }.get(kind, _COL_EDGE_FALL)

            src_r = node_rects[src]
            dst_r = node_rects[dst]

            # Connect bottom-center of src to top-center of dst
            src_pt = QPointF(src_r.center().x(), src_r.bottom())
            dst_pt = QPointF(dst_r.center().x(), dst_r.top())
            _arrow(self._scene, src_pt, dst_pt, colour)

        self._view.fitInView(self._scene.itemsBoundingRect(),
                             Qt.AspectRatioMode.KeepAspectRatio)

    def highlight_block(self, addr: int) -> None:
        """Highlight the block containing addr and re-render."""
        self._active_addr = addr
        self.refresh(addr)
