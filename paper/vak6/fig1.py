# -*- coding: utf-8 -*-
"""Рисунок 1 статьи: модель нарушителя на стенде ArduPilot — стадии профиля, свидетельства, формирующие их
участники и точки внедрения целей Ц1–Ц6 (протокол, табл. 3.1 и 3.2; профиль scii-gate ardupilot_cubeorange).

matplotlib, Liberation Serif, оттенки серого, ширина 16 см, 600 dpi (TIFF и JPG для журнала, PNG для просмотра).

    python paper/vak6/fig1.py OUT_BASENAME
"""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 8})
CM = 1 / 2.54
EDGE, ARROW, MUTED = "#222222", "#333333", "#555555"
FILL_M, FILL, FILL_G = "#d4d4d4", "#f4f4f4", "#bdbdbd"

#: стадия, название, обязательная, строки (свидетельства, участник)
STAGES = [
    ("v1", "Исходный код", False, [("s11", "—"), ("s12", "REV"), ("s13", "SAST"), ("s14", "TAG")]),
    ("v2", "Сборка", True, [("s21, s22*, s23", "BLD"), ("s24", "IND")]),
    ("v3", "Хранилище", False, [("s31, s32", "REPO")]),
    ("v4", "Пакет", True, [("s41", "BLD"), ("s42*", "PKG"), ("s43", "TEST")]),
    ("v5", "Устройство", False, [("s51", "SB"), ("s52, s53", "гейт"), ("s54", "—")]),
]
EDGES = ["0,8", "1,0", "0,8", "0,8"]


def box(ax, x0, y0, w, h, fill="white", lw=0.9, z=3):
    ax.add_patch(FancyBboxPatch((x0, y0), w, h, boxstyle="round,pad=0,rounding_size=0.12",
                                linewidth=lw, edgecolor=EDGE, facecolor=fill, zorder=z))


def arrow(ax, x0, y0, x1, y1, lw=0.9, ls="-", z=2):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle="-|>", color=ARROW, lw=lw, linestyle=ls, shrinkA=0, shrinkB=0,
                                mutation_scale=8), zorder=z)


def goal(ax, x, y, label, who, side="right"):
    ax.add_patch(plt.Circle((x, y), 0.25, facecolor=FILL_G, edgecolor=EDGE, lw=0.8, zorder=6))
    ax.text(x, y, label, ha="center", va="center", fontsize=7.5, fontweight="bold", zorder=7)
    if side == "right":
        ax.text(x + 0.34, y, who, ha="left", va="center", fontsize=7.5, style="italic", color=MUTED, zorder=7)
    else:
        ax.text(x - 0.34, y, who, ha="right", va="center", fontsize=7.5, style="italic", color=MUTED, zorder=7)


def main(base):
    W, H = 16.0, 7.4
    fig = plt.figure(figsize=(W * CM, H * CM), dpi=600)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis("off")

    bw, gap, x0 = 2.75, 0.45, 0.22
    ytop, bh = 6.35, 2.0
    xs = [x0 + i * (bw + gap) for i in range(5)]
    for x, (vid, name, mand, rows) in zip(xs, STAGES):
        box(ax, x, ytop - bh, bw, bh, fill=FILL_M if mand else FILL, lw=1.7 if mand else 0.9)
        ax.text(x + bw / 2, ytop - 0.3, "%s  %s" % (vid, name), ha="center", va="center", fontsize=8.5,
                fontweight="bold", zorder=5)
        for j, (sids, who) in enumerate(rows):
            yy = ytop - 0.74 - j * 0.36
            ax.text(x + 0.14, yy, sids, ha="left", va="center", fontsize=8, zorder=5)
            ax.text(x + bw - 0.14, yy, who, ha="right", va="center", fontsize=7.5, style="italic", color=MUTED,
                    zorder=5)
    for i in range(4):
        arrow(ax, xs[i] + bw, ytop - 0.3, xs[i + 1], ytop - 0.3)
        ax.text(xs[i] + bw + gap / 2, ytop - 0.22, EDGES[i], ha="center", va="bottom", fontsize=7.5, zorder=4)

    # точки внедрения на стадиях
    gy = 6.95
    goal(ax, xs[1] + 0.45, gy, "Ц2", "ARC")
    goal(ax, xs[1] + 1.85, gy, "Ц3", "DEP")
    for gx in (xs[1] + 0.45, xs[1] + 1.85):
        arrow(ax, gx, gy - 0.25, gx, ytop, lw=0.8)
    by = ytop - bh - 0.5
    goal(ax, xs[1] + bw / 2, by, "Ц1", "BLD")
    goal(ax, xs[2] + bw / 2, by, "Ц4", "REPO")
    for gx in (xs[1] + bw / 2, xs[2] + bw / 2):
        arrow(ax, gx, by + 0.25, gx, ytop - bh, lw=0.8)

    # комплект: свидетельства всех стадий и пакет уходят в канал
    yc = 3.25
    for i in (0, 3, 4):
        ax.plot([xs[i] + 0.5, xs[i] + 0.5], [ytop - bh, yc], color=ARROW, lw=0.8, ls=(0, (3, 2)), zorder=1)
    for i in (1, 2):
        ax.plot([xs[i] + 0.35, xs[i] + 0.35], [ytop - bh, yc], color=ARROW, lw=0.8, ls=(0, (3, 2)), zorder=1)
    ax.plot([xs[0] + 0.5, xs[4] + 0.5], [yc, yc], color=ARROW, lw=0.8, ls=(0, (3, 2)), zorder=1)
    ax.text(6.4, yc - 0.12, "комплект: пакет и свидетельства всех стадий", ha="left", va="top",
            fontsize=7.5, style="italic", color=MUTED)

    yb = 2.05
    cx0, cw = 1.55, 4.4
    box(ax, cx0, yb - 0.45, cw, 0.9)
    ax.text(cx0 + cw / 2, yb + 0.13, "Канал доставки комплекта (CH)", ha="center", va="center", fontsize=8,
            zorder=5)
    ax.text(cx0 + cw / 2, yb - 0.2, "скрыть, повторить, заменить", ha="center", va="center", fontsize=7.5,
            style="italic", color=MUTED, zorder=5)
    arrow(ax, cx0 + cw / 2, yc, cx0 + cw / 2, yb + 0.45, lw=0.8, ls=(0, (3, 2)))
    goal(ax, 0.5, yb + 0.3, "Ц5", "", side="left")
    goal(ax, 0.5, yb - 0.3, "Ц6", "", side="left")
    arrow(ax, 0.75, yb + 0.3, cx0, yb + 0.3, lw=0.8)
    arrow(ax, 0.75, yb - 0.3, cx0, yb - 0.3, lw=0.8)

    gx0, gw = 6.6, 3.95
    box(ax, gx0, yb - 0.55, gw, 1.1, fill=FILL_G, lw=1.2)
    ax.text(gx0 + gw / 2, yb + 0.19, "Модуль допуска получателя", ha="center", va="center", fontsize=8,
            fontweight="bold", zorder=5)
    ax.text(gx0 + gw / 2, yb - 0.17, "политика и правило П1–П11", ha="center", va="center", fontsize=7.5, zorder=5)
    dx0, dw = 11.3, 4.45
    box(ax, dx0, yb - 0.45, dw, 0.9)
    ax.text(dx0 + dw / 2, yb + 0.13, "допуск, ручное рассмотрение,", ha="center", va="center", fontsize=7.5,
            zorder=5)
    ax.text(dx0 + dw / 2, yb - 0.2, "запрос свидетельств, отказ", ha="center", va="center", fontsize=7.5, zorder=5)
    arrow(ax, cx0 + cw, yb, gx0, yb)
    arrow(ax, gx0 + gw, yb, dx0, yb)

    # легенда
    ly = 0.72
    ax.text(0.22, ly, "Серый фон и толстая рамка — обязательная стадия, * — обязательное свидетельство, курсив — "
            "участник, формирующий свидетельство", ha="left", va="center", fontsize=7.5)
    ax.text(0.22, ly - 0.36, "(гейт — проверка самим модулем допуска по образу), на рёбрах — веса связей стадий, "
            "Ц1–Ц6 — точки внедрения целей атаки", ha="left", va="center", fontsize=7.5)
    for ext in ("png", "tif", "jpg"):
        kw = {"pil_kwargs": {"compression": "tiff_lzw"}} if ext == "tif" else {}
        fig.savefig("%s.%s" % (base, ext), dpi=600, **kw)
    plt.close(fig)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fig1")
