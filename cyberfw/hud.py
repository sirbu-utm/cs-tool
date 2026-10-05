"""The frame language every screen is built from: one instrument panel.

:class:`HudFrame` is a double-line frame whose border carries the banner's
green-to-cyan ramp. Section names sit in the border as tags (``╔═ Tools ═══``),
sections stack with ``╠═ Tag ═══╣`` dividers, and panes side by side meet with
``╤`` / ``╧``. A table inside a frame that uses :data:`HEAD` as its header style
gets a gradient header band. The launcher, the tool card, ``status``, the live
pipeline table, the closing summary and the record table all use it, so the app
reads as one control panel instead of loose tables.

Everything degrades honestly. Truecolor gets a smooth per-cell ramp, 256 and 16
colours get even bands of colours the terminal really has (a header band is one
solid colour there, so no word straddles two), and with no colour at all — a
pipe, CI, a file — the tags are plain words in the border. Glyphs stay inside
code page 437 (``═║╔╗╚╝╠╣╤╧╪│``), which the classic Windows console fonts carry.
Text on a coloured background is never bold: conhost and most terminals draw
bold black as grey, which is what made the first prototype's tags hard to read.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass

from rich.cells import cell_len
from rich.color import Color, blend_rgb
from rich.color_triplet import ColorTriplet
from rich.console import Console, ConsoleOptions, RenderableType, RenderResult
from rich.measure import Measurement
from rich.segment import Segment
from rich.style import Style
from rich.table import Table
from rich.text import Text

__all__ = [
    "ALERT",
    "BRAND",
    "ByWidth",
    "HEAD",
    "KEY",
    "EdgeRule",
    "HudFrame",
    "Palette",
    "Pane",
    "PathText",
    "hud_table",
    "join",
    "keycap",
]


@dataclass(frozen=True)
class Palette:
    """A horizontal colour ramp that degrades honestly.

    Truecolor gets a smooth per-cell blend; 256 and 16 colours get even bands
    of colours the terminal really has (a cell-by-cell downgrade collapses into
    one or two colours); no colour gets ``None`` and the caller draws plain.
    """

    start: ColorTriplet
    end: ColorTriplet
    bands_256: tuple[Color, ...]
    bands_16: tuple[Color, ...]

    def _bands(self, console: Console) -> tuple[Color, ...] | None:
        if console.color_system == "256":
            return self.bands_256
        if console.color_system in ("standard", "windows"):
            return self.bands_16
        return None

    def at(self, console: Console, x: int, width: int) -> Color | None:
        """The ramp's colour for cell ``x`` of ``width``; ``None`` without colour."""
        if console.color_system is None or console.no_color:
            return None
        bands = self._bands(console)
        if bands is None:
            return Color.from_triplet(blend_rgb(self.start, self.end, x / max(width - 1, 1)))
        return bands[min(x * len(bands) // max(width, 1), len(bands) - 1)]

    def band(self, console: Console, x: int, width: int) -> Color | None:
        """A header band's colour: the ramp in truecolor, one solid colour below
        it, so a word in the band never straddles two hard colour blocks."""
        if console.color_system is None or console.no_color:
            return None
        bands = self._bands(console)
        return self.at(console, x, width) if bands is None else bands[0]


#: The banner's ramp: green to cyan (the ends and bands of ``GradientRule``).
BRAND = Palette(
    ColorTriplet(0x2E, 0xD5, 0x73),
    ColorTriplet(0x2E, 0xC5, 0xD5),
    tuple(Color.from_ansi(n) for n in (40, 41, 42, 43, 44)),
    tuple(Color.parse(n) for n in ("green", "bright_green", "bright_cyan", "cyan")),
)
#: A run that failed: red to amber, so its closing frame reads as trouble
#: before a word of it is read.
ALERT = Palette(
    ColorTriplet(0xFF, 0x4D, 0x4D),
    ColorTriplet(0xFF, 0xA5, 0x3D),
    tuple(Color.from_ansi(n) for n in (196, 202, 208, 214)),
    tuple(Color.parse(n) for n in ("red", "bright_red", "bright_red", "yellow")),
)

#: The background a :data:`HEAD` band is marked with. A frame repaints exactly
#: this colour with its ramp, so it is one step off the ramp's own start (no
#: other style uses it); outside a frame it simply prints as a green band.
_HEAD_MARK = Color.from_rgb(0x2E, 0xD5, 0x74)

#: ``header_style`` for a table inside a :class:`HudFrame`: a gradient band.
HEAD = Style(color="black", bgcolor=_HEAD_MARK)

#: A key the user can type, drawn as a light key top. Only ever laid out side
#: by side on one line: terminal rows have no gap, so caps stacked in a column
#: fuse into one solid stripe.
KEY = Style(color="black", bgcolor="white")


@dataclass
class Pane:
    """One cell of a :class:`HudFrame` row: a body under an optional tag."""

    body: RenderableType
    title: str | Text | None = None
    #: Text right-aligned in the border above this pane.
    meta: str | Text | None = None
    #: Fixed body width; ``None`` shares what the fixed panes leave.
    width: int | None = None
    #: Cells between the frame line and the body (0 lets a header band touch it).
    pad: int = 1


class HudFrame:
    """A double-line frame: ramped border, tag titles, rows of panes.

    ``rows`` holds a :class:`Pane` (a full-width row) or a list of panes (side
    by side, split by ``│``). ``footer`` is right-aligned in the bottom border.
    ``title`` mirrors the first tag, for callers that ask a panel its title.
    """

    def __init__(
        self,
        rows: Sequence[Pane | Sequence[Pane]],
        *,
        footer: str | Text | None = None,
        palette: Palette = BRAND,
        expand: bool = True,
    ) -> None:
        self.rows: list[list[Pane]] = [[row] if isinstance(row, Pane) else list(row) for row in rows]
        self.footer = footer
        self.palette = palette
        self.expand = expand
        first = self.rows[0][0].title if self.rows and self.rows[0] else None
        self.title = _plain(first)

    # -- measuring --------------------------------------------------------
    @staticmethod
    def _overhead(row: list[Pane]) -> int:
        return 2 + sum(2 * pane.pad for pane in row) + (len(row) - 1)

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        if self.expand:
            return Measurement(options.max_width, options.max_width)
        widest = 0
        for row in self.rows:
            content = 0
            for pane in row:
                body = pane.width if pane.width is not None else Measurement.get(console, options, pane.body).maximum
                content += max(body, cell_len(_plain(pane.title)) + cell_len(_plain(pane.meta)) + 6)
            widest = max(widest, content + self._overhead(row))
        widest = max(widest, cell_len(_plain(self.footer)) + 8)
        width = min(widest, options.max_width)
        return Measurement(width, width)

    # -- rendering --------------------------------------------------------
    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width if self.expand else Measurement.get(console, options, self).maximum
        colours = [self.palette.at(console, x, width) for x in range(width)]
        line_styles = [Style(color=colour) if colour else Style() for colour in colours]
        layouts = [self._layout(row, width) for row in self.rows]
        splits = [[x for x, _w, _p in layout[1:]] for layout in layouts]

        for index, (row, layout) in enumerate(zip(self.rows, layouts, strict=True)):
            above = splits[index - 1] if index else []
            left, right = ("╔", "╗") if index == 0 else ("╠", "╣")
            border = _border(width, left, right, above, splits[index], line_styles)
            for pane, (x, w, _p) in zip(row, layout, strict=True):
                span = w + 2 * pane.pad  # border cells above this pane
                tag_end = _overlay_tag(console, border, pane.title, x + 2, span - 3, colours)
                if pane.meta:
                    meta_x = x + span - cell_len(_plain(pane.meta)) - 1
                    if meta_x > tag_end + 2:  # the tag wins; the meta is the extra
                        _overlay_text(console, border, pane.meta, meta_x)
            yield from _emit(border)
            yield from self._body(console, options, row, layout, width, line_styles)
        bottom = _border(width, "╚", "╝", splits[-1] if splits else [], [], line_styles)
        if self.footer:
            _overlay_text(console, bottom, self.footer, width - 3 - cell_len(_plain(self.footer)))
        yield from _emit(bottom)

    @staticmethod
    def _layout(row: list[Pane], width: int) -> list[tuple[int, int, int]]:
        """``(x of the pane's left line, body width, pad)`` per pane."""
        free = width - HudFrame._overhead(row)
        fixed = sum(pane.width for pane in row if pane.width is not None)
        flexible = sum(1 for pane in row if pane.width is None)
        share, extra = divmod(max(free - fixed, 0), max(flexible, 1))
        layout: list[tuple[int, int, int]] = []
        x = 0
        for pane in row:
            if pane.width is not None:
                body = pane.width
            else:
                body = share + (1 if extra > 0 else 0)
                extra -= 1
            layout.append((x, body, pane.pad))
            x += 1 + 2 * pane.pad + body
        return layout

    def _body(
        self,
        console: Console,
        options: ConsoleOptions,
        row: list[Pane],
        layout: list[tuple[int, int, int]],
        width: int,
        line_styles: list[Style],
    ) -> Iterator[Segment]:
        rendered = []
        for pane, (x, body, pad) in zip(row, layout, strict=True):
            lines = console.render_lines(pane.body, options.update(width=max(body, 1), height=None), pad=True)
            rendered.append([self._paint_band(console, line, x + 1 + pad, width) for line in lines])
        height = max(len(lines) for lines in rendered)
        for line_no in range(height):
            cells = [Segment("║", line_styles[0])]
            for column, (x, body, pad) in enumerate(layout):
                if column:
                    cells.append(Segment("│", line_styles[x]))
                lines = rendered[column]
                cells.append(Segment(" " * pad))
                cells.extend(lines[line_no] if line_no < len(lines) else [Segment(" " * body)])
                cells.append(Segment(" " * pad))
            cells.append(Segment("║", line_styles[width - 1]))
            yield from Segment.simplify(cells)
            yield Segment.line()

    def _paint_band(self, console: Console, line: list[Segment], x0: int, width: int) -> list[Segment]:
        """Repaint :data:`HEAD`'s marker background with the frame's ramp."""
        painted: list[Segment] = []
        x = x0
        for segment in line:
            style = segment.style
            if style is not None and style.bgcolor == _HEAD_MARK:
                for char in segment.text:
                    colour = self.palette.band(console, x, width)
                    painted.append(Segment(char, style + Style(bgcolor=colour) if colour else style))
                    x += cell_len(char)
            else:
                painted.append(segment)
                x += cell_len(segment.text)
        return list(Segment.simplify(painted))


def _plain(value: str | Text | None) -> str:
    if value is None:
        return ""
    return value.plain if isinstance(value, Text) else value


def _border(
    width: int, left: str, right: str, up: list[int], down: list[int], styles: list[Style]
) -> list[tuple[str, Style]]:
    cells: list[tuple[str, Style]] = []
    for x in range(width):
        if x == 0:
            char = left
        elif x == width - 1:
            char = right
        elif x in up and x in down:
            char = "╪"
        elif x in up:
            char = "╧"
        elif x in down:
            char = "╤"
        else:
            char = "═"
        cells.append((char, styles[x]))
    return cells


def _overlay_tag(
    console: Console, cells: list[tuple[str, Style]], title: str | Text | None, x: int, room: int, colours: list[Color | None]
) -> int:
    """Draw `` title `` as a tag at ``x`` (dark text on the border's colour, or
    reverse video without colour); returns where it ends. A title longer than
    ``room`` is shortened with an ellipsis, never dropped."""
    if not title:
        return x
    text = (title if isinstance(title, Text) else Text(title)).copy()
    text.truncate(max(room - 2, 1), overflow="ellipsis")
    colour = colours[min(x, len(colours) - 1)]
    tag = Style(color="black", bgcolor=colour) if colour else Style(reverse=True)
    padded = Text(" ") + text + Text(" ")
    padded.stylize_before(tag)
    _overlay_text(console, cells, padded, x, air=False)
    return x + padded.cell_len


def _overlay_text(
    console: Console, cells: list[tuple[str, Style]], text: str | Text, x: int, *, air: bool = True
) -> None:
    """Write ``text`` over border cells from ``x``. ``air`` keeps a blank cell
    either side (plain text); a tag carries its own padding. Text that does not
    fit is left out: the border stays whole rather than clipped."""
    text = text if isinstance(text, Text) else Text(text)
    flat = [(char, segment.style or Style()) for segment in text.render(console, end="") for char in segment.text]
    if x < 2 or x + len(flat) + 2 > len(cells):
        return
    if air:
        cells[x - 1] = (" ", cells[x - 1][1])
        cells[x + len(flat)] = (" ", cells[x + len(flat)][1])
    for offset, cell in enumerate(flat):
        cells[x + offset] = cell


def _emit(cells: list[tuple[str, Style]]) -> Iterator[Segment]:
    yield from Segment.simplify(Segment(char, style) for char, style in cells)
    yield Segment.line()


def keycap(key: str, label: str, *, slot: int = 4, label_style: str = "white") -> Text:
    """`` r ``  run pipeline — a key top, then what it does.

    The plain text is ``" r    run pipeline"``: the key padded to ``slot``
    cells and one space before the label, as the old sidebar printed it
    (``f"{key:<4} {label}"``), so a pipe, a log or a test reads the same.
    """
    trailing = " " if len(key) < slot else ""
    pad = " " * max(slot - len(key) - len(trailing), 0)
    return Text.assemble((" " + key + trailing, KEY), pad, " ", (label, label_style))


def hud_table(**kwargs: object) -> Table:
    """The table every frame holds: no lines of its own (the frame draws them),
    a gradient header band, one cell of air per column."""
    options: dict[str, object] = {
        "box": None,
        "show_edge": False,
        "pad_edge": True,
        "padding": (0, 1),
        "expand": True,
        "header_style": HEAD,
    }
    options.update(kwargs)
    return Table(**options)  # type: ignore[arg-type]


class EdgeRule:
    """The ramp drawn with a half block across the width. ``▄`` sits on the
    line below the art it underlines, so it never fuses with its last row.
    ``progress`` below 1 draws only the leading part, tipped with a bright cell."""

    def __init__(self, char: str = "▄", progress: float = 1.0) -> None:
        self.char = char
        self.progress = progress

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width
        drawn = int(width * min(max(self.progress, 0.0), 1.0))
        cells = []
        for x in range(drawn):
            colour = BRAND.at(console, x, width)
            tip = self.progress < 1 and x == drawn - 1
            cells.append(Segment(self.char, Style(color="bright_white", bold=True) if tip else Style(color=colour)))
        yield from Segment.simplify(cells)
        yield Segment.line()


class PathText:
    """A path that wraps only after a separator (``/`` or ``\\``), so a long
    report path breaks between directories, never inside ``report.json``."""

    def __init__(self, path: object, style: str = "white") -> None:
        self.path = str(path)
        self.style = style

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        parts = _path_parts(self.path)
        return Measurement(max((cell_len(p) for p in parts), default=1), cell_len(self.path))

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = max(options.max_width, 1)
        line = ""
        for part in _path_parts(self.path):
            if line and cell_len(line + part) > width:
                yield Text(line, style=self.style)
                line = ""
            while cell_len(part) > width:  # one directory longer than the column: fold it
                yield Text(part[:width], style=self.style)
                part = part[width:]
            line += part
        yield Text(line, style=self.style)


def _path_parts(path: str) -> list[str]:
    """``C:\\a\\b.json`` -> ``["C:\\", "a\\", "b.json"]``: each part keeps its separator."""
    parts: list[str] = []
    current = ""
    for char in path:
        current += char
        if char in "/\\":
            parts.append(current)
            current = ""
    if current or not parts:
        parts.append(current)
    return parts


class ByWidth:
    """A renderable that lays itself out for the width it is given: the same
    screen in a 120-column console, an 80-column CI log and a ``Live`` region."""

    def __init__(self, build: Callable[[int], RenderableType]) -> None:
        self.build = build

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        yield self.build(options.max_width)


def join(parts: Iterable[Text], separator: str = "   ") -> Text:
    """Join texts with an unstyled separator: ``Text.join`` would take a styled
    joiner as the base style of the result and tint every part with it."""
    return Text(separator).join(part for part in parts if part.plain)
