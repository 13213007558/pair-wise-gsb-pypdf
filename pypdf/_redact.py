"""
Permanent redaction (redact-and-sanitize) of sensitive PDF content.

Unlike visual masking (white/black rectangles drawn on top of the content),
the functions in this module truly remove sensitive text from a document:

* Text-showing operations (Tj, TJ, ' and ") that match the requested texts
  or regions are deleted from page content streams, from (nested) Form
  XObjects and from annotation appearance streams.
* Resources that are no longer referenced after the removal (fonts, images,
  Form XObjects) are pruned from the resource dictionaries and their
  indirect objects are blanked out.
* Remaining occurrences of the sensitive strings in metadata, annotations
  and other string objects are stripped.
* The serialized output is re-read and verified: if any sensitive string can
  still be found in extracted text, decompressed streams or any object, an
  error is raised instead of reporting a fake success.

Documents that are encrypted, digitally signed, or that show text with
unsupported font encodings are rejected *before* any modification takes
place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, Optional, Sequence, Union, cast

from ._font import Font
from ._page import PageObject
from ._reader import PdfReader
from ._text_extraction import mult
from ._writer import PdfWriter
from .errors import RedactionError, RedactionNotSupportedError
from .generic import (
    ArrayObject,
    ByteStringObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    IndirectObject,
    NullObject,
    PdfObject,
    StreamObject,
    TextStringObject,
    encode_pdfdocencoding,
)

__all__ = ["RedactionHit", "RedactionReport", "redact_and_sanitize"]

_MATRIX_IDENTITY = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
_SUPPORTED_FONT_SUBTYPES = {"Type1", "MMType1", "TrueType", "Type0"}
_MAX_XOBJECT_DEPTH = 32
_PATH_CONSTRUCTION_OPERATORS = {b"m", b"l", b"c", b"v", b"y", b"h", b"re"}
_PATH_PAINTING_OPERATORS = {
    b"S", b"s", b"f", b"F", b"f*", b"B", b"B*", b"b", b"b*",
}
_PATH_RESET_OPERATORS = {b"n", b"W", b"W*"}

_Rectangle = tuple[float, float, float, float]


@dataclass(frozen=True)
class RedactionHit:
    """
    A single piece of content that was removed by redact_and_sanitize().

    Attributes:
        page_index: Zero-based index of the page on which the hit occurred.
        rect: Bounding box (x0, y0, x1, y1) of the removed content, in the
            page's default user space (the coordinate system of /MediaBox,
            unaffected by /Rotate).
        text: The matched sensitive text, or "" if the hit was purely
            region-based (e.g. an overlapping image).
        source: Where the hit was found: "content", "xobject",
            "annotation", "image" or "path".

    """

    page_index: int
    rect: _Rectangle
    text: str
    source: str


@dataclass
class RedactionReport:
    """Summary of a redact_and_sanitize() run."""

    hits: list[RedactionHit] = field(default_factory=list)

    @property
    def hit_count(self) -> int:
        """Total number of removed content pieces."""
        return len(self.hits)

    @property
    def pages(self) -> list[int]:
        """Sorted list of zero-based page indices affected by the redaction."""
        return sorted({hit.page_index for hit in self.hits})


@dataclass
class _Context:
    """Coordinate context in which a content stream is rendered."""

    page_index: int
    # Matrix mapping the stream local coordinates to the page default
    # user space.
    matrix: list[float]
    regions: tuple[_Rectangle, ...]


class _GraphicsState:
    __slots__ = (
        "ctm", "tm", "tlm", "font_name", "font_size",
        "tc", "tw", "tz", "tl", "ts",
    )

    def __init__(self) -> None:
        self.ctm = list(_MATRIX_IDENTITY)
        self.tm = list(_MATRIX_IDENTITY)
        self.tlm = list(_MATRIX_IDENTITY)
        self.font_name: Optional[str] = None
        self.font_size = 0.0
        self.tc = 0.0
        self.tw = 0.0
        self.tz = 1.0
        self.tl = 0.0
        self.ts = 0.0

    def copy(self) -> "_GraphicsState":
        clone = _GraphicsState()
        for attr in self.__slots__:
            value = getattr(self, attr)
            setattr(clone, attr, list(value) if isinstance(value, list) else value)
        return clone


class _StreamRecord:
    """Bookkeeping for one content stream that is being rewritten."""

    __slots__ = (
        "key", "stream", "resources", "page", "page_index", "referrer",
        "referrers",
        "operations", "remove", "dead", "matched",
        "final_ops", "used_fonts", "used_xobjects",
    )

    def __init__(
        self,
        key: object,
        stream: Optional[StreamObject],
        resources: DictionaryObject,
        operations: list[tuple[Any, bytes]],
        page: Optional[PageObject] = None,
        page_index: int = -1,
        referrer: Optional[tuple[int, str]] = None,
    ) -> None:
        self.key = key
        self.stream = stream
        self.resources = resources
        self.operations = operations
        self.page = page
        self.page_index = page_index
        # (id of the resources dictionary, XObject name) through which this
        # stream is referenced; None for page content streams.
        self.referrer = referrer
        # All (resources id, XObject name) pairs through which this stream
        # is referenced; a shared XObject may have several.
        self.referrers: set[tuple[int, str]] = (
            {referrer} if referrer is not None else set()
        )
        self.remove: set[int] = set()
        self.dead = False
        # (operation index, page index, rectangle) triples already reported.
        self.matched: set[tuple[int, int, _Rectangle]] = set()
        self.final_ops: list[tuple[Any, bytes]] = []
        self.used_fonts: set[str] = set()
        self.used_xobjects: set[str] = set()


def _apply_matrix(matrix: Sequence[float], x: float, y: float) -> tuple[float, float]:
    return (
        matrix[0] * x + matrix[2] * y + matrix[4],
        matrix[1] * x + matrix[3] * y + matrix[5],
    )


def _normalize_rectangle(rect: Sequence[float]) -> _Rectangle:
    x0, y0, x1, y1 = (float(v) for v in rect)
    return min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)


def _rectangles_intersect(a: _Rectangle, b: _Rectangle) -> bool:
    return a[0] <= b[2] and a[2] >= b[0] and a[1] <= b[3] and a[3] >= b[1]


def _byte_needles(texts: Sequence[str]) -> set[bytes]:
    needles: set[bytes] = set()
    for target in texts:
        for encoding in ("utf-8", "utf-16-be", "utf-16-le"):
            needles.add(target.encode(encoding))
        try:
            needles.add(encode_pdfdocencoding(target))
        except Exception:
            pass
        try:
            needles.add(target.encode("latin-1"))
        except Exception:
            pass
    needles.discard(b"")
    return needles


def _page_resources(page: DictionaryObject) -> DictionaryObject:
    node: Optional[DictionaryObject] = page
    while node is not None:
        resources = node.get("/Resources")
        if resources is not None:
            return cast(DictionaryObject, resources.get_object())
        parent = node.get("/Parent")
        node = parent.get_object() if parent is not None else None
    return DictionaryObject()


class _RedactionEngine:
    def __init__(
        self,
        writer: PdfWriter,
        texts: list[str],
        regions: dict[int, tuple[_Rectangle, ...]],
        remove_overlapping_images: bool,
        remove_overlapping_paths: bool,
        draw_black_boxes: bool,
    ) -> None:
        self.writer = writer
        self.texts = texts
        self.regions = regions
        self.remove_overlapping_images = remove_overlapping_images
        self.remove_overlapping_paths = remove_overlapping_paths
        self.draw_black_boxes = draw_black_boxes
        self.hits: list[RedactionHit] = []
        self._streams: dict[object, _StreamRecord] = {}
        self._active: set[object] = set()
        self._resources: dict[int, DictionaryObject] = {}
        self._fonts: dict[int, Font] = {}
        self._page_boxes: dict[int, list[_Rectangle]] = {}
        self._needles = _byte_needles(texts)

    # ------------------------------------------------------------------
    # Main driver
    # ------------------------------------------------------------------
    def run(self) -> None:
        for index, page in enumerate(self.writer.pages):
            self._process_page(page, index)
        self._finalize_operations()
        self._prune_resources()
        self._rebuild_streams()
        self._sanitize_strings()

    def _process_page(self, page: PageObject, page_index: int) -> None:
        regions = self.regions.get(page_index, ())
        context = _Context(page_index, list(_MATRIX_IDENTITY), regions)
        contents = page.get_contents()
        if contents is not None:
            resources = _page_resources(page)
            record = self._register_stream(
                ("page", page_index),
                None,
                resources,
                content=contents,
                page=page,
                page_index=page_index,
            )
            self._walk(record, [context], 0)
        self._process_annotations(page, page_index, regions)

    def _process_annotations(
        self,
        page: PageObject,
        page_index: int,
        regions: tuple[_Rectangle, ...],
    ) -> None:
        annots = page.get("/Annots")
        if not annots:
            return
        page_resources = _page_resources(page)
        for annot_ref in annots.get_object():
            try:
                annot = annot_ref.get_object()
            except Exception:
                continue
            appearance = annot.get("/AP")
            if appearance is None:
                continue
            appearance = appearance.get_object()
            streams: list[StreamObject] = []
            for key in ("/N", "/R", "/D"):
                value = appearance.get(key)
                if value is None:
                    continue
                value = value.get_object()
                if isinstance(value, StreamObject):
                    streams.append(value)
                elif isinstance(value, DictionaryObject):
                    streams.extend(
                        cast(StreamObject, sub.get_object())
                        for sub in value.values()
                        if isinstance(sub.get_object(), StreamObject)
                    )
            for appearance_stream in streams:
                matrix = [
                    float(v)
                    for v in appearance_stream.get("/Matrix", _MATRIX_IDENTITY)
                ]
                resources = appearance_stream.get("/Resources")
                stream_resources = cast(
                    DictionaryObject,
                    resources.get_object() if resources is not None else page_resources,
                )
                record = self._register_stream(
                    self._stream_key(appearance_stream),
                    appearance_stream,
                    stream_resources,
                )
                self._walk(record, [_Context(page_index, matrix, regions)], 0)

    # ------------------------------------------------------------------
    # Stream registration
    # ------------------------------------------------------------------
    @staticmethod
    def _stream_key(stream: PdfObject) -> tuple[Any, ...]:
        reference = getattr(stream, "indirect_reference", None)
        if reference is not None:
            return ("indirect", reference.idnum, reference.generation)
        return ("direct", id(stream))

    def _register_stream(
        self,
        key: object,
        stream: Optional[StreamObject],
        resources: DictionaryObject,
        content: Optional[ContentStream] = None,
        page: Optional[PageObject] = None,
        page_index: int = -1,
        referrer: Optional[tuple[int, str]] = None,
    ) -> _StreamRecord:
        existing = self._streams.get(key)
        if existing is not None:
            return existing
        if content is None:
            assert stream is not None
            content = ContentStream(stream, self.writer)
        try:
            operations = content.operations
        except Exception as exc:
            raise RedactionError(
                f"Could not parse a content stream: {exc}"
            ) from exc
        record = _StreamRecord(
            key, stream, resources, operations, page, page_index, referrer
        )
        self._streams[key] = record
        self._resources[id(resources)] = resources
        return record

    # ------------------------------------------------------------------
    # Content stream walking
    # ------------------------------------------------------------------
    def _walk(
        self, record: _StreamRecord, contexts: list[_Context], depth: int
    ) -> None:
        if depth > _MAX_XOBJECT_DEPTH:
            raise RedactionError(
                f"Form XObject nesting exceeds {_MAX_XOBJECT_DEPTH} levels."
            )
        if record.key in self._active:
            # Cyclic XObject reference; nothing more to do.
            return
        self._active.add(record.key)
        try:
            self._walk_operations(record, contexts, depth)
        finally:
            self._active.discard(record.key)

    def _walk_operations(
        self, record: _StreamRecord, contexts: list[_Context], depth: int
    ) -> None:
        state = _GraphicsState()
        stack: list[_GraphicsState] = []
        path_points: Optional[list[tuple[float, float]]] = None
        path_start = 0
        for index, (operands, operator) in enumerate(record.operations):
            if operator == b"q":
                stack.append(state.copy())
            elif operator == b"Q":
                if stack:
                    state = stack.pop()
            elif operator == b"cm":
                try:
                    matrix = [float(o) for o in operands[:6]]
                    state.ctm = mult(matrix, state.ctm)
                except (TypeError, ValueError, IndexError):
                    pass
            elif operator == b"BT":
                state.tm = list(_MATRIX_IDENTITY)
                state.tlm = list(_MATRIX_IDENTITY)
            elif operator == b"Tf":
                if len(operands) >= 1:
                    state.font_name = str(operands[0])
                if len(operands) >= 2:
                    try:
                        state.font_size = float(operands[1])
                    except (TypeError, ValueError):
                        pass
            elif operator == b"Tc":
                state.tc = _as_float(operands, 0, state.tc)
            elif operator == b"Tw":
                state.tw = _as_float(operands, 0, state.tw)
            elif operator == b"Tz":
                state.tz = _as_float(operands, 0, state.tz * 100.0) / 100.0
            elif operator == b"TL":
                state.tl = _as_float(operands, 0, state.tl)
            elif operator == b"Ts":
                state.ts = _as_float(operands, 0, state.ts)
            elif operator == b"Td":
                self._move_text_line(
                    state,
                    _as_float(operands, 0, 0.0),
                    _as_float(operands, 1, 0.0),
                )
            elif operator == b"TD":
                ty = _as_float(operands, 1, 0.0)
                state.tl = -ty
                self._move_text_line(state, _as_float(operands, 0, 0.0), ty)
            elif operator == b"Tm":
                try:
                    matrix = [float(o) for o in operands[:6]]
                    if len(matrix) == 6:
                        state.tm = matrix
                        state.tlm = list(matrix)
                except (TypeError, ValueError):
                    pass
            elif operator == b"T*":
                self._move_text_line(state, 0.0, -state.tl)
            elif operator in (b"Tj", b"TJ", b"'", b'"'):
                self._handle_text_showing(record, state, index, operands, operator, contexts)
            elif operator == b"Do":
                self._handle_do(record, state, index, operands, contexts, depth)
            elif operator == b"INLINE IMAGE" and self.remove_overlapping_images:
                self._check_image_hit(record, state, index, contexts)
            elif operator in _PATH_CONSTRUCTION_OPERATORS:
                if path_points is None:
                    path_points = []
                    path_start = index
                path_points.extend(_path_operand_points(operator, operands))
            elif operator in _PATH_PAINTING_OPERATORS:
                if self.remove_overlapping_paths and path_points:
                    self._check_path_hit(
                        record, state, path_start, index, path_points, contexts
                    )
                path_points = None
            elif operator in _PATH_RESET_OPERATORS:
                path_points = None

    @staticmethod
    def _move_text_line(state: _GraphicsState, tx: float, ty: float) -> None:
        state.tlm[4] += tx * state.tlm[0] + ty * state.tlm[2]
        state.tlm[5] += tx * state.tlm[1] + ty * state.tlm[3]
        state.tm = list(state.tlm)

    # ------------------------------------------------------------------
    # Text showing
    # ------------------------------------------------------------------
    def _handle_text_showing(
        self,
        record: _StreamRecord,
        state: _GraphicsState,
        index: int,
        operands: list[Any],
        operator: bytes,
        contexts: list[_Context],
    ) -> None:
        if operator == b"'":
            # Move to next line, then show text.
            self._move_text_line(state, 0.0, -state.tl)
            show_operands = operands[:1]
        elif operator == b'"':
            # Set word/character spacing, move to next line, then show text.
            if len(operands) >= 3:
                state.tw = _as_float(operands, 0, state.tw)
                state.tc = _as_float(operands, 1, state.tc)
                show_operands = [operands[2]]
            else:
                show_operands = []
            self._move_text_line(state, 0.0, -state.tl)
        else:
            show_operands = operands[:1]

        font = self._get_font(record.resources, state.font_name)
        decoded, advance = self._decode_show_operation(
            font, state, show_operands, operator
        )

        self._match_text(record, state, index, decoded, advance, font, contexts)

        # Update the text matrix for the following operations.
        state.tm[4] += advance * state.tm[0]
        state.tm[5] += advance * state.tm[1]

    def _decode_show_operation(
        self,
        font: Font,
        state: _GraphicsState,
        show_operands: list[Any],
        operator: bytes,
    ) -> tuple[str, float]:
        decoded_parts: list[str] = []
        advance = 0.0

        def add_string(operand: Any) -> None:
            nonlocal advance
            if isinstance(operand, str):
                # TextStringObject operands are already decoded by the
                # parser (mirrors the text extraction behavior).
                raw = operand
                character_map = font.character_map
                text = (
                    "".join(character_map.get(char, char) for char in raw)
                    if character_map
                    else raw
                )
            else:
                raw, text = self._decode_string(font, bytes(operand))
            decoded_parts.append(text)
            for char in raw:
                width = (
                    font.space_width
                    if char == font.space_char
                    else font.character_widths.get(
                        char, font.character_widths.get("default", 500.0)
                    )
                )
                char_advance = width / 1000.0 * state.font_size + state.tc
                if char == font.space_char:
                    char_advance += state.tw
                advance += char_advance * state.tz

        def add_adjustment(value: Any) -> None:
            nonlocal advance
            try:
                advance += -float(value) / 1000.0 * state.font_size * state.tz
            except (TypeError, ValueError):
                pass

        for operand in show_operands:
            if isinstance(operand, (list, ArrayObject)):
                for item in operand:
                    if isinstance(item, (str, bytes, ByteStringObject)):
                        add_string(item)
                    else:
                        add_adjustment(item)
            elif isinstance(operand, (str, bytes, ByteStringObject)):
                add_string(operand)
        return "".join(decoded_parts), advance

    def _decode_string(self, font: Font, data: bytes) -> tuple[str, str]:
        encoding = font.encoding
        if isinstance(encoding, str):
            try:
                raw = data.decode(encoding, "surrogatepass")
            except Exception as exc:
                raise RedactionNotSupportedError(
                    f"Font {font.name!r} uses the unsupported encoding "
                    f"{encoding!r}; refusing to redact."
                ) from exc
        else:
            raw = "".join(encoding.get(code, chr(code)) for code in data)
        character_map = font.character_map
        if character_map:
            return raw, "".join(character_map.get(char, char) for char in raw)
        return raw, raw

    def _match_text(
        self,
        record: _StreamRecord,
        state: _GraphicsState,
        index: int,
        decoded: str,
        advance: float,
        font: Font,
        contexts: list[_Context],
    ) -> None:
        matched_texts = [target for target in self.texts if target in decoded]
        local_matrix = mult(state.tm, state.ctm)
        y0 = state.ts + font.font_descriptor.descent / 1000.0 * state.font_size
        y1 = state.ts + font.font_descriptor.ascent / 1000.0 * state.font_size
        corners = ((0.0, y0), (advance, y0), (advance, y1), (0.0, y1))
        for context in contexts:
            matrix = mult(local_matrix, context.matrix)
            points = [_apply_matrix(matrix, x, y) for x, y in corners]
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            rect = (min(xs), min(ys), max(xs), max(ys))
            match_key = (index, context.page_index, rect)
            already_reported = match_key in record.matched
            region_hit = any(
                _rectangles_intersect(rect, region) for region in context.regions
            )
            if not matched_texts and not region_hit:
                continue
            record.remove.add(index)
            self._page_boxes.setdefault(context.page_index, []).append(rect)
            if already_reported:
                continue
            record.matched.add(match_key)
            source = (
                "content"
                if record.page is not None
                else "annotation" if record.referrer is None else "xobject"
            )
            self.hits.append(
                RedactionHit(
                    page_index=context.page_index,
                    rect=rect,
                    text=matched_texts[0] if matched_texts else "",
                    source=source,
                )
            )

    # ------------------------------------------------------------------
    # XObjects
    # ------------------------------------------------------------------
    def _handle_do(
        self,
        record: _StreamRecord,
        state: _GraphicsState,
        index: int,
        operands: list[Any],
        contexts: list[_Context],
        depth: int,
    ) -> None:
        if not operands:
            return
        name = str(operands[0])
        xobjects = record.resources.get("/XObject")
        if xobjects is None:
            return
        xobjects = xobjects.get_object()
        entry = xobjects.get(name)
        if entry is None:
            return
        try:
            xobject = entry.get_object()
        except Exception:
            return
        if not isinstance(xobject, StreamObject):
            return
        subtype = xobject.get("/Subtype")
        if subtype == "/Form":
            matrix = [
                float(v) for v in xobject.get("/Matrix", _MATRIX_IDENTITY)
            ]
            sub_contexts = [
                _Context(
                    context.page_index,
                    mult(matrix, mult(state.ctm, context.matrix)),
                    context.regions,
                )
                for context in contexts
            ]
            resources = xobject.get("/Resources")
            resources = (
                resources.get_object()
                if resources is not None
                else record.resources
            )
            sub_record = self._register_stream(
                self._stream_key(xobject),
                xobject,
                resources,
                referrer=(id(record.resources), name),
            )
            sub_record.referrers.add((id(record.resources), name))
            self._walk(sub_record, sub_contexts, depth + 1)
        elif subtype == "/Image" and self.remove_overlapping_images:
            self._check_image_hit(record, state, index, contexts)

    def _check_image_hit(
        self,
        record: _StreamRecord,
        state: _GraphicsState,
        index: int,
        contexts: list[_Context],
    ) -> None:
        # Images are painted in the unit square of the current user space.
        unit_square = ((0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0))
        for context in contexts:
            matrix = mult(state.ctm, context.matrix)
            points = [_apply_matrix(matrix, x, y) for x, y in unit_square]
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            rect = (min(xs), min(ys), max(xs), max(ys))
            match_key = (index, context.page_index, rect)
            if not any(
                _rectangles_intersect(rect, region) for region in context.regions
            ):
                continue
            record.remove.add(index)
            self._page_boxes.setdefault(context.page_index, []).append(rect)
            if match_key in record.matched:
                continue
            record.matched.add(match_key)
            self.hits.append(
                RedactionHit(
                    page_index=context.page_index,
                    rect=rect,
                    text="",
                    source="image",
                )
            )

    # ------------------------------------------------------------------
    # Vector paths
    # ------------------------------------------------------------------
    def _check_path_hit(
        self,
        record: _StreamRecord,
        state: _GraphicsState,
        path_start: int,
        paint_index: int,
        path_points: list[tuple[float, float]],
        contexts: list[_Context],
    ) -> None:
        for context in contexts:
            matrix = mult(state.ctm, context.matrix)
            points = [_apply_matrix(matrix, x, y) for x, y in path_points]
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            rect = (min(xs), min(ys), max(xs), max(ys))
            match_key = (paint_index, context.page_index, rect)
            if not any(
                _rectangles_intersect(rect, region) for region in context.regions
            ):
                continue
            for i in range(path_start, paint_index + 1):
                record.remove.add(i)
            self._page_boxes.setdefault(context.page_index, []).append(rect)
            if match_key in record.matched:
                return
            record.matched.add(match_key)
            self.hits.append(
                RedactionHit(
                    page_index=context.page_index,
                    rect=rect,
                    text="",
                    source="path",
                )
            )
            return

    # ------------------------------------------------------------------
    # Fonts
    # ------------------------------------------------------------------
    def _get_font(self, resources: DictionaryObject, font_name: Optional[str]) -> Font:
        if font_name is None:
            raise RedactionNotSupportedError(
                "Text is shown without a selected font; refusing to redact."
            )
        fonts = resources.get("/Font")
        font_dict = None
        if fonts is not None:
            font_dict = fonts.get_object().get(font_name)
        if font_dict is None:
            raise RedactionNotSupportedError(
                f"Font resource {font_name!r} is not defined; "
                "refusing to redact."
            )
        font_dict = font_dict.get_object()
        cache_key = id(font_dict)
        if cache_key not in self._fonts:
            try:
                font = Font.from_font_resource(font_dict)
            except Exception as exc:
                raise RedactionNotSupportedError(
                    f"Font {font_name!r} cannot be interpreted: {exc}"
                ) from exc
            if font.sub_type not in _SUPPORTED_FONT_SUBTYPES or not font.interpretable:
                raise RedactionNotSupportedError(
                    f"Font {font.name!r} of subtype {font.sub_type!r} is not "
                    "supported for redaction; refusing to redact."
                )
            self._fonts[cache_key] = font
        return self._fonts[cache_key]

    # ------------------------------------------------------------------
    # Resource pruning
    # ------------------------------------------------------------------
    def _finalize_operations(self) -> None:
        """
        Compute the final operation list of every stream.

        Besides dropping the redacted operations, this also drops font
        selections (Tf) whose font is never used by a remaining
        text-showing operation, so that the associated font resources can
        be pruned afterwards.
        """
        for record in self._streams.values():
            filtered = [
                (index, operation)
                for index, operation in enumerate(record.operations)
                if index not in record.remove
            ]
            used_fonts: set[str] = set()
            current_font: Optional[str] = None
            for _, (operands, operator) in filtered:
                if operator == b"Tf":
                    current_font = str(operands[0]) if operands else None
                elif operator in (b"Tj", b"TJ", b"'", b'"') and current_font:
                    used_fonts.add(current_font)
            final_ops: list[tuple[Any, bytes]] = []
            used_xobjects: set[str] = set()
            for _, (operands, operator) in filtered:
                if (
                    operator == b"Tf"
                    and operands
                    and str(operands[0]) not in used_fonts
                ):
                    continue
                if operator == b"Do" and operands:
                    used_xobjects.add(str(operands[0]))
                final_ops.append((operands, operator))
            record.final_ops = final_ops
            record.used_fonts = used_fonts
            record.used_xobjects = used_xobjects

    def _compute_usage(self) -> dict[int, tuple[set[str], set[str]]]:
        usage: dict[int, tuple[set[str], set[str]]] = {
            key: (set(), set()) for key in self._resources
        }
        for record in self._streams.values():
            if record.dead:
                continue
            fonts, xobjects = usage.setdefault(id(record.resources), (set(), set()))
            fonts.update(record.used_fonts)
            xobjects.update(record.used_xobjects)
        return usage

    def _prune_resources(self) -> None:
        candidates: list[object] = []
        # Iterate to a fixpoint: dropping a Form XObject may make the
        # resources it used unreferenced as well.
        while True:
            usage = self._compute_usage()
            removed_any = False
            for resources_id, resources in self._resources.items():
                used_fonts, used_xobjects = usage.get(resources_id, (set(), set()))
                for section, used_names in (
                    ("/Font", used_fonts),
                    ("/XObject", used_xobjects),
                ):
                    dictionary = resources.get(section)
                    if dictionary is None:
                        continue
                    dictionary = dictionary.get_object()
                    for name in list(dictionary.keys()):
                        if str(name) in used_names:
                            continue
                        value = dictionary.raw_get(name)
                        del dictionary[name]
                        candidates.append(value)
                        removed_any = True
                        if section == "/XObject":
                            for record in self._streams.values():
                                record.referrers.discard((resources_id, str(name)))
            for record in self._streams.values():
                # A stream is dead once every reference to it was pruned.
                if record.referrer is not None and not record.referrers:
                    record.dead = True
            if not removed_any:
                break
        # Blank out the indirect objects that are no longer referenced
        # from any surviving resource dictionary.
        surviving: set[int] = set()
        for resources in self._resources.values():
            for section in ("/Font", "/XObject"):
                dictionary = resources.get(section)
                if dictionary is None:
                    continue
                for value in dictionary.get_object().values():
                    if isinstance(value, IndirectObject):
                        surviving.add(value.idnum)
        surviving.update(self._protected_resource_ids())
        for candidate in candidates:
            if (
                isinstance(candidate, IndirectObject)
                and candidate.pdf is self.writer
                and candidate.idnum not in surviving
            ):
                try:
                    self.writer._replace_object(candidate.idnum, NullObject())
                except Exception:
                    pass

    def _protected_resource_ids(self) -> set[int]:
        # Resources of the interactive form dictionary are out of scope for
        # pruning; never blank the objects they reference.
        protected: set[int] = set()
        try:
            acroform = self.writer._root_object.get("/AcroForm")
            if acroform is None:
                return protected
            default_resources = acroform.get_object().get("/DR")
            if default_resources is None:
                return protected
            default_resources = default_resources.get_object()
            for section in ("/Font", "/XObject"):
                dictionary = default_resources.get(section)
                if dictionary is None:
                    continue
                for value in dictionary.get_object().values():
                    if isinstance(value, IndirectObject):
                        protected.add(value.idnum)
        except Exception:
            pass
        return protected

    # ------------------------------------------------------------------
    # Stream rebuilding
    # ------------------------------------------------------------------
    def _rebuild_streams(self) -> None:
        for record in self._streams.values():
            if record.dead:
                continue
            filtered = record.final_ops
            if record.page is not None:
                if self.draw_black_boxes:
                    boxes = self._page_boxes.get(record.page_index)
                    if boxes:
                        filtered = filtered + _black_box_operations(boxes)
                content = ContentStream(None, self.writer)
                content.operations = filtered
                record.page.replace_contents(content)
            elif record.remove:
                content = ContentStream(None, self.writer)
                content.operations = filtered
                data = content.get_data()
                stream = cast(StreamObject, record.stream)
                reference = getattr(stream, "indirect_reference", None)
                if reference is not None and reference.pdf is self.writer:
                    replacement = DecodedStreamObject()
                    for key, value in stream.items():
                        if key not in ("/Length", "/Filter", "/DecodeParms"):
                            replacement[key] = value
                    replacement.set_data(data)
                    self.writer._replace_object(reference.idnum, replacement)
                else:
                    try:
                        stream.set_data(data)
                    except Exception as exc:
                        raise RedactionNotSupportedError(
                            "A content stream that requires redaction uses "
                            f"an unsupported stream filter: {exc}"
                        ) from exc

    # ------------------------------------------------------------------
    # String sanitization (metadata, annotations, outlines, ...)
    # ------------------------------------------------------------------
    def _sanitize_strings(self) -> None:
        leftovers: list[str] = []
        visited: set[int] = set()
        for obj in list(self.writer._objects):
            if obj is not None:
                self._sanitize_value(obj, visited, leftovers)
        if leftovers:
            raise RedactionError(
                "Sensitive content remains in streams that cannot be "
                f"sanitized safely: {', '.join(leftovers)}"
            )

    def _sanitize_value(
        self, obj: PdfObject, visited: set[int], leftovers: list[str]
    ) -> PdfObject:
        if isinstance(obj, TextStringObject):
            sanitized_text = str(obj)
            for target in self.texts:
                sanitized_text = sanitized_text.replace(target, "")
            return TextStringObject(sanitized_text) if sanitized_text != obj else obj
        if isinstance(obj, ByteStringObject):
            data = bytes(obj)
            for needle in self._needles:
                data = data.replace(needle, b"")
            return ByteStringObject(data) if data != bytes(obj) else obj
        object_id = id(obj)
        if object_id in visited:
            return obj
        visited.add(object_id)
        if isinstance(obj, StreamObject):
            try:
                data = obj.get_data()
            except Exception:
                data = b""
            if any(needle in data for needle in self._needles):
                if obj.get("/Type") == "/Metadata":
                    for needle in self._needles:
                        data = data.replace(needle, b"")
                    try:
                        obj.set_data(data)
                    except Exception as exc:
                        raise RedactionError(
                            f"Could not sanitize the XMP metadata stream: {exc}"
                        ) from exc
                else:
                    leftovers.append(
                        f"stream of subtype {obj.get('/Subtype', 'unknown')}"
                    )
        if isinstance(obj, DictionaryObject):
            for key in list(obj.keys()):
                value = obj.raw_get(key)
                if isinstance(value, IndirectObject):
                    continue  # indirect objects are sanitized at top level
                sanitized = self._sanitize_value(value, visited, leftovers)
                if sanitized is not value:
                    obj[key] = sanitized
        elif isinstance(obj, ArrayObject):
            for index, value in enumerate(obj):
                if isinstance(value, IndirectObject):
                    continue
                sanitized = self._sanitize_value(value, visited, leftovers)
                if sanitized is not value:
                    obj[index] = sanitized
        return obj


def _as_float(operands: list[Any], index: int, default: float) -> float:
    try:
        return float(operands[index])
    except (IndexError, TypeError, ValueError):
        return default


def _path_operand_points(
    operator: bytes, operands: list[Any]
) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    try:
        if operator == b"re" and len(operands) >= 4:
            x, y, w, h = (float(v) for v in operands[:4])
            points.extend([(x, y), (x + w, y), (x + w, y + h), (x, y + h)])
        elif operator in (b"m", b"l") and len(operands) >= 2:
            points.append((float(operands[0]), float(operands[1])))
        elif operator in (b"c", b"v", b"y"):
            numbers = [float(v) for v in operands]
            points.extend(
                (numbers[i], numbers[i + 1])
                for i in range(0, len(numbers) - 1, 2)
            )
    except (TypeError, ValueError):
        pass
    return points


def _black_box_operations(
    rectangles: list[_Rectangle],
) -> list[tuple[list[Any], bytes]]:
    # Purely visual complement: the sensitive content has already been
    # removed; these boxes only cover whatever might remain visible.
    operations: list[tuple[list[Any], bytes]] = []
    padding = 1.0
    for x0, y0, x1, y1 in rectangles:
        operations.append(([], b"q"))
        operations.append(
            ([FloatObject(0), FloatObject(0), FloatObject(0)], b"rg")
        )
        operations.append(
            (
                [
                    FloatObject(x0 - padding),
                    FloatObject(y0 - padding),
                    FloatObject(x1 - x0 + 2 * padding),
                    FloatObject(y1 - y0 + 2 * padding),
                ],
                b"re",
            )
        )
        operations.append(([], b"f"))
        operations.append(([], b"Q"))
    return operations


def _preflight_checks(reader: PdfReader) -> None:
    if reader.is_encrypted:
        raise RedactionNotSupportedError(
            "Encrypted documents cannot be redacted; decrypt and review "
            "the document first."
        )
    root = cast(DictionaryObject, reader.trailer["/Root"])
    if "/Perms" in root:
        raise RedactionNotSupportedError(
            "The document carries usage rights or a certification "
            "signature (/Perms); modifying it would invalidate the "
            "signature, so redaction is refused."
        )
    acroform = root.get("/AcroForm")
    if acroform is None:
        return
    acroform = acroform.get_object()
    try:
        sig_flags = int(acroform.get("/SigFlags", 0) or 0)
    except (TypeError, ValueError):
        sig_flags = 0
    if sig_flags:
        raise RedactionNotSupportedError(
            "The document contains digital signature fields "
            "(/SigFlags); modifying it would invalidate the signature, "
            "so redaction is refused."
        )

    def check_fields(fields: Any, inherited_type: Any) -> None:
        for field_ref in fields or []:
            try:
                field_dict = field_ref.get_object()
            except Exception:
                continue
            field_type = field_dict.get("/FT", inherited_type)
            if field_type == "/Sig":
                raise RedactionNotSupportedError(
                    "The document contains a digital signature field; "
                    "modifying it would invalidate the signature, so "
                    "redaction is refused."
                )
            check_fields(field_dict.get("/Kids"), field_type)

    check_fields(acroform.get("/Fields"), None)


def _verify_output(data: bytes, texts: Sequence[str]) -> None:
    if not texts:
        return
    needles = _byte_needles(texts)
    reader = PdfReader(BytesIO(data), strict=False)
    for page in reader.pages:
        try:
            extracted = page.extract_text() or ""
        except Exception:
            extracted = ""
        for target in texts:
            if target in extracted:
                raise RedactionError(
                    "Redaction verification failed: sensitive text is still "
                    "extractable from the output."
                )
    visited: set[int] = set()
    stack: list[object] = [reader.trailer]
    while stack:
        obj = stack.pop()
        if isinstance(obj, IndirectObject):
            try:
                obj = obj.get_object()
            except Exception:
                continue
        if obj is None or id(obj) in visited:
            continue
        visited.add(id(obj))
        if isinstance(obj, StreamObject):
            try:
                stream_data = obj.get_data()
            except Exception:
                stream_data = b""
            for needle in needles:
                if needle in stream_data:
                    raise RedactionError(
                        "Redaction verification failed: sensitive data is "
                        "still present in a stream of the output."
                    )
            stack.extend(obj.values())
        elif isinstance(obj, DictionaryObject):
            stack.extend(obj.values())
        elif isinstance(obj, (list, ArrayObject)):
            stack.extend(obj)
        elif isinstance(obj, TextStringObject):
            for target in texts:
                if target in obj:
                    raise RedactionError(
                        "Redaction verification failed: sensitive text is "
                        "still present in a string object of the output."
                    )
        elif isinstance(obj, ByteStringObject):
            for needle in needles:
                if needle in bytes(obj):
                    raise RedactionError(
                        "Redaction verification failed: sensitive data is "
                        "still present in a string object of the output."
                    )
    for needle in needles:
        if needle in data:
            raise RedactionError(
                "Redaction verification failed: sensitive data is still "
                "present in the serialized output."
            )


def redact_and_sanitize(
    reader: PdfReader,
    output: Union[str, Path, BinaryIO, None] = None,
    *,
    texts: Sequence[str] = (),
    regions: Optional[dict[int, Sequence[Sequence[float]]]] = None,
    draw_black_boxes: bool = True,
    remove_overlapping_images: bool = True,
    remove_overlapping_paths: bool = False,
) -> RedactionReport:
    """
    Permanently remove sensitive content from a PDF document.

    The document is analyzed, all matching content is removed from page
    content streams, (nested) Form XObjects and annotation appearance
    streams, now-unreferenced resources (fonts, images, XObjects) are
    dropped, and the result is verified after serialization: the original
    sensitive strings can no longer be found in extracted text,
    decompressed content streams, or any object of the output file.

    Args:
        reader: The source document. It is never modified; the redacted
            document is built in a fresh writer.
        output: Where to write the redacted PDF: a file path or a binary
            file-like object. If None, the document is only analyzed and
            verified in memory.
        texts: Sensitive strings to search for. A text-showing operation
            is removed when its decoded text contains any of these
            strings. Matching is done per text-showing operation after
            font decoding (Tj, TJ, ' and " operators).
        regions: Mapping of zero-based page indices to rectangles
            (x0, y0, x1, y1) given in the page's default user space (the
            coordinate system of /MediaBox, unaffected by /Rotate or
            /CropBox). Any text, image (see remove_overlapping_images) or
            path (see remove_overlapping_paths) intersecting a rectangle
            is removed.
        draw_black_boxes: If True (default), black rectangles are drawn
            over the removed regions as a visual complement. The removal
            itself does not depend on this appearance.
        remove_overlapping_images: If True (default), images whose
            bounding box intersects a redaction region are removed, since
            they may contain a rasterized copy of the sensitive content.
        remove_overlapping_paths: If True, vector paths intersecting a
            redaction region are removed as well. Defaults to False to
            avoid destroying unrelated graphics.

    Returns:
        A RedactionReport listing every removed piece of content.

    Raises:
        RedactionNotSupportedError: If the document is encrypted, carries
            a digital signature, or shows text with an unsupported font
            or encoding. Raised before anything is modified or written.
        RedactionError: If the sensitive content cannot be removed or
            the post-write verification finds remaining sensitive data.

    """
    target_texts = [str(t) for t in texts if t]
    region_map: dict[int, tuple[_Rectangle, ...]] = {}
    for page_index, rectangles in (regions or {}).items():
        region_map[int(page_index)] = tuple(
            _normalize_rectangle(rectangle) for rectangle in rectangles
        )
    if not target_texts and not region_map:
        raise ValueError(
            "Nothing to redact: provide at least one of texts or regions."
        )

    _preflight_checks(reader)

    writer = PdfWriter()
    writer.clone_document_from_reader(reader)
    engine = _RedactionEngine(
        writer,
        target_texts,
        region_map,
        remove_overlapping_images=remove_overlapping_images,
        remove_overlapping_paths=remove_overlapping_paths,
        draw_black_boxes=draw_black_boxes,
    )
    engine.run()

    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()
    _verify_output(data, target_texts)

    if output is not None:
        if isinstance(output, (str, Path)):
            with open(output, "wb") as file:
                file.write(data)
        else:
            output.write(data)
    return RedactionReport(hits=engine.hits)
