"""Test the pypdf._redact module (redact-and-sanitize)."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter, redact_and_sanitize
from pypdf.errors import RedactionNotSupportedError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    ContentStream,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    StreamObject,
    TextStringObject,
)

SECRET = "110101199003077777"


def _content_stream(writer, data):
    stream = ContentStream(None, writer)
    stream.set_data(data)
    return stream


def _type1_font_ref(writer, base_font="/Helvetica"):
    return writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject(base_font),
            NameObject("/Encoding"): NameObject("/WinAnsiEncoding"),
        })
    )


def _type0_font_ref(writer):
    """Build a minimal Type0 (composite) font with Identity-H encoding."""
    to_unicode = DecodedStreamObject()
    to_unicode.set_data(
        b"/CIDInit /ProcSet findresource begin\n"
        b"12 dict begin\n"
        b"begincmap\n"
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
        b"/CMapName /Adobe-Identity-UCS def\n"
        b"/CMapType 2 def\n"
        b"1 begincodespacerange\n"
        b"<0000> <FFFF>\n"
        b"endcodespacerange\n"
        b"1 beginbfrange\n"
        b"<0030> <0039> <0030>\n"
        b"endbfrange\n"
        b"endcmap\n"
        b"CMapName currentdict /CMap defineresource pop\n"
        b"end\n"
        b"end\n"
    )
    to_unicode_ref = writer._add_object(to_unicode)
    descriptor_ref = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/FontDescriptor"),
            NameObject("/FontName"): NameObject("/TestCIDFont"),
            NameObject("/Flags"): NumberObject(4),
            NameObject("/FontBBox"): ArrayObject(
                [NumberObject(0), NumberObject(-200), NumberObject(1000), NumberObject(900)]
            ),
            NameObject("/ItalicAngle"): NumberObject(0),
            NameObject("/Ascent"): NumberObject(800),
            NameObject("/Descent"): NumberObject(-200),
            NameObject("/CapHeight"): NumberObject(700),
            NameObject("/StemV"): NumberObject(80),
        })
    )
    cid_font_ref = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/CIDFontType2"),
            NameObject("/BaseFont"): NameObject("/TestCIDFont"),
            NameObject("/CIDSystemInfo"): DictionaryObject({
                NameObject("/Registry"): TextStringObject("Adobe"),
                NameObject("/Ordering"): TextStringObject("Identity"),
                NameObject("/Supplement"): NumberObject(0),
            }),
            NameObject("/FontDescriptor"): descriptor_ref,
            NameObject("/DW"): NumberObject(600),
            NameObject("/W"): ArrayObject([
                NumberObject(48),
                ArrayObject([NumberObject(500)] * 10),
            ]),
        })
    )
    return writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type0"),
            NameObject("/BaseFont"): NameObject("/TestCIDFont"),
            NameObject("/Encoding"): NameObject("/Identity-H"),
            NameObject("/DescendantFonts"): ArrayObject([cid_font_ref]),
            NameObject("/ToUnicode"): to_unicode_ref,
        })
    )


def _utf16be_hex(text):
    return b"<" + text.encode("utf-16-be").hex().encode() + b">"


def _image_xobject_ref(writer):
    image = DecodedStreamObject()
    image.set_data(bytes([255, 0, 0]))
    image[NameObject("/Type")] = NameObject("/XObject")
    image[NameObject("/Subtype")] = NameObject("/Image")
    image[NameObject("/Width")] = NumberObject(1)
    image[NameObject("/Height")] = NumberObject(1)
    image[NameObject("/ColorSpace")] = NameObject("/DeviceRGB")
    image[NameObject("/BitsPerComponent")] = NumberObject(8)
    return writer._add_object(image)


def _form_xobject_ref(writer, data, font_ref):
    xobject = DecodedStreamObject()
    xobject.set_data(data)
    xobject[NameObject("/Type")] = NameObject("/XObject")
    xobject[NameObject("/Subtype")] = NameObject("/Form")
    xobject[NameObject("/BBox")] = ArrayObject(
        [FloatObject(0), FloatObject(0), FloatObject(300), FloatObject(100)]
    )
    xobject[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    return writer._add_object(xobject)


def _make_single_page_pdf(content, fonts=None, extra_page_items=None, xobjects=None):
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    resources = DictionaryObject()
    if fonts:
        resources[NameObject("/Font")] = DictionaryObject(fonts)
    if xobjects:
        resources[NameObject("/XObject")] = DictionaryObject(xobjects)
    page[NameObject("/Resources")] = resources
    for key, value in (extra_page_items or {}).items():
        page[NameObject(key)] = value
    page.replace_contents(_content_stream(writer, content))
    buffer = BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _assert_unrecoverable(pdf_bytes, secret=SECRET):
    """The sensitive string must not be recoverable from the output."""
    assert secret.encode("utf-8") not in pdf_bytes
    assert secret.encode("utf-16-be") not in pdf_bytes
    reader = PdfReader(BytesIO(pdf_bytes))
    for page in reader.pages:
        assert secret not in (page.extract_text() or "")
    # Independently walk every object: no decompressed stream and no
    # string object may contain the sensitive data.
    visited = set()
    stack = [reader.trailer]
    while stack:
        obj = stack.pop()
        if hasattr(obj, "get_object") and not isinstance(
            obj, (DictionaryObject, ArrayObject, StreamObject)
        ):
            obj = obj.get_object()
        if obj is None or id(obj) in visited:
            continue
        visited.add(id(obj))
        if isinstance(obj, StreamObject):
            assert secret.encode("utf-8") not in obj.get_data()
            assert secret.encode("utf-16-be") not in obj.get_data()
            stack.extend(obj.values())
        elif isinstance(obj, DictionaryObject):
            stack.extend(obj.values())
        elif isinstance(obj, (list, ArrayObject)):
            stack.extend(obj)
        elif isinstance(obj, TextStringObject):
            assert secret not in obj
        elif isinstance(obj, ByteStringObject):
            assert secret.encode("utf-8") not in bytes(obj)


def test_redact_type1_text_match():
    """Type1 font: Tj, TJ and quote operators are all redacted."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer,
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET\n"
        + b"BT /F1 12 Tf 100 650 Td [(Keep) -20 (this)] TJ ET\n"
        + b"BT /F1 12 Tf 100 600 Td (ID: " + SECRET.encode() + b") ' ET\n"
        + b"BT /F1 12 Tf 100 550 Td (safe line) Tj ET",
    ))
    writer.add_outline_item("Section 1", 0)
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    reader = PdfReader(BytesIO(data))
    assert SECRET in reader.pages[0].extract_text()

    out = BytesIO()
    report = redact_and_sanitize(reader, out, texts=[SECRET])
    assert report.hit_count == 2
    assert report.pages == [0]
    assert all(hit.source == "content" for hit in report.hits)
    assert all(hit.text == SECRET for hit in report.hits)
    # The hit rectangle is given in page user space around (100, 700).
    x0, y0, x1, y1 = report.hits[0].rect
    assert x0 == pytest.approx(100, abs=2)
    assert y1 - y0 == pytest.approx(12, abs=4)

    result = out.getvalue()
    _assert_unrecoverable(result)
    reader2 = PdfReader(BytesIO(result))
    remaining = reader2.pages[0].extract_text()
    assert "Keepthis" in remaining.replace(" ", "")
    assert "safe line" in remaining
    # Page dimensions and bookmarks are preserved.
    assert float(reader2.pages[0].mediabox.width) == 612
    assert float(reader2.pages[0].mediabox.height) == 792
    assert reader2.outline[0].title == "Section 1"


def test_redact_type0_font_text_match():
    """Type0 (Identity-H) font: hex strings are decoded and redacted."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type0_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F2"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer,
        b"BT /F2 14 Tf 100 700 Td " + _utf16be_hex("ID: " + SECRET) + b" Tj ET\n"
        + b"BT /F2 14 Tf 100 650 Td " + _utf16be_hex("42") + b" Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    reader = PdfReader(BytesIO(data))
    assert SECRET in reader.pages[0].extract_text()

    out = BytesIO()
    report = redact_and_sanitize(reader, out, texts=[SECRET])
    assert report.hit_count == 1

    result = out.getvalue()
    _assert_unrecoverable(result)
    remaining = PdfReader(BytesIO(result)).pages[0].extract_text()
    assert "42" in remaining


def test_redact_region_match_and_miss():
    """Region-based selection: positive and negative cases."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer,
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET\n"
        + b"BT /F1 12 Tf 100 100 Td (far away) Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    # Positive: the region covers the sensitive text.
    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(data)), out, regions={0: [(90, 690, 400, 720)]}
    )
    assert report.hit_count == 1
    result = out.getvalue()
    _assert_unrecoverable(result)
    assert "far away" in PdfReader(BytesIO(result)).pages[0].extract_text()

    # Negative: a region elsewhere must not touch anything.
    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(data)), out, regions={0: [(90, 90, 200, 120)]}
    )
    assert report.hit_count == 1  # only the "far away" line intersects
    assert SECRET in PdfReader(BytesIO(out.getvalue())).pages[0].extract_text()

    # Negative: a region that hits nothing at all.
    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(data)), out, regions={0: [(500, 50, 600, 80)]}
    )
    assert report.hit_count == 0
    assert SECRET in PdfReader(BytesIO(out.getvalue())).pages[0].extract_text()


def test_redact_rotated_page():
    """Regions are given in default user space, independent of /Rotate."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page[NameObject("/Rotate")] = NumberObject(90)
    page.replace_contents(_content_stream(
        writer,
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    # Text-based redaction on a rotated page.
    out = BytesIO()
    report = redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    assert report.hit_count == 1
    result = out.getvalue()
    _assert_unrecoverable(result)
    reader2 = PdfReader(BytesIO(result))
    assert reader2.pages[0].get("/Rotate") == 90
    assert float(reader2.pages[0].mediabox.width) == 612

    # Region-based redaction on a rotated page (default user space).
    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(data)), out, regions={0: [(90, 690, 400, 720)]}
    )
    assert report.hit_count == 1
    _assert_unrecoverable(out.getvalue())


def test_redact_cropbox_preserved():
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page[NameObject("/CropBox")] = ArrayObject(
        [FloatObject(50), FloatObject(50), FloatObject(400), FloatObject(400)]
    )
    page.replace_contents(_content_stream(
        writer,
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    reader2 = PdfReader(BytesIO(out.getvalue()))
    cropbox = reader2.pages[0]["/CropBox"]
    assert [float(v) for v in cropbox] == [50, 50, 400, 400]
    _assert_unrecoverable(out.getvalue())


def test_redact_shared_and_nested_form_xobject():
    """A Form XObject used by several pages is sanitized exactly once."""
    writer = PdfWriter()
    font_ref = _type1_font_ref(writer)
    inner_ref = _form_xobject_ref(
        writer,
        b"BT /F1 12 Tf 10 10 Td (ID: " + SECRET.encode() + b") Tj ET\n"
        + b"BT /F1 12 Tf 10 40 Td (SharedOK) Tj ET",
        font_ref,
    )
    # A nested Form XObject that draws the inner one.
    outer = DecodedStreamObject()
    outer.set_data(b"q 1 0 0 1 20 20 cm /Fm1 Do Q")
    outer[NameObject("/Type")] = NameObject("/XObject")
    outer[NameObject("/Subtype")] = NameObject("/Form")
    outer[NameObject("/BBox")] = ArrayObject(
        [FloatObject(0), FloatObject(0), FloatObject(400), FloatObject(200)]
    )
    outer[NameObject("/Resources")] = DictionaryObject({
        NameObject("/XObject"): DictionaryObject({NameObject("/Fm1"): inner_ref})
    })
    outer_ref = writer._add_object(outer)

    page1 = writer.add_blank_page(612, 792)
    page1[NameObject("/Resources")] = DictionaryObject({
        NameObject("/XObject"): DictionaryObject({NameObject("/Fm1"): inner_ref})
    })
    page1.replace_contents(_content_stream(
        writer, b"q 1 0 0 1 50 500 cm /Fm1 Do Q",
    ))
    page2 = writer.add_blank_page(612, 792)
    page2[NameObject("/Resources")] = DictionaryObject({
        NameObject("/XObject"): DictionaryObject({
            NameObject("/Fm1"): inner_ref,
            NameObject("/Fm2"): outer_ref,
        })
    })
    page2.replace_contents(_content_stream(
        writer, b"q 1 0 0 1 200 300 cm /Fm1 Do Q\nq 1 0 0 1 0 0 cm /Fm2 Do Q",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    reader = PdfReader(BytesIO(data))
    assert SECRET in reader.pages[0].extract_text()
    assert SECRET in reader.pages[1].extract_text()

    out = BytesIO()
    report = redact_and_sanitize(reader, out, texts=[SECRET])
    # One hit per placement: page 1 direct, page 2 direct + nested.
    assert report.hit_count == 3
    assert report.pages == [0, 1]
    assert all(hit.source == "xobject" for hit in report.hits)

    result = out.getvalue()
    _assert_unrecoverable(result)
    reader2 = PdfReader(BytesIO(result))
    assert "SharedOK" in reader2.pages[0].extract_text()
    assert "SharedOK" in reader2.pages[1].extract_text()


def test_redact_annotation_appearance():
    """Text inside annotation appearance streams (/AP) is redacted."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(writer, b"BT /F1 12 Tf 100 700 Td (body) Tj ET"))
    appearance = DecodedStreamObject()
    appearance.set_data(
        b"BT /F1 10 Tf 2 8 Td (ID: " + SECRET.encode() + b") Tj ET"
    )
    appearance[NameObject("/Type")] = NameObject("/XObject")
    appearance[NameObject("/Subtype")] = NameObject("/Form")
    appearance[NameObject("/BBox")] = ArrayObject(
        [FloatObject(0), FloatObject(0), FloatObject(150), FloatObject(20)]
    )
    appearance[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    appearance_ref = writer._add_object(appearance)
    annot_ref = writer._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/Rect"): ArrayObject(
            [FloatObject(50), FloatObject(50), FloatObject(200), FloatObject(70)]
        ),
        NameObject("/AP"): DictionaryObject({NameObject("/N"): appearance_ref}),
    }))
    page[NameObject("/Annots")] = ArrayObject([annot_ref])
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    assert SECRET.encode() in data  # sanity: present before redaction
    out = BytesIO()
    report = redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    assert report.hit_count == 1
    assert report.hits[0].source == "annotation"
    result = out.getvalue()
    _assert_unrecoverable(result)
    # The annotation itself and the page body text are preserved.
    reader2 = PdfReader(BytesIO(result))
    assert len(reader2.pages[0]["/Annots"]) == 1
    assert "body" in reader2.pages[0].extract_text()


def test_redact_prunes_unreferenced_resources():
    """Fonts and images only used by removed content are dropped."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    keep_ref = _type1_font_ref(writer, "/Helvetica")
    secret_ref = _type1_font_ref(writer, "/Times-Roman")
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({
            NameObject("/F1"): keep_ref,
            NameObject("/F2"): secret_ref,
        })
    })
    page.replace_contents(_content_stream(
        writer,
        b"BT /F2 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET\n"
        + b"BT /F1 12 Tf 100 650 Td (keep me) Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    result = out.getvalue()
    _assert_unrecoverable(result)
    reader2 = PdfReader(BytesIO(result))
    fonts = reader2.pages[0]["/Resources"]["/Font"]
    assert "/F1" in fonts
    assert "/F2" not in fonts
    # The dropped font object is blanked out of the file entirely.
    assert b"/Times-Roman" not in result
    assert b"/Helvetica" in result


def test_redact_image_overlap_policy():
    """Images overlapping a redaction region are removed by default."""
    def build():
        writer = PdfWriter()
        page = writer.add_blank_page(612, 792)
        font_ref = _type1_font_ref(writer)
        image_ref = _image_xobject_ref(writer)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref}),
            NameObject("/XObject"): DictionaryObject({NameObject("/Im1"): image_ref}),
        })
        page.replace_contents(_content_stream(
            writer,
            b"q 200 0 0 200 100 400 cm /Im1 Do Q\n"
            + b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
        ))
        buffer = BytesIO()
        writer.write(buffer)
        return buffer.getvalue()

    region = {0: [(90, 690, 400, 720)]}  # covers the text, not the image
    image_region = {0: [(90, 390, 400, 720)]}  # covers text and image

    # Default policy: an image intersecting the region is removed.
    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(build())), out, regions=image_region
    )
    assert {hit.source for hit in report.hits} == {"content", "image"}
    result = out.getvalue()
    _assert_unrecoverable(result)
    reader2 = PdfReader(BytesIO(result))
    xobjects = reader2.pages[0]["/Resources"].get("/XObject")
    assert xobjects is None or "/Im1" not in xobjects

    # Policy disabled: the image is kept.
    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(build())),
        out,
        regions=image_region,
        remove_overlapping_images=False,
    )
    assert {hit.source for hit in report.hits} == {"content"}
    reader2 = PdfReader(BytesIO(out.getvalue()))
    assert "/Im1" in reader2.pages[0]["/Resources"]["/XObject"]

    # An image outside the region is kept.
    out = BytesIO()
    report = redact_and_sanitize(PdfReader(BytesIO(build())), out, regions=region)
    assert {hit.source for hit in report.hits} == {"content"}
    reader2 = PdfReader(BytesIO(out.getvalue()))
    assert "/Im1" in reader2.pages[0]["/Resources"]["/XObject"]


def test_redact_black_boxes_optional():
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer,
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    with_boxes = out.getvalue()
    _assert_unrecoverable(with_boxes)
    content = PdfReader(BytesIO(with_boxes)).pages[0].get_contents().get_data()
    assert b" re" in content and b"0.0 0.0 0.0 rg" in content

    out = BytesIO()
    redact_and_sanitize(
        PdfReader(BytesIO(data)), out, texts=[SECRET], draw_black_boxes=False
    )
    without_boxes = out.getvalue()
    _assert_unrecoverable(without_boxes)
    content = PdfReader(BytesIO(without_boxes)).pages[0].get_contents().get_data()
    assert b" re" not in content


def test_redact_sanitizes_metadata():
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer,
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    writer.add_metadata({
        "/Title": "Application for " + SECRET,
        "/Author": "unit-test",
    })
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    result = out.getvalue()
    _assert_unrecoverable(result)
    metadata = PdfReader(BytesIO(result)).metadata
    assert SECRET not in metadata.title
    assert metadata.author == "unit-test"


def test_redact_refuses_encrypted():
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer, b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    writer.encrypt("user-password")
    buffer = BytesIO()
    writer.write(buffer)

    reader = PdfReader(BytesIO(buffer.getvalue()))
    assert reader.is_encrypted
    with pytest.raises(RedactionNotSupportedError):
        redact_and_sanitize(reader, BytesIO(), texts=[SECRET])


def test_redact_refuses_signed():
    def build(acroform_factory):
        writer = PdfWriter()
        page = writer.add_blank_page(612, 792)
        font_ref = _type1_font_ref(writer)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
        })
        page.replace_contents(_content_stream(
            writer, b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
        ))
        writer._root_object[NameObject("/AcroForm")] = writer._add_object(
            acroform_factory(writer)
        )
        buffer = BytesIO()
        writer.write(buffer)
        return buffer.getvalue()

    # /SigFlags set.
    data = build(lambda writer: DictionaryObject({
        NameObject("/SigFlags"): NumberObject(3),
        NameObject("/Fields"): ArrayObject(),
    }))
    with pytest.raises(RedactionNotSupportedError):
        redact_and_sanitize(PdfReader(BytesIO(data)), BytesIO(), texts=[SECRET])

    # An actual signature field.
    def with_signature_field(writer):
        sig_field_ref = writer._add_object(DictionaryObject({
            NameObject("/FT"): NameObject("/Sig"),
            NameObject("/T"): TextStringObject("Signature1"),
        }))
        return DictionaryObject({
            NameObject("/Fields"): ArrayObject([sig_field_ref]),
        })

    data = build(with_signature_field)
    with pytest.raises(RedactionNotSupportedError):
        redact_and_sanitize(PdfReader(BytesIO(data)), BytesIO(), texts=[SECRET])


def test_redact_refuses_unsupported_font():
    """Type3 fonts cannot be decoded reliably: refuse before modifying."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    type3_ref = writer._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type3"),
        NameObject("/FontBBox"): ArrayObject(
            [NumberObject(0), NumberObject(0), NumberObject(1000), NumberObject(1000)]
        ),
        NameObject("/FontMatrix"): ArrayObject(
            [FloatObject(0.001), FloatObject(0), FloatObject(0),
             FloatObject(0.001), FloatObject(0), FloatObject(0)]
        ),
        NameObject("/CharProcs"): DictionaryObject(),
        NameObject("/Encoding"): NameObject("/WinAnsiEncoding"),
        NameObject("/FirstChar"): NumberObject(0),
        NameObject("/LastChar"): NumberObject(255),
        NameObject("/Widths"): ArrayObject([NumberObject(500)] * 256),
    }))
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F3"): type3_ref})
    })
    page.replace_contents(_content_stream(
        writer, b"BT /F3 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    with pytest.raises(RedactionNotSupportedError):
        redact_and_sanitize(PdfReader(BytesIO(data)), BytesIO(), texts=[SECRET])


def test_redact_requires_texts_or_regions():
    writer = PdfWriter()
    writer.add_blank_page(612, 792)
    buffer = BytesIO()
    writer.write(buffer)
    with pytest.raises(ValueError, match="Nothing to redact"):
        redact_and_sanitize(PdfReader(BytesIO(buffer.getvalue())), BytesIO())


def test_redact_no_match_passthrough():
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer, b"BT /F1 12 Tf 100 700 Td (nothing sensitive) Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    report = redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    assert report.hit_count == 0
    assert report.pages == []
    reader2 = PdfReader(BytesIO(out.getvalue()))
    assert "nothing sensitive" in reader2.pages[0].extract_text()
    assert float(reader2.pages[0].mediabox.width) == 612


def test_redact_does_not_modify_source(tmp_path):
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer, b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    source_path = tmp_path / "source.pdf"
    with open(source_path, "wb") as file:
        writer.write(file)
    original_bytes = source_path.read_bytes()

    reader = PdfReader(str(source_path))
    output_path = tmp_path / "redacted.pdf"
    report = redact_and_sanitize(reader, output_path, texts=[SECRET])
    assert report.hit_count == 1

    # The source file is untouched, on disk and in memory.
    assert source_path.read_bytes() == original_bytes
    assert SECRET in PdfReader(str(source_path)).pages[0].extract_text()
    assert SECRET in reader.pages[0].extract_text()
    # The output file is clean.
    _assert_unrecoverable(output_path.read_bytes())


def test_redact_in_memory_only():
    """output=None only analyzes and verifies; nothing is written."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer, b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)

    report = redact_and_sanitize(PdfReader(BytesIO(buffer.getvalue())), texts=[SECRET])
    assert report.hit_count == 1
    assert report.pages == [0]


def test_redact_inline_image_overlap():
    """Inline images (BI/ID/EI) follow the same overlap policy."""
    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font_ref = _type1_font_ref(writer)
    page[NameObject("/Resources")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
    })
    page.replace_contents(_content_stream(
        writer,
        b"q 200 0 0 200 100 400 cm\n"
        b"BI /W 1 /H 1 /CS /RGB /BPC 8 ID \xff\x00\x00 EI\n"
        b"Q\n"
        b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
    ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(data)), out, regions={0: [(90, 390, 400, 720)]}
    )
    assert {hit.source for hit in report.hits} == {"content", "image"}
    content = PdfReader(BytesIO(out.getvalue())).pages[0].get_contents().get_data()
    assert b"BI" not in content


def test_redact_path_overlap_policy():
    """Vector paths overlapping a region are removed only on request."""
    def build():
        writer = PdfWriter()
        page = writer.add_blank_page(612, 792)
        font_ref = _type1_font_ref(writer)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
        })
        page.replace_contents(_content_stream(
            writer,
            b"100 400 200 200 re f\n"
            + b"BT /F1 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
        ))
        buffer = BytesIO()
        writer.write(buffer)
        return buffer.getvalue()

    region = {0: [(90, 390, 400, 720)]}

    out = BytesIO()
    report = redact_and_sanitize(
        PdfReader(BytesIO(build())),
        out,
        regions=region,
        remove_overlapping_paths=True,
    )
    assert {hit.source for hit in report.hits} == {"content", "path"}
    content = PdfReader(BytesIO(out.getvalue())).pages[0].get_contents().get_data()
    assert b"200 200 re" not in content

    out = BytesIO()
    report = redact_and_sanitize(PdfReader(BytesIO(build())), out, regions=region)
    assert {hit.source for hit in report.hits} == {"content"}
    content = PdfReader(BytesIO(out.getvalue())).pages[0].get_contents().get_data()
    assert b"200 200 re" in content


def test_redact_duplicate_resources_across_pages():
    """A font shared by two pages is pruned everywhere and blanked once."""
    writer = PdfWriter()
    secret_ref = _type1_font_ref(writer, "/Times-Roman")
    for _ in range(2):
        page = writer.add_blank_page(612, 792)
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F2"): secret_ref})
        })
        page.replace_contents(_content_stream(
            writer, b"BT /F2 12 Tf 100 700 Td (ID: " + SECRET.encode() + b") Tj ET",
        ))
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    out = BytesIO()
    report = redact_and_sanitize(PdfReader(BytesIO(data)), out, texts=[SECRET])
    assert report.hit_count == 2
    result = out.getvalue()
    _assert_unrecoverable(result)
    reader2 = PdfReader(BytesIO(result))
    for page in reader2.pages:
        assert "/F2" not in page["/Resources"].get("/Font", {})
    assert b"/Times-Roman" not in result
