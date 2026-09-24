"""
Tests for signature-aware incremental writing.

The documents are built in memory: a signature field with a placeholder
/Contents and a fixed-width placeholder /ByteRange is written, then the
/ByteRange numbers are patched in place (exactly like a real signing
process would) so that the coverage is correct.
"""

import hashlib
import re
from io import BytesIO
from pathlib import Path

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.annotations import Text
from pypdf.errors import PyPdfError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    RectangleObject,
    TextStringObject,
)

CONTENTS_BYTES = 8192

BYTE_RANGE_PATTERN = re.compile(
    rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]"
)


def _make_signature_dict(base_digit: int) -> DictionaryObject:
    """Signature dictionary with fixed-width (10-digit) placeholder numbers."""
    return DictionaryObject({
        NameObject("/Type"): NameObject("/Sig"),
        NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
        NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
        NameObject("/ByteRange"): ArrayObject([
            NumberObject(int(str(base_digit + i) * 10)) for i in range(4)
        ]),
        NameObject("/Contents"): ByteStringObject(b"\x00" * CONTENTS_BYTES),
        NameObject("/Reason"): TextStringObject("testing"),
    })


def _patch_byte_range(data: bytes, base_digit: int) -> bytes:
    """
    Replace the placeholder /ByteRange numbers with the real coverage.

    The coverage includes the angle brackets of the /Contents hex string
    and excludes only the hex string itself.
    """
    result = bytearray(data)
    first_placeholder = str(base_digit).encode() * 10
    index = result.index(first_placeholder)
    contents_index = result.index(b"/Contents", index)
    opening = result.index(b"<", contents_index)
    closing = result.index(b">", opening)
    values = (0, opening + 1, closing, len(result) - closing)
    for i, value in enumerate(values):
        placeholder = str(base_digit + i).encode() * 10
        position = result.index(placeholder)
        result[position:position + 10] = f"{value:010d}".encode()
    return bytes(result)


def _external_signed_hash(data: bytes, signature_index: int = 0) -> str:
    """
    Hash the signed byte ranges, computed straight from the raw bytes
    (independently of any pypdf parsing).
    """
    matches = BYTE_RANGE_PATTERN.findall(data)
    start1, length1, start2, length2 = (
        int(value) for value in matches[signature_index]
    )
    digest = hashlib.sha256()
    digest.update(data[start1:start1 + length1])
    digest.update(data[start2:start2 + length2])
    return digest.hexdigest()


def _build_document(
    *,
    docmdp_permission=None,
    with_text_field=False,
    linearized=False,
) -> bytes:
    """Build a one-page document with one signed signature field."""
    writer = PdfWriter()
    if linearized:
        # An (unreferenced) dictionary holding /Linearized within the first
        # 1024 bytes is enough to mark the file as linearized.
        writer._add_object(DictionaryObject({
            NameObject("/Linearized"): NumberObject(1),
        }))
    page = writer.add_blank_page(612, 792)
    sig_dict = _make_signature_dict(1)
    if docmdp_permission is not None:
        sig_dict[NameObject("/Reference")] = ArrayObject([
            DictionaryObject({
                NameObject("/Type"): NameObject("/SigRef"),
                NameObject("/TransformMethod"): NameObject("/DocMDP"),
                NameObject("/TransformParams"): DictionaryObject({
                    NameObject("/Type"): NameObject("/TransformParams"),
                    NameObject("/P"): NumberObject(docmdp_permission),
                }),
            })
        ])
    sig_ref = writer._add_object(sig_dict)
    fields = ArrayObject()
    annots = ArrayObject()
    sig_field_ref = writer._add_object(DictionaryObject({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/T"): TextStringObject("Signature1"),
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/Rect"): RectangleObject((0, 0, 0, 0)),
        NameObject("/P"): page.indirect_reference,
        NameObject("/V"): sig_ref,
    }))
    fields.append(sig_field_ref)
    annots.append(sig_field_ref)
    if with_text_field:
        text_field_ref = writer._add_object(DictionaryObject({
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/T"): TextStringObject("TextField1"),
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/Rect"): RectangleObject((10, 10, 110, 30)),
            NameObject("/P"): page.indirect_reference,
        }))
        fields.append(text_field_ref)
        annots.append(text_field_ref)
    acroform_ref = writer._add_object(DictionaryObject({
        NameObject("/Fields"): fields,
        NameObject("/SigFlags"): NumberObject(3),
    }))
    writer.root_object[NameObject("/AcroForm")] = acroform_ref
    if docmdp_permission is not None:
        writer.root_object[NameObject("/Perms")] = DictionaryObject({
            NameObject("/DocMDP"): sig_ref,
        })
    page[NameObject("/Annots")] = annots
    buffer = BytesIO()
    writer.write(buffer)
    return _patch_byte_range(buffer.getvalue(), 1)


def _append_second_signature(signed_once: bytes) -> bytes:
    """Append a second revision holding a second signature."""
    writer = PdfWriter(BytesIO(signed_once), incremental=True)
    sig_ref = writer._add_object(_make_signature_dict(5))
    field_ref = writer._add_object(DictionaryObject({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/T"): TextStringObject("Signature2"),
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/Rect"): RectangleObject((0, 0, 0, 0)),
        NameObject("/V"): sig_ref,
    }))
    writer.root_object["/AcroForm"]["/Fields"].append(field_ref)
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()
    assert data.startswith(signed_once)
    return _patch_byte_range(data, 5)


def _find_field_idnum(writer: PdfWriter, name: str) -> int:
    for field in writer.root_object["/AcroForm"]["/Fields"]:
        if field.get_object().get("/T") == name:
            return field.idnum
    raise AssertionError(f"field {name} not found")


def test_incremental_annotation_preserves_two_signatures():
    signed_once = _build_document()
    hash1_original = _external_signed_hash(signed_once, 0)

    signed_twice = _append_second_signature(signed_once)
    assert signed_twice.startswith(signed_once)
    assert _external_signed_hash(signed_twice, 0) == hash1_original
    hash2_original = _external_signed_hash(signed_twice, 1)

    writer = PdfWriter(BytesIO(signed_twice), incremental=True)
    coverages = writer.signature_coverages
    assert len(coverages) == 2
    assert {coverage.field_name for coverage in coverages} == {
        "Signature1", "Signature2",
    }
    for coverage, expected in zip(coverages, BYTE_RANGE_PATTERN.findall(signed_twice)):
        assert coverage.byte_range == tuple(int(value) for value in expected)
        assert coverage.contents == b"\x00" * CONTENTS_BYTES

    # Add an annotation: the new object lands outside every covered range.
    writer.add_annotation(0, Text(text="a note", rect=(50, 50, 100, 100)))
    output = BytesIO()
    writer.write(output)
    final = output.getvalue()

    # The original prefix is byte-identical.
    assert final.startswith(signed_twice)
    # Both signatures still hash to their original value (external check).
    assert _external_signed_hash(final, 0) == hash1_original
    assert _external_signed_hash(final, 1) == hash2_original

    # The new xref/trailer /Prev chain is readable by pypdf.
    reader = PdfReader(BytesIO(final))
    assert len(reader.pages) == 1
    assert reader._startxref > len(signed_twice)
    annots = reader.pages[0]["/Annots"]
    assert any(
        annot.get_object().get("/Subtype") == "/Text" for annot in annots
    )
    fields = reader.get_fields()
    assert "Signature1" in fields
    assert "Signature2" in fields


def test_empty_increment_is_byte_identical():
    document = _build_document()
    writer = PdfWriter(BytesIO(document), incremental=True)
    output = BytesIO()
    writer.write(output)
    assert output.getvalue() == document


def test_signature_field_modification_is_rejected_and_file_not_truncated(tmp_path):
    document = _build_document()
    target = tmp_path / "signed.pdf"
    target.write_bytes(document)

    writer = PdfWriter(BytesIO(document), incremental=True)
    coverage = writer.signature_coverages[0]
    field = writer.get_object(coverage.field_idnum)
    field[NameObject("/F")] = NumberObject(2)
    with pytest.raises(PyPdfError, match="signature"):
        writer.write(target)
    # The failed write must not have truncated the signed file.
    assert target.read_bytes() == document


def test_signature_dictionary_modification_is_rejected_and_stream_untouched():
    writer = PdfWriter(BytesIO(_build_document()), incremental=True)
    coverage = writer.signature_coverages[0]
    sig_dict = writer.get_object(coverage.signature_idnum)
    sig_dict[NameObject("/Reason")] = TextStringObject("changed")
    stream = BytesIO()
    with pytest.raises(PyPdfError, match="signature"):
        writer.write(stream)
    assert stream.getvalue() == b""


def test_compress_identical_objects_is_rejected_when_signed():
    writer = PdfWriter(BytesIO(_build_document()), incremental=True)
    with pytest.raises(PyPdfError, match="compress_identical_objects"):
        writer.compress_identical_objects()


def test_docmdp_p1_rejects_any_change():
    document = _build_document(docmdp_permission=1)
    writer = PdfWriter(BytesIO(document), incremental=True)
    assert writer.signature_coverages[0].docmdp_permission == 1
    writer.add_metadata({"/Author": "someone"})
    with pytest.raises(PyPdfError, match="P=1"):
        writer.write(BytesIO())


def test_docmdp_p2_allows_form_fill_only():
    document = _build_document(docmdp_permission=2, with_text_field=True)

    # Filling in a form field is allowed.
    writer = PdfWriter(BytesIO(document), incremental=True)
    text_field = writer.get_object(_find_field_idnum(writer, "TextField1"))
    text_field[NameObject("/V")] = TextStringObject("filled")
    output = BytesIO()
    writer.write(output)
    assert output.getvalue().startswith(document)

    # Modifying a page is rejected.
    writer = PdfWriter(BytesIO(document), incremental=True)
    writer.pages[0][NameObject("/MediaBox")] = RectangleObject((0, 0, 100, 100))
    with pytest.raises(PyPdfError, match="P=2"):
        writer.write(BytesIO())


def test_docmdp_p3_allows_annotations():
    document = _build_document(docmdp_permission=3)

    writer = PdfWriter(BytesIO(document), incremental=True)
    writer.add_annotation(0, Text(text="ok", rect=(1, 1, 2, 2)))
    output = BytesIO()
    writer.write(output)
    assert output.getvalue().startswith(document)

    writer = PdfWriter(BytesIO(document), incremental=True)
    writer.pages[0][NameObject("/MediaBox")] = RectangleObject((0, 0, 100, 100))
    with pytest.raises(PyPdfError, match="P=3"):
        writer.write(BytesIO())


def test_linearized_signed_document_warns(caplog):
    document = _build_document(linearized=True)
    writer = PdfWriter(BytesIO(document), incremental=True)
    writer.add_metadata({"/Author": "someone"})
    output = BytesIO()
    writer.write(output)
    assert "linearization" in caplog.text
    assert output.getvalue().startswith(document)


def test_non_incremental_writer_is_not_validated():
    document = _build_document()
    writer = PdfWriter(BytesIO(document))
    assert writer.signature_coverages == []
    output = BytesIO()
    writer.write(output)  # must not raise
    reader = PdfReader(BytesIO(output.getvalue()))
    assert len(reader.pages) == 1


def test_write_ownership_and_stream_position(tmp_path):
    document = _build_document()

    # A file-like object is flushed, not closed, and left at the end.
    writer = PdfWriter(BytesIO(document), incremental=True)
    writer.add_annotation(0, Text(text="note", rect=(0, 0, 1, 1)))
    stream = BytesIO()
    my_file, returned = writer.write(stream)
    assert my_file is False
    assert returned is stream
    assert not stream.closed
    assert stream.tell() == len(stream.getvalue())

    # A path is opened, written and closed by the writer.
    writer = PdfWriter(BytesIO(document), incremental=True)
    target = tmp_path / "out.pdf"
    my_file, returned = writer.write(target)
    assert my_file is True
    assert returned.closed
    assert target.read_bytes() == document  # empty increment: identical bytes


def test_incremental_write_failure_does_not_truncate_path_target(tmp_path):
    document = _build_document(docmdp_permission=1)
    target = tmp_path / "certified.pdf"
    target.write_bytes(document)
    writer = PdfWriter(BytesIO(document), incremental=True)
    writer.add_metadata({"/Author": "someone"})
    with pytest.raises(PyPdfError):
        writer.write(target)
    assert target.read_bytes() == document


