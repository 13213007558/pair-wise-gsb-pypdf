"""Tests for signature-aware incremental writing (pypdf/_signatures.py)."""

import hashlib
import logging
import re
from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.annotations import FreeText
from pypdf.errors import SignatureIntegrityError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

CONTENTS_BYTES = 64  # serialized as 128 hex chars; holds a sha256 hex digest + padding
BYTE_RANGE_PLACEHOLDER = {
    "sig1": b"1111111111",
    "sig2": b"2222222222",
    "docmdp": b"3333333333",
}
CONTENTS_FILL = {"sig1": b"\x00", "sig2": b"\x01", "docmdp": b"\x02"}


def _signature_dictionary(name, docmdp_permission=None):
    """Build a mock signature dictionary with fixed-width placeholders."""
    sig = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Sig"),
            NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
            NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
            NameObject("/ByteRange"): ArrayObject(
                [NumberObject(int(BYTE_RANGE_PLACEHOLDER[name]))] * 4
            ),
            NameObject("/Contents"): ByteStringObject(
                CONTENTS_FILL[name] * CONTENTS_BYTES
            ),
        }
    )
    if docmdp_permission is not None:
        sig[NameObject("/Reference")] = ArrayObject(
            [
                DictionaryObject(
                    {
                        NameObject("/Type"): NameObject("/SigRef"),
                        NameObject("/TransformParams"): DictionaryObject(
                            {
                                NameObject("/Type"): NameObject("/TransformParams"),
                                NameObject("/P"): NumberObject(docmdp_permission),
                            }
                        ),
                    }
                )
            ]
        )
    return sig


def _build_signed_pdf(
    *, docmdp_permission=None, fill_second_signature=True, linearized_marker=False
):
    """
    Build an in-memory PDF with two signature fields and patch the
    placeholders so that the signatures cover selected objects.

    Returns a tuple (data, ids, coverage):
    * data: the final PDF bytes
    * ids: dict of relevant object ids
    * coverage: dict signature name -> list of covered (start, stop) segments
    """
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    sig1 = writer._add_object(_signature_dictionary("sig1"))
    field1 = writer._add_object(
        DictionaryObject(
            {
                NameObject("/FT"): NameObject("/Sig"),
                NameObject("/T"): TextStringObject("Signature1"),
                NameObject("/V"): sig1,
            }
        )
    )
    field2_dict = DictionaryObject(
        {
            NameObject("/FT"): NameObject("/Sig"),
            NameObject("/T"): TextStringObject("Signature2"),
        }
    )
    sig2 = None
    if fill_second_signature:
        sig2 = writer._add_object(_signature_dictionary("sig2"))
        field2_dict[NameObject("/V")] = sig2
    field2 = writer._add_object(field2_dict)
    acroform = writer._add_object(
        DictionaryObject(
            {
                NameObject("/Fields"): ArrayObject([field1, field2]),
                NameObject("/SigFlags"): NumberObject(3),
            }
        )
    )
    writer._root_object[NameObject("/AcroForm")] = acroform
    docmdp = None
    if docmdp_permission is not None:
        docmdp = writer._add_object(_signature_dictionary("docmdp", docmdp_permission))
        writer._root_object[NameObject("/Perms")] = DictionaryObject(
            {NameObject("/DocMDP"): docmdp}
        )
    if linearized_marker:
        # Fake a linearization parameter dictionary within the first 1024 bytes.
        writer.add_metadata({"/Linearized": "1.0"})
    buffer = BytesIO()
    writer.write(buffer)
    data = buffer.getvalue()

    reader = PdfReader(BytesIO(data))
    offsets = dict(reader.xref[0])

    def span(idnum):
        start = offsets[idnum]
        end = data.find(b"endobj", start) + len(b"endobj")
        return (start, end)

    ids = {
        "page": reader.pages[0].indirect_reference.idnum,
        "catalog": reader.trailer.raw_get("/Root").idnum,
        "info": reader.trailer.raw_get("/Info").idnum,
        "acroform": acroform.idnum,
        "field1": field1.idnum,
        "sig1": sig1.idnum,
        "field2": field2.idnum,
    }
    if sig2 is not None:
        ids["sig2"] = sig2.idnum

    coverage = {"sig1": [span(ids["info"]), span(ids["catalog"])]}
    if sig2 is not None:
        coverage["sig2"] = [span(ids["catalog"]), span(ids["acroform"])]
    else:
        # The empty signature field is covered by the first signature, so
        # that filling it exercises the multi-signature exception.
        coverage["sig1"] = [span(ids["catalog"]), span(ids["field2"])]
    if docmdp is not None:
        coverage["docmdp"] = [span(ids["catalog"]), span(ids["info"])]

    def patch_byte_range(data, name, segments):
        segments = sorted(segments)
        flat = [
            segments[0][0],
            segments[0][1] - segments[0][0],
            segments[1][0],
            segments[1][1] - segments[1][0],
        ]
        old = b"/ByteRange [ " + b" ".join([BYTE_RANGE_PLACEHOLDER[name]] * 4) + b" ]"
        new = ("/ByteRange [ " + " ".join(f"{v:010d}" for v in flat) + " ]").encode()
        assert len(old) == len(new)
        assert data.count(old) == 1
        return data.replace(old, new)

    def patch_contents(data, name, segments):
        digest = hashlib.sha256(
            b"".join(data[start:stop] for start, stop in segments)
        ).hexdigest()
        old_hex = CONTENTS_FILL[name].hex().encode() * CONTENTS_BYTES
        old = b"<" + old_hex + b">"
        new = b"<" + digest.encode() + b"0" * (len(old_hex) - len(digest)) + b">"
        assert data.count(old) == 1
        return data.replace(old, new)

    for name, segments in coverage.items():
        data = patch_byte_range(data, name, segments)
    for name, segments in coverage.items():
        data = patch_contents(data, name, sorted(segments))
    return data, ids, coverage


def _externally_verify_signatures(data):
    """
    Recompute the byte-range digests from raw bytes only (no pypdf objects)
    and compare them against the digests stored in /Contents.
    """
    byte_ranges = re.findall(rb"/ByteRange \[ (\d+) (\d+) (\d+) (\d+) \]", data)
    contents = re.findall(rb"/Contents <([0-9a-f]+)>", data)
    assert len(byte_ranges) > 0
    assert len(byte_ranges) == len(contents)
    for raw_range, content in zip(byte_ranges, contents):
        offset1, length1, offset2, length2 = (int(v) for v in raw_range)
        digest = hashlib.sha256(
            data[offset1 : offset1 + length1] + data[offset2 : offset2 + length2]
        ).hexdigest()
        assert content.decode().startswith(digest)


def _add_note(writer):
    return writer.add_annotation(
        0,
        FreeText(text="harmless note", rect=(10, 10, 80, 40), font_size="12pt"),
    )


def test_incremental_annotation_preserves_signed_prefix():
    data, ids, coverage = _build_signed_pdf()
    assert len(coverage) == 2  # two signatures

    writer = PdfWriter(BytesIO(data), incremental=True)
    assert writer.list_objects_in_increment() == []  # cloning changes nothing
    _add_note(writer)
    out = BytesIO()
    writer.write(out)
    result = out.getvalue()

    # The original prefix is byte-identical (checked via the original hash).
    assert len(result) > len(data)
    assert result[: len(data)] == data
    assert hashlib.sha256(result[: len(data)]).digest() == hashlib.sha256(data).digest()

    # The new xref/trailer/Prev chain can be read back.
    new_startxref = int(result[result.rfind(b"startxref") :].splitlines()[1])
    assert new_startxref >= len(data)
    reader = PdfReader(BytesIO(result))
    assert len(reader.pages) == 1
    annots = reader.pages[0]["/Annots"]
    assert len(annots) == 1
    assert annots[0].get_object()["/Subtype"] == "/FreeText"
    assert reader.trailer["/Root"].get_object()["/AcroForm"] is not None

    # External byte-range verification of both signatures.
    _externally_verify_signatures(result)

    # The caller-provided stream is left open and positioned at the end.
    assert not out.closed
    assert out.tell() == len(result)


def test_modifying_covered_info_object_is_rejected_before_writing():
    data, ids, _ = _build_signed_pdf()
    writer = PdfWriter(BytesIO(data), incremental=True)
    writer.add_metadata({"/Author": "eve"})  # /Info is covered by sig1
    out = BytesIO()
    with pytest.raises(SignatureIntegrityError, match="covered by a signature"):
        writer.write(out)
    assert out.getvalue() == b""  # nothing was written


def test_modifying_covered_catalog_is_rejected():
    data, ids, _ = _build_signed_pdf()
    writer = PdfWriter(BytesIO(data), incremental=True)
    writer._root_object[NameObject("/PageLayout")] = NameObject("/OneColumn")
    with pytest.raises(SignatureIntegrityError, match="covered by a signature"):
        writer.write(BytesIO())


def test_modifying_object_covered_by_second_signature_only_is_rejected():
    """Multiple signatures: the union of all byte ranges is enforced."""
    data, ids, _ = _build_signed_pdf()
    writer = PdfWriter(BytesIO(data), incremental=True)
    acroform = writer.get_object(ids["acroform"])  # covered by sig2 only
    acroform[NameObject("/NeedAppearances")] = NameObject("/Yes")
    with pytest.raises(SignatureIntegrityError, match="covered by a signature"):
        writer.write(BytesIO())


def test_modifying_signature_field_or_dictionary_is_rejected():
    data, ids, _ = _build_signed_pdf()

    writer = PdfWriter(BytesIO(data), incremental=True)
    writer.get_object(ids["field1"])[NameObject("/T")] = TextStringObject("forged")
    with pytest.raises(SignatureIntegrityError, match="signature field"):
        writer.write(BytesIO())

    writer = PdfWriter(BytesIO(data), incremental=True)
    writer.get_object(ids["sig1"])[NameObject("/Reason")] = TextStringObject("forged")
    with pytest.raises(SignatureIntegrityError, match="signature dictionary"):
        writer.write(BytesIO())


def test_docmdp_p1_rejects_any_modification():
    data, ids, _ = _build_signed_pdf(docmdp_permission=1)
    writer = PdfWriter(BytesIO(data), incremental=True)
    _add_note(writer)
    with pytest.raises(SignatureIntegrityError, match="DocMDP"):
        writer.write(BytesIO())


def test_docmdp_p3_allows_annotation_outside_coverage():
    data, ids, _ = _build_signed_pdf(docmdp_permission=3)
    writer = PdfWriter(BytesIO(data), incremental=True)
    _add_note(writer)
    out = BytesIO()
    writer.write(out)
    assert out.getvalue()[: len(data)] == data
    _externally_verify_signatures(out.getvalue())


def test_filling_empty_signature_field_is_allowed():
    """Multi-signature workflow: an empty field may be filled incrementally."""
    data, ids, _ = _build_signed_pdf(fill_second_signature=False)
    writer = PdfWriter(BytesIO(data), incremental=True)
    new_sig = writer._add_object(
        DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Sig"),
                NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
                NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
                NameObject("/ByteRange"): ArrayObject(
                    [NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)]
                ),
                NameObject("/Contents"): ByteStringObject(b"\x00" * 16),
            }
        )
    )
    writer.get_object(ids["field2"])[NameObject("/V")] = new_sig
    out = BytesIO()
    writer.write(out)
    assert out.getvalue()[: len(data)] == data
    reader = PdfReader(BytesIO(out.getvalue()))
    fields = reader.trailer["/Root"].get_object()["/AcroForm"].get_object()["/Fields"]
    assert "/V" in fields[1].get_object()


def test_touching_empty_signature_field_without_signing_is_rejected():
    data, ids, _ = _build_signed_pdf(fill_second_signature=False)
    writer = PdfWriter(BytesIO(data), incremental=True)
    # field2 is covered by sig1; renaming it is not a signature fill.
    writer.get_object(ids["field2"])[NameObject("/T")] = TextStringObject("renamed")
    with pytest.raises(SignatureIntegrityError, match="covered by a signature"):
        writer.write(BytesIO())


def test_linearized_file_warns_about_lost_linearization(caplog):
    data, ids, _ = _build_signed_pdf(linearized_marker=True)
    writer = PdfWriter(BytesIO(data), incremental=True)
    _add_note(writer)
    out = BytesIO()
    with caplog.at_level(logging.WARNING, logger="pypdf._signatures"):
        writer.write(out)
    assert "linearized" in caplog.text.lower()
    assert out.getvalue()[: len(data)] == data


def test_failed_incremental_write_does_not_truncate_target(tmp_path):
    data, ids, _ = _build_signed_pdf()
    target = tmp_path / "signed.pdf"
    target.write_bytes(data)

    # Validation failure: the target file is never touched.
    writer = PdfWriter(BytesIO(data), incremental=True)
    writer.add_metadata({"/Author": "eve"})
    with pytest.raises(SignatureIntegrityError):
        writer.write(target)
    assert target.read_bytes() == data

    # Failure in the middle of writing: the target file is still intact.
    writer = PdfWriter(BytesIO(data), incremental=True)
    _add_note(writer)

    def failing_increment(stream):
        raise RuntimeError("simulated I/O failure")

    writer._write_increment = failing_increment
    with pytest.raises(RuntimeError, match="simulated I/O failure"):
        writer.write(target)
    assert target.read_bytes() == data
    assert list(tmp_path.iterdir()) == [target]  # no temporary file left behind

    # A successful write to a path is atomic and keeps the signed prefix.
    writer = PdfWriter(BytesIO(data), incremental=True)
    _add_note(writer)
    my_file, stream = writer.write(target)
    assert my_file is True
    written = target.read_bytes()
    assert written[: len(data)] == data
    reader = PdfReader(BytesIO(written))
    assert len(reader.pages[0]["/Annots"]) == 1


def test_incremental_write_to_path_without_changes(tmp_path):
    data, ids, _ = _build_signed_pdf()
    target = tmp_path / "signed.pdf"
    writer = PdfWriter(BytesIO(data), incremental=True)
    writer.write(target)
    assert target.read_bytes() == data


def test_non_incremental_writer_behavior_is_unchanged():
    """A full rewrite is not signature-validated (and invalidates signatures)."""
    data, ids, _ = _build_signed_pdf()
    writer = PdfWriter(BytesIO(data))
    writer.add_metadata({"/Author": "eve"})
    writer._root_object[NameObject("/PageLayout")] = NameObject("/OneColumn")
    out = BytesIO()
    writer.write(out)  # must not raise
    assert out.getvalue()[: len(data)] != data
