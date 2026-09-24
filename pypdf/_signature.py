"""
Signature-aware validation helpers for incremental updates.

When a PDF document is signed, the signature dictionary contains a
/ByteRange entry covering (almost) the whole file at the time of
signing, and a /Contents entry holding the signature value. Any
change to the covered bytes invalidates the signature.

The incremental writer keeps the original bytes untouched and only
appends a new revision, so the cryptographic coverage stays intact as
long as:

* the signature field/dictionary objects themselves are not modified,
* covered objects are not compressed, renumbered or reordered
  (compress_identical_objects),
* the document-level DocMDP permission (certification signatures)
  allows the kind of change being made.

Capability boundaries:

* Multiple signatures are supported: every signature found in the
  original document is checked individually against the objects
  modified in the increment.
* DocMDP permissions are enforced conservatively:
  P=1 rejects any modification of an original (covered) object,
  P=2 only allows changes to form fields and the AcroForm
  dictionary, P=3 additionally allows annotations (and the
  /Annots entry of pages).
* Linearized files: appending an increment invalidates the
  linearization. pypdf does not update the linearization dictionary;
  a warning is emitted and the document remains a valid, but no
  longer linearized, PDF.
* FieldMDP/lock dictionaries and appearance re-generation of
  signature fields are not validated.
"""

from dataclasses import dataclass
from typing import Iterator, Optional, Protocol, cast

from ._utils import StreamType, logger_warning
from .generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    PdfObject,
)


@dataclass
class SignatureCoverage:
    """
    Byte-range coverage of one digital signature of the original document.

    Attributes:
        signature_idnum: idnum of the signature dictionary (the object
            holding /ByteRange and /Contents). Falls back to the idnum of
            the signature field when the dictionary is a direct object,
            and to -1 when neither is indirect.
        field_idnum: idnum of the signature form field, if indirect.
        field_name: (partial) name of the signature field.
        byte_range: the four /ByteRange numbers
            (offset1, length1, offset2, length2).
        contents: raw bytes of the /Contents placeholder/signature.
        docmdp_permission: DocMDP permission (1, 2 or 3) when this
            signature is the document certification signature
            (referenced from /Perms /DocMDP), else None.

    """

    signature_idnum: int
    field_idnum: Optional[int]
    field_name: str
    byte_range: tuple[int, int, int, int]
    contents: bytes
    docmdp_permission: Optional[int] = None

    @property
    def covered_ranges(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """The two covered (start, stop) byte ranges of the signature."""
        start1, length1, start2, length2 = self.byte_range
        return (start1, start1 + length1), (start2, start2 + length2)

    def covers_offset(self, offset: int) -> bool:
        """Return True if the given file offset is covered by the signature."""
        return any(start <= offset < stop for start, stop in self.covered_ranges)


def _dereference(value: PdfObject) -> PdfObject:
    if isinstance(value, IndirectObject):
        return cast(PdfObject, value.get_object())
    return value


def _iter_signature_fields(
    root: DictionaryObject,
) -> Iterator[tuple[Optional[int], DictionaryObject, str]]:
    """Yield (field_idnum, field_dict, field_name) for every signature field."""
    acroform = root.get("/AcroForm")
    if acroform is None:
        return
    acroform_dict = _dereference(cast(PdfObject, acroform))
    if not isinstance(acroform_dict, DictionaryObject):
        return
    fields = acroform_dict.get("/Fields")
    if not isinstance(fields, ArrayObject):
        return

    def walk(
        field_array: ArrayObject, inherited_name: str
    ) -> Iterator[tuple[Optional[int], DictionaryObject, str]]:
        for field in field_array:
            field_idnum = field.idnum if isinstance(field, IndirectObject) else None
            field_dict = _dereference(field)
            if not isinstance(field_dict, DictionaryObject):
                continue
            name = str(field_dict.get("/T", inherited_name))
            if str(field_dict.get("/FT", "")) == "/Sig":
                yield field_idnum, field_dict, name
            kids = field_dict.get("/Kids")
            if isinstance(kids, ArrayObject):
                yield from walk(kids, name)

    yield from walk(fields, "")


def _extract_docmdp_permissions(root: DictionaryObject) -> dict[int, int]:
    """Map idnum of certification signature dictionaries to their DocMDP /P."""
    perms = root.get("/Perms")
    if perms is None:
        return {}
    perms_dict = _dereference(cast(PdfObject, perms))
    if not isinstance(perms_dict, DictionaryObject):
        return {}
    docmdp = perms_dict.get("/DocMDP")
    if docmdp is None:
        return {}
    sig_dict = _dereference(cast(PdfObject, docmdp))
    if not isinstance(sig_dict, DictionaryObject):
        return {}
    permission = 2  # default value of /P per ISO 32000
    references = sig_dict.get("/Reference")
    if isinstance(references, ArrayObject):
        for reference in references:
            reference_dict = _dereference(reference)
            if not isinstance(reference_dict, DictionaryObject):
                continue
            if str(reference_dict.get("/TransformMethod")) != "/DocMDP":
                continue
            params = reference_dict.get("/TransformParams")
            if params is not None:
                params_dict = _dereference(cast(PdfObject, params))
                if isinstance(params_dict, DictionaryObject):
                    permission = int(params_dict.get("/P", 2))
    sig_idnum = docmdp.idnum if isinstance(docmdp, IndirectObject) else -1
    return {sig_idnum: permission}


def extract_signature_coverages(reader: "PdfReaderProtocol") -> list[SignatureCoverage]:
    """
    Extract the byte-range coverage of every signature of a document.

    Args:
        reader: The reader of the original (signed) document.

    Returns:
        A list of :class:`SignatureCoverage`, one per signed signature
        field. Unsigned signature fields (without /V) are ignored.

    """
    coverages: list[SignatureCoverage] = []
    try:
        root = _dereference(reader.trailer["/Root"])
    except Exception:  # malformed documents
        return coverages
    if not isinstance(root, DictionaryObject):
        return coverages
    docmdp_permissions = _extract_docmdp_permissions(root)
    for field_idnum, field_dict, field_name in _iter_signature_fields(root):
        value = field_dict.get("/V")
        if value is None:
            continue
        sig_dict = _dereference(cast(PdfObject, value))
        if not isinstance(sig_dict, DictionaryObject):
            continue
        byte_range = sig_dict.get("/ByteRange")
        contents = sig_dict.get("/Contents")
        if byte_range is None or contents is None:
            continue
        if isinstance(contents, bytes):
            contents_bytes = bytes(contents)
        else:
            contents_bytes = contents.original_bytes
        try:
            ranges = tuple(int(number) for number in cast(ArrayObject, byte_range))
        except (TypeError, ValueError):
            logger_warning(
                "Ignoring signature field %(name)s with malformed /ByteRange",
                source=__name__,
                name=field_name,
            )
            continue
        if len(ranges) != 4:
            logger_warning(
                "Ignoring signature field %(name)s with malformed /ByteRange",
                source=__name__,
                name=field_name,
            )
            continue
        if isinstance(value, IndirectObject):
            signature_idnum = value.idnum
        elif field_idnum is not None:
            signature_idnum = field_idnum
        else:
            signature_idnum = -1
        coverages.append(
            SignatureCoverage(
                signature_idnum=signature_idnum,
                field_idnum=field_idnum,
                field_name=field_name,
                byte_range=(ranges[0], ranges[1], ranges[2], ranges[3]),
                contents=contents_bytes,
                docmdp_permission=docmdp_permissions.get(signature_idnum),
            )
        )
    return coverages


def get_object_offsets(reader: "PdfReaderProtocol") -> dict[int, int]:
    """
    Return the file offset of every indirect object known to the reader.

    Objects living inside object streams have no direct offset and are
    not included.
    """
    offsets: dict[int, int] = {}
    for generation_entries in reader.xref.values():
        for idnum, offset in generation_entries.items():
            offsets[idnum] = offset
    return offsets


def is_linearized(reader: "PdfReaderProtocol") -> bool:
    """Return True if the document starts with a linearization dictionary."""
    stream: StreamType = reader.stream
    position = stream.tell()
    try:
        stream.seek(0)
        return b"/Linearized" in stream.read(1024)
    finally:
        stream.seek(position)


class PdfReaderProtocol(Protocol):
    """Structural type for the reader attributes used in this module."""

    stream: StreamType
    trailer: DictionaryObject
    xref: dict[int, dict[int, int]]
