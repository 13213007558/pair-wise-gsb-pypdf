"""
Signature-aware validation for incremental updates of signed PDF documents.

When a PDF document is signed, the signature dictionary stores a
``/ByteRange`` (the byte regions the signature covers) and ``/Contents``
(the signature value computed over those regions). Any change to the
covered bytes invalidates the signature, so signed documents may only be
extended through *incremental updates*: the original bytes are kept
untouched and new or modified objects are appended as a new revision
whose xref section chains back through ``/Prev``.

This module inspects the signatures of the original document before an
incremental :class:`pypdf.PdfWriter` writes anything, and rejects updates
that would tamper with signed content.

Capability boundaries
---------------------
* Multiple signatures: all signature dictionaries found in the document
  are honored. A modification is rejected if it violates *any* of them.
  Filling a previously *empty* signature field (adding a ``/V`` signature
  dictionary to it) is explicitly allowed so that multi-signature
  workflows keep working.
* DocMDP: a ``/P`` value of 1 (no changes allowed) rejects any
  modification. ``/P`` values 2 (form fill-in and signing) and 3
  (additionally annotations) are permitted, but pypdf only enforces the
  byte-range level checks; it does not verify the semantic kind of each
  change against the DocMDP policy.
* Linearized files: an incremental update invalidates linearization
  ("fast web view"). The update is allowed, but a warning is emitted.
* Objects stored in (compressed) object streams cannot be checked with
  byte granularity; modifying such an object is rejected when its
  container stream is covered by a signature.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ._utils import logger_warning
from .errors import SignatureIntegrityError
from .generic import DictionaryObject, IndirectObject

if TYPE_CHECKING:
    from ._reader import PdfReader
    from ._writer import PdfWriter

#: Sentinel offset returned by `_object_file_offset` for objects that
#: live inside an object stream (and therefore have no own file offset).
IN_OBJECT_STREAM = -1


@dataclass
class SignatureInfo:
    """
    Describes one signature found in a PDF document.

    Args:
        field_id: Object id of the signature form field, if indirect.
        sig_id: Object id of the signature dictionary (``/V``), if indirect.
        byte_range: The four ``/ByteRange`` numbers
            ``(offset1, length1, offset2, length2)``.
        subfilter: The ``/SubFilter`` of the signature dictionary.
        docmdp_permission: The DocMDP permission ``/P`` (1, 2 or 3) if this
            signature is referenced from ``/Perms`` ``/DocMDP``, else None.
    """

    field_id: Optional[int]
    sig_id: Optional[int]
    byte_range: tuple[int, int, int, int]
    subfilter: str
    docmdp_permission: Optional[int] = None

    @property
    def covered_segments(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """Byte ranges covered by this signature as ``(start, stop)`` pairs."""
        offset1, length1, offset2, length2 = self.byte_range
        return (offset1, offset1 + length1), (offset2, offset2 + length2)


def _idnum_of(obj: object) -> Optional[int]:
    return obj.idnum if isinstance(obj, IndirectObject) else None


def _build_signature_info(
    sig: DictionaryObject,
    field_reference: object,
    sig_reference: object,
    docmdp_permission: Optional[int],
) -> Optional[SignatureInfo]:
    byte_range = sig.get("/ByteRange")
    if byte_range is None or "/Contents" not in sig:
        # Not a (fully) filled signature; nothing to protect yet.
        return None
    try:
        numbers = tuple(int(v) for v in byte_range)
    except (TypeError, ValueError):
        return None
    if len(numbers) != 4:
        return None
    return SignatureInfo(
        field_id=_idnum_of(field_reference),
        sig_id=_idnum_of(sig_reference),
        byte_range=numbers,  # type: ignore[arg-type]
        subfilter=str(sig.get("/SubFilter", "")),
        docmdp_permission=docmdp_permission,
    )


def _docmdp_permission_of(sig: DictionaryObject) -> Optional[int]:
    """Extract the DocMDP permission ``/P`` from a signature dictionary."""
    references = sig.get("/Reference")
    if not references:
        return None
    for reference in references:
        reference_obj = reference.get_object()
        if not isinstance(reference_obj, DictionaryObject):
            continue
        transform_params = reference_obj.get("/TransformParams")
        if transform_params is None:
            continue
        transform_params = transform_params.get_object()
        if isinstance(transform_params, DictionaryObject):
            permission = transform_params.get("/P")
            if permission is not None:
                return int(permission)
    return None


def extract_signatures(reader: "PdfReader") -> list[SignatureInfo]:
    """
    Collect information about all signatures embedded in the document.

    Both document-level signatures (AcroForm fields of type ``/Sig`` with a
    filled ``/V``) and the DocMDP signature referenced from the catalog
    ``/Perms`` entry are returned.

    Args:
        reader: The reader of the original (signed) document.

    Returns:
        A list of :class:`SignatureInfo`; empty for unsigned documents.

    """
    signatures: list[SignatureInfo] = []
    root = reader.trailer.get("/Root")
    if root is None:
        return signatures
    catalog = root.get_object()
    if not isinstance(catalog, DictionaryObject):
        return signatures

    acroform = catalog.get("/AcroForm")
    if acroform is not None:
        acroform_obj = acroform.get_object()
        if isinstance(acroform_obj, DictionaryObject):
            for field_reference in acroform_obj.get("/Fields", []):
                field = (
                    field_reference.get_object()
                    if isinstance(field_reference, IndirectObject)
                    else field_reference
                )
                if (
                    not isinstance(field, DictionaryObject)
                    or field.get("/FT") != "/Sig"
                ):
                    continue
                sig_reference = field.get("/V")
                if sig_reference is None:
                    # Empty signature field; may still be filled later.
                    continue
                sig = sig_reference.get_object()
                if not isinstance(sig, DictionaryObject):
                    continue
                info = _build_signature_info(sig, field_reference, sig_reference, None)
                if info is not None:
                    signatures.append(info)

    perms = catalog.get("/Perms")
    if perms is not None:
        perms_obj = perms.get_object()
        if isinstance(perms_obj, DictionaryObject):
            docmdp_reference = perms_obj.get("/DocMDP")
            if docmdp_reference is not None:
                sig = docmdp_reference.get_object()
                if isinstance(sig, DictionaryObject):
                    info = _build_signature_info(
                        sig, None, docmdp_reference, _docmdp_permission_of(sig)
                    )
                    if info is not None:
                        signatures.append(info)
    return signatures


def _object_file_offset(reader: "PdfReader", idnum: int) -> Optional[int]:
    """
    Return the file offset of an original object.

    Returns ``IN_OBJECT_STREAM`` for objects stored in an object stream and
    None if the object is unknown (e.g. a free entry).
    """
    if idnum in reader.xref_objStm:
        return IN_OBJECT_STREAM
    for generation in reader.xref:
        offset = reader.xref[generation].get(idnum)
        if offset is not None:
            return offset
    return None


def _is_covered(offset: int, segments: list[tuple[int, int]]) -> bool:
    return any(start <= offset < stop for start, stop in segments)


def _is_empty_signature_fill(writer: "PdfWriter", idnum: int) -> bool:
    """
    Check whether the modification of an original object consists of filling
    a previously empty signature field (adding ``/V``), which is the
    standard way to apply an additional signature to a document.
    """
    reader = writer._reader
    assert reader is not None
    try:
        original = reader.get_object(IndirectObject(idnum, 0, reader))
    except Exception:
        return False
    if (
        not isinstance(original, DictionaryObject)
        or original.get("/FT") != "/Sig"
        or original.get("/V") is not None
    ):
        return False
    new_object = writer._objects[idnum - 1]
    return (
        isinstance(new_object, DictionaryObject)
        and new_object.get("/V") is not None
    )


def _is_linearized(reader: "PdfReader") -> bool:
    """
    Check whether the original document is linearized.

    A linearization parameter dictionary is required to appear within the
    first 1024 bytes of the file.
    """
    stream = reader.stream
    position = stream.tell()
    try:
        stream.seek(0)
        return b"/Linearized" in stream.read(1024)
    finally:
        stream.seek(position)


def validate_incremental_update(writer: "PdfWriter") -> None:
    """
    Validate a pending incremental update against the signatures of the
    original document.

    Must be called before any byte is written to the output stream. Raises
    :class:`pypdf.errors.SignatureIntegrityError` if the update would
    tamper with signed content. Does nothing for unsigned documents or
    when no object was modified.

    Args:
        writer: A :class:`pypdf.PdfWriter` in incremental mode.

    """
    reader = writer._reader
    assert reader is not None
    signatures = extract_signatures(reader)
    if not signatures:
        return
    if _is_linearized(reader):
        logger_warning(
            "Incremental update of a linearized PDF: the linearization "
            "(fast web view) of the original document is lost.",
            source=__name__,
        )
    modified = writer.list_objects_in_increment()
    if not modified:
        return
    if any(signature.docmdp_permission == 1 for signature in signatures):
        raise SignatureIntegrityError(
            "The document is certified with DocMDP permission /P=1 "
            "(no changes allowed); no incremental update is permitted."
        )
    protected_ids: dict[int, str] = {}
    for signature in signatures:
        if signature.field_id is not None:
            protected_ids[signature.field_id] = "signature field"
        if signature.sig_id is not None:
            protected_ids[signature.sig_id] = "signature dictionary"
    segments = [
        segment
        for signature in signatures
        for segment in signature.covered_segments
    ]
    original_count = len(writer._original_hash)
    for reference in modified:
        idnum = reference.idnum
        if idnum - 1 >= original_count:
            # New object appended in the new revision; always allowed.
            continue
        if _is_empty_signature_fill(writer, idnum):
            # Filling a previously empty signature field is the standard
            # multi-signature workflow and is explicitly allowed.
            continue
        if idnum in protected_ids:
            raise SignatureIntegrityError(
                f"The incremental update modifies the {protected_ids[idnum]} "
                f"(object {idnum} 0); changing existing signature fields or "
                "dictionaries invalidates the signature."
            )
        offset = _object_file_offset(reader, idnum)
        if offset is None:
            continue
        if offset == IN_OBJECT_STREAM:
            container_id = reader.xref_objStm[idnum][0]
            container_offset = _object_file_offset(reader, container_id)
            if container_offset is not None and _is_covered(container_offset, segments):
                raise SignatureIntegrityError(
                    f"Object {idnum} 0 is stored in compressed object stream "
                    f"{container_id} 0 which is covered by a signature "
                    "/ByteRange; modifying compressed objects of a signed "
                    "document is not supported."
                )
            continue
        if _is_covered(offset, segments):
            raise SignatureIntegrityError(
                f"Object {idnum} 0 is covered by a signature /ByteRange; "
                "modifying, compressing or reordering covered objects "
                "invalidates the signature. Only objects outside the "
                "covered byte ranges may be changed, and only by appending "
                "a new revision."
            )
