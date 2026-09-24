# Signed documents and incremental updates

A signed PDF must not be rewritten: the signature dictionary covers the
bytes of the file at signing time through its `/ByteRange` entry, so any
reordering, compression or header rewrite invalidates the signature.

To add content (for example a comment annotation) to a signed document,
use the incremental writer. It copies the original bytes unchanged and
appends a new revision (new/updated objects, a new xref stream and a
trailer with a `/Prev` chain):

```python
from pypdf import PdfWriter
from pypdf.annotations import Text

writer = PdfWriter("signed.pdf", incremental=True)
writer.add_annotation(0, Text(text="reviewed", rect=(50, 50, 100, 100)))
writer.write("signed-with-comment.pdf")
```

Before anything is written, pypdf validates the pending increment against
the signatures of the original document (`PdfWriter.signature_coverages`)
and raises `PyPdfError` if the update would invalidate a signature:

* modifying a signature field or signature dictionary is rejected;
* `compress_identical_objects()` is rejected on signed documents, as it
  renumbers and rewrites covered objects;
* the DocMDP permission of a certification signature is enforced:
  `P=1` rejects any change to the original objects, `P=2` only allows
  filling in form fields, `P=3` additionally allows annotations.

Capability boundaries:

* Multiple signatures are supported; every signature of the original
  document is checked individually.
* Linearized files stay readable and the appended revision is valid, but
  the linearization is lost (pypdf does not update the linearization
  dictionary); a warning is emitted.
* FieldMDP lock dictionaries and signature appearance regeneration are
  not validated.

When writing to a path in incremental mode, the output is rendered in
memory first, so a rejected update never truncates the signed file on
disk. When writing to a file-like object, the object is flushed but not
closed and is left positioned at the end of the written data.

