# Digital signatures and incremental updates

A signed PDF must not be rewritten: the signature covers a `/ByteRange` of
the original file bytes, so any change to those bytes invalidates it. To add
content (for example an annotation) to a signed document, use the
incremental mode of `PdfWriter`, which keeps the original bytes
byte-identical and appends the changes as a new revision:

```python
from pypdf import PdfReader, PdfWriter

writer = PdfWriter("signed.pdf", incremental=True)
# ... modify objects that are not covered by a signature ...
with open("signed-with-note.pdf", "wb") as fp:
    writer.write(fp)
```

Before anything is written, pypdf validates the pending update against all
signatures of the original document and raises
`pypdf.errors.SignatureIntegrityError` if the update would tamper with
signed content:

* Modifying a signature field or a signature dictionary is rejected.
* Modifying, compressing or reordering an object covered by a signature
  `/ByteRange` is rejected; only objects outside the covered byte ranges
  may be changed, and only by appending a new revision.
* New objects are always allowed.

## Capability boundaries

* **Multiple signatures**: all signature dictionaries in the document are
  honored; a modification is rejected if it violates *any* of them. Filling
  a previously *empty* signature field (adding a `/V` signature dictionary)
  is allowed, so multi-signature workflows keep working.
* **DocMDP**: a certification with `/P = 1` (no changes allowed) rejects
  any modification. `/P = 2` (form fill-in and signing) and `/P = 3`
  (additionally annotations) are permitted, but pypdf only enforces the
  byte-range checks; it does not verify the semantic kind of each change
  against the DocMDP policy.
* **Linearized files**: an incremental update invalidates linearization
  ("fast web view"). The update is allowed, but a warning is emitted.
* **Compressed objects**: objects stored in object streams cannot be checked
  with byte granularity; modifying such an object is rejected when its
  container stream is covered by a signature.
* **Atomic writes**: when writing to a file path in incremental mode, the
  new revision is rendered to a temporary file first and then moved over the
  target, so a failure mid-write cannot truncate an existing file. A
  caller-provided stream is flushed but never closed by pypdf, and its
  position is left at the end of the written data.

The non-incremental writer is not affected by these checks: a full rewrite
re-layouts the file and invalidates signatures by design.

