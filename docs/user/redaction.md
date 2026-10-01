# Redaction (permanent content removal)

Drawing a white or black rectangle over sensitive text does **not** remove
it from a PDF: the text stays in the content stream and can be recovered.
`pypdf.redact_and_sanitize()` instead parses the page content streams,
removes the matching text-showing operations, and sanitizes the document
so the sensitive data is gone for good:

* Text is matched after font decoding (Type1, TrueType and Type0 fonts),
  either by content (`texts`) or by page region (`regions`).
* Page content streams, nested Form XObjects and annotation appearance
  streams are all processed; Form XObjects shared by several pages are
  checked for every placement.
* Images overlapping a redaction region are removed as well (they may
  contain a rasterized copy of the sensitive content); vector paths can
  optionally be removed, too.
* Font, image and XObject resources that are no longer referenced after
  the removal are pruned, and metadata strings are scrubbed.
* After writing, the output is re-read and verified: if the sensitive
  strings can still be found anywhere, an error is raised instead of
  reporting a fake success.

```python
from pypdf import PdfReader, redact_and_sanitize

reader = PdfReader("application.pdf")
report = redact_and_sanitize(
    reader,
    "application-redacted.pdf",
    texts=["110101199003077777"],          # exact strings to remove
    regions={0: [(90, 690, 400, 720)]},    # page 0 rectangle (x0, y0, x1, y1)
)
print(report.hit_count, report.pages)
```

Regions are given in the page's *default user space* (the coordinate
system of `/MediaBox`), independent of `/Rotate` and `/CropBox`.

Optionally, black rectangles can be drawn over the redacted areas
(`draw_black_boxes=True`, the default). This is purely visual; the
removal itself does not depend on it.

```{note}
Encrypted documents, digitally signed documents, and documents that show
text with unsupported font encodings are rejected with
`pypdf.errors.RedactionNotSupportedError` **before** anything is
modified. The source document is never changed in place.
```
