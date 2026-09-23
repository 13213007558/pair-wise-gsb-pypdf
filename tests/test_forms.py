"""Test form-related functionality. Separate file to keep overview."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.errors import PyPdfError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    RectangleObject,
    TextStringObject,
)
from tests import get_data_from_url


@pytest.mark.enable_socket
def test_form_button__v_value_should_be_name_object():
    url = "https://github.com/user-attachments/files/18736500/blank-form.pdf"
    name = "issue3115.pdf"
    reader = PdfReader(BytesIO(get_data_from_url(url=url, name=name)))
    writer = PdfWriter(clone_from=reader)
    writer.update_page_form_field_values(
        writer.pages[0],
        {"Other": "/On"},
        auto_regenerate=False,
    )
    stream = BytesIO()
    writer.write(stream)

    # Wrong: `/V (/On)`.
    assert b"\n/V /On\n" in stream.getvalue()


def _build_selective_flatten_document():
    """Build a document with parent/child fields, a field reused across
    pages, a rotated widget, state-dependent button appearances, a field
    without appearance and a signature field."""
    writer = PdfWriter()
    page1 = writer.add_blank_page(612, 792)
    page2 = writer.add_blank_page(612, 792)
    page2.rotate(90)

    def make_ap(bbox, data=b"0 0 1 0 rg 0 0 10 10 re f", matrix=None):
        stream = DecodedStreamObject.initialize_from_dictionary({
            NameObject("/Type"): NameObject("/XObject"),
            NameObject("/Subtype"): NameObject("/Form"),
            NameObject("/BBox"): RectangleObject(bbox),
            "__streamdata__": ByteStringObject(data),
        })
        if matrix is not None:
            stream[NameObject("/Matrix")] = ArrayObject(
                [NumberObject(v) for v in matrix]
            )
        return writer._add_object(stream)

    def normal_ap(bbox, **kwargs):
        return DictionaryObject({NameObject("/N"): make_ap(bbox, **kwargs)})

    def make_widget(rect, ap_entry, name=None, field_type=None, mk=None):
        widget = DictionaryObject()
        widget[NameObject("/Type")] = NameObject("/Annot")
        widget[NameObject("/Subtype")] = NameObject("/Widget")
        widget[NameObject("/Rect")] = RectangleObject(rect)
        widget[NameObject("/AP")] = ap_entry
        if name is not None:
            widget[NameObject("/T")] = TextStringObject(name)
        if field_type is not None:
            widget[NameObject("/FT")] = NameObject(field_type)
        if mk is not None:
            widget[NameObject("/MK")] = mk
        return widget

    fields = []
    page1_annots = []
    page2_annots = []

    # Parent field with two child text fields on different pages.
    child1 = make_widget(
        [10, 700, 160, 720], normal_ap([0, 0, 150, 20]), name="child1", field_type="/Tx"
    )
    child1_ref = writer._add_object(child1)
    child2 = make_widget(
        [20, 700, 170, 720], normal_ap([0, 0, 150, 20]), name="child2", field_type="/Tx"
    )
    child2_ref = writer._add_object(child2)
    parent = DictionaryObject()
    parent[NameObject("/T")] = TextStringObject("parent")
    parent[NameObject("/FT")] = NameObject("/Tx")
    parent[NameObject("/Kids")] = ArrayObject([child1_ref, child2_ref])
    parent_ref = writer._add_object(parent)
    child1[NameObject("/Parent")] = parent_ref
    child2[NameObject("/Parent")] = parent_ref
    fields.append(parent_ref)
    page1_annots.append(child1_ref)
    page2_annots.append(child2_ref)

    # Text field with one widget on each page.
    shared_widget1 = make_widget([10, 600, 160, 620], normal_ap([0, 0, 150, 20]))
    shared_widget1_ref = writer._add_object(shared_widget1)
    shared_widget2 = make_widget([20, 600, 170, 620], normal_ap([0, 0, 150, 20]))
    shared_widget2_ref = writer._add_object(shared_widget2)
    shared = DictionaryObject()
    shared[NameObject("/T")] = TextStringObject("shared")
    shared[NameObject("/FT")] = NameObject("/Tx")
    shared[NameObject("/V")] = TextStringObject("shared value")
    shared[NameObject("/Kids")] = ArrayObject([shared_widget1_ref, shared_widget2_ref])
    shared_ref = writer._add_object(shared)
    shared_widget1[NameObject("/Parent")] = shared_ref
    shared_widget2[NameObject("/Parent")] = shared_ref
    fields.append(shared_ref)
    page1_annots.append(shared_widget1_ref)
    page2_annots.append(shared_widget2_ref)

    # Widget rotated through its appearance characteristics (/MK /R).
    rotated = make_widget(
        [100, 100, 200, 200],
        normal_ap([0, 0, 100, 100]),
        name="rotated",
        field_type="/Tx",
        mk=DictionaryObject({NameObject("/R"): NumberObject(90)}),
    )
    rotated_ref = writer._add_object(rotated)
    fields.append(rotated_ref)
    page1_annots.append(rotated_ref)

    # Appearance with a non-trivial /BBox and /Matrix.
    matrix = make_widget(
        [300, 400, 400, 450],
        normal_ap([10, 10, 60, 35], matrix=[2, 0, 0, 2, 5, 5]),
        name="matrix",
        field_type="/Tx",
    )
    matrix_ref = writer._add_object(matrix)
    fields.append(matrix_ref)
    page1_annots.append(matrix_ref)

    # Checkbox with one appearance stream per state.
    check = make_widget(
        [10, 500, 30, 520],
        DictionaryObject({
            NameObject("/N"): DictionaryObject({
                NameObject("/On"): make_ap([0, 0, 20, 20], data=b"1 0 0 rg 0 0 20 20 re f"),
                NameObject("/Off"): make_ap([0, 0, 20, 20], data=b"0 0 0 rg"),
            })
        }),
        name="check",
        field_type="/Btn",
    )
    check[NameObject("/AS")] = NameObject("/On")
    check[NameObject("/V")] = NameObject("/On")
    check_ref = writer._add_object(check)
    fields.append(check_ref)
    page1_annots.append(check_ref)

    # Two fields sharing the same appearance stream object.
    shared_ap = make_ap([0, 0, 100, 20], data=b"0 1 0 0 rg 0 0 5 5 re f")
    sharer_a = make_widget(
        [10, 300, 110, 320],
        DictionaryObject({NameObject("/N"): shared_ap}),
        name="sharer_a",
        field_type="/Tx",
    )
    sharer_a_ref = writer._add_object(sharer_a)
    sharer_b = make_widget(
        [10, 250, 110, 270],
        DictionaryObject({NameObject("/N"): shared_ap}),
        name="sharer_b",
        field_type="/Tx",
    )
    sharer_b_ref = writer._add_object(sharer_b)
    fields.extend([sharer_a_ref, sharer_b_ref])
    page1_annots.extend([sharer_a_ref, sharer_b_ref])

    # Text field without any appearance.
    broken = DictionaryObject()
    broken[NameObject("/Type")] = NameObject("/Annot")
    broken[NameObject("/Subtype")] = NameObject("/Widget")
    broken[NameObject("/Rect")] = RectangleObject([10, 200, 110, 220])
    broken[NameObject("/T")] = TextStringObject("broken")
    broken[NameObject("/FT")] = NameObject("/Tx")
    broken_ref = writer._add_object(broken)
    fields.append(broken_ref)
    page1_annots.append(broken_ref)

    # Signature field with a valid appearance (still not flattenable).
    sig = make_widget(
        [10, 100, 110, 120], normal_ap([0, 0, 100, 20]), name="sig", field_type="/Sig"
    )
    sig_ref = writer._add_object(sig)
    fields.append(sig_ref)
    page1_annots.append(sig_ref)

    acro_form = DictionaryObject()
    acro_form[NameObject("/Fields")] = ArrayObject(fields)
    acro_form[NameObject("/DA")] = TextStringObject("0 0 0 rg /Helv 12 Tf")
    acro_form[NameObject("/DR")] = DictionaryObject({
        NameObject("/Font"): DictionaryObject({
            NameObject("/Helv"): writer._add_object(DictionaryObject({
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            }))
        })
    })
    writer._root_object[NameObject("/AcroForm")] = writer._add_object(acro_form)
    page1[NameObject("/Annots")] = ArrayObject(page1_annots)
    page2[NameObject("/Annots")] = ArrayObject(page2_annots)
    return writer


def _rewrite(writer):
    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    return PdfReader(stream)


def test_flatten_fields__parent_child_and_cross_page():
    writer = _build_selective_flatten_document()
    writer.flatten_fields(["parent.child1", "shared"])

    # The unselected child field is still modifiable.
    writer.update_page_form_field_values(
        writer.pages[1], {"parent.child2": "updated"}, auto_regenerate=False
    )

    reader = _rewrite(writer)
    fields = reader.get_fields()
    assert "parent.child1" not in fields
    assert "shared" not in fields
    assert "parent" in fields
    assert fields["parent.child2"]["/V"] == "updated"

    # All widgets of the selected fields are gone from the pages, the
    # widgets of unselected fields are kept.
    assert len(reader.pages[0]["/Annots"]) == 7
    assert len(reader.pages[1]["/Annots"]) == 1

    # The appearances are painted at the widget rectangles.
    page1_content = reader.pages[0]["/Contents"].get_object().get_data()
    assert b"1.0000 0.0000 0.0000 1.0000 10.0000 700.0000 cm\n/Flat_parent_child1 Do" in page1_content
    assert b"1.0000 0.0000 0.0000 1.0000 10.0000 600.0000 cm\n/Flat_shared Do" in page1_content
    page2_content = reader.pages[1]["/Contents"].get_object().get_data()
    assert b"1.0000 0.0000 0.0000 1.0000 20.0000 600.0000 cm\n/Flat_shared Do" in page2_content


def test_flatten_fields__rotated_widget():
    writer = _build_selective_flatten_document()
    writer.flatten_fields("rotated")
    reader = _rewrite(writer)
    assert "rotated" not in reader.get_fields()
    content = reader.pages[0]["/Contents"].get_object().get_data()
    # 90 degrees counterclockwise around the center of the rectangle.
    assert b"0.0000 1.0000 -1.0000 0.0000 200.0000 100.0000 cm" in content


def test_flatten_fields__appearance_bbox_and_matrix():
    writer = _build_selective_flatten_document()
    writer.flatten_fields("matrix")
    reader = _rewrite(writer)
    assert "matrix" not in reader.get_fields()
    content = reader.pages[0]["/Contents"].get_object().get_data()
    # /BBox [10 10 60 35] mapped through /Matrix [2 0 0 2 5 5] gives
    # [25 25 125 75], which is then aligned with the rectangle [300 400 400 450].
    assert b"1.0000 0.0000 0.0000 1.0000 275.0000 375.0000 cm" in content


def test_flatten_fields__rotated_page():
    writer = _build_selective_flatten_document()
    assert writer.pages[1]["/Rotate"] == 90
    writer.flatten_fields("parent.child2")
    reader = _rewrite(writer)
    assert "parent.child2" not in reader.get_fields()
    assert "parent.child1" in reader.get_fields()
    content = reader.pages[1]["/Contents"].get_object().get_data()
    # The rectangle is used in default user space, so the placement is
    # correct regardless of the page rotation.
    assert b"1.0000 0.0000 0.0000 1.0000 20.0000 700.0000 cm" in content


def test_flatten_fields__button_state_appearance():
    writer = _build_selective_flatten_document()
    writer.flatten_fields("check")
    reader = _rewrite(writer)
    assert "check" not in reader.get_fields()
    xobjects = reader.pages[0]["/Resources"]["/XObject"]
    # The appearance of the selected state (/On) is used, not /Off.
    assert xobjects["/Flat_check"].get_object().get_data() == b"1 0 0 rg 0 0 20 20 re f"


def test_flatten_fields__missing_appearance_is_atomic():
    writer = _build_selective_flatten_document()
    page1 = writer.pages[0]
    annots_before = len(page1["/Annots"])
    with pytest.raises(PyPdfError, match="no valid appearance stream"):
        writer.flatten_fields(["rotated", "broken"])
    # The document is left unchanged: nothing painted, nothing removed.
    assert "/Contents" not in page1
    assert len(page1["/Annots"]) == annots_before
    fields = writer.get_fields()
    assert "rotated" in fields
    assert "broken" in fields


def test_flatten_fields__signature_field_rejected():
    writer = _build_selective_flatten_document()
    with pytest.raises(PyPdfError, match="[Ss]ignature"):
        writer.flatten_fields("sig")
    assert "sig" in writer.get_fields()


def test_flatten_fields__unknown_field():
    writer = _build_selective_flatten_document()
    with pytest.raises(PyPdfError, match="unknown field"):
        writer.flatten_fields("does_not_exist")
    with pytest.raises(PyPdfError, match="No /AcroForm"):
        PdfWriter().flatten_fields("anything")


def test_flatten_fields__empty_parent_pruned():
    writer = _build_selective_flatten_document()
    writer.flatten_fields(["parent.child1", "parent.child2"])
    reader = _rewrite(writer)
    fields = reader.get_fields()
    assert "parent" not in fields
    assert "parent.child1" not in fields
    assert "parent.child2" not in fields
    assert len(reader.pages[0]["/Annots"]) == 8
    assert len(reader.pages[1]["/Annots"]) == 1


def test_flatten_fields__shared_resources_kept():
    writer = _build_selective_flatten_document()
    writer.flatten_fields("sharer_a")
    reader = _rewrite(writer)
    fields = reader.get_fields()
    assert "sharer_a" not in fields
    # The appearance stream shared with the other field is still usable.
    sharer_b = fields["sharer_b"].indirect_reference.get_object()
    assert (
        sharer_b["/AP"]["/N"].get_object().get_data() == b"0 1 0 0 rg 0 0 5 5 re f"
    )


def test_flatten_fields__field_and_descendant_selected_together():
    writer = _build_selective_flatten_document()
    writer.flatten_fields(["parent", "parent.child1"])
    reader = _rewrite(writer)
    fields = reader.get_fields()
    assert "parent" not in fields
    assert "parent.child1" not in fields
    assert "parent.child2" not in fields
    # The shared widget is painted only once.
    content = reader.pages[0]["/Contents"].get_object().get_data()
    assert content.count(b"/Flat_parent Do") == 1
