"""Tests for the read-only AcroForm calculation plan."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf._calculation import (
    CalculationPlan,
    DependencyCycle,
    DuplicateFieldName,
    MissingDependency,
    SelfLoop,
)
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    TextStringObject,
)


def _make_widget(writer, page):
    widget = DictionaryObject()
    widget[NameObject("/Type")] = NameObject("/Annot")
    widget[NameObject("/Subtype")] = NameObject("/Widget")
    widget[NameObject("/Rect")] = ArrayObject(
        [FloatObject(0), FloatObject(0), FloatObject(50), FloatObject(20)]
    )
    widget[NameObject("/P")] = page.indirect_reference
    return writer._add_object(widget)


def _make_field(writer, name, *, value=None, script=None, parent=None, kids=()):
    field = DictionaryObject()
    field[NameObject("/FT")] = NameObject("/Tx")
    if name is not None:
        field[NameObject("/T")] = TextStringObject(name)
    if value is not None:
        field[NameObject("/V")] = TextStringObject(value)
    if parent is not None:
        field[NameObject("/Parent")] = parent
    if script is not None:
        field[NameObject("/AA")] = DictionaryObject(
            {
                NameObject("/C"): DictionaryObject(
                    {
                        NameObject("/S"): NameObject("/JavaScript"),
                        NameObject("/JS"): TextStringObject(script),
                    }
                )
            }
        )
    reference = writer._add_object(field)
    if kids:
        field[NameObject("/Kids")] = ArrayObject(list(kids))
    return reference


def _build_form_pdf(*, cyclic=True, include_co=True):
    """Build a PDF with parent/child fields, two dependency branches and,
    optionally, a dependency cycle."""
    writer = PdfWriter()
    page1 = writer.add_blank_page(width=300, height=300)
    page2 = writer.add_blank_page(width=300, height=300)

    # Parent field with two child fields; "order.qty" is rendered by
    # widgets on both pages (cross-page widgets sharing one field).
    order_ref = _make_field(writer, "order")
    qty_widgets = [_make_widget(writer, page1), _make_widget(writer, page2)]
    qty_ref = _make_field(writer, "qty", value="2", parent=order_ref, kids=qty_widgets)
    for widget_ref in qty_widgets:
        widget_ref.get_object()[NameObject("/Parent")] = qty_ref
    price_widget = _make_widget(writer, page2)
    price_ref = _make_field(
        writer, "price", value="3", parent=order_ref, kids=[price_widget]
    )
    price_widget.get_object()[NameObject("/Parent")] = price_ref
    order_ref.get_object()[NameObject("/Kids")] = ArrayObject([qty_ref, price_ref])

    # Two dependency branches: subtotal -> tax and subtotal -> shipping,
    # both joined by total.
    subtotal_ref = _make_field(
        writer,
        "subtotal",
        script=(
            "event.value = this.getField('order.qty').value"
            " * this.getField('order.price').value;"
        ),
    )
    tax_ref = _make_field(
        writer, "tax", script="event.value = this.getField('subtotal').value * 0.1;"
    )
    shipping_ref = _make_field(
        writer,
        "shipping",
        script="event.value = this.getField('subtotal').value > 100 ? 0 : 5;",
    )
    total_ref = _make_field(
        writer,
        "total",
        script=(
            "event.value = this.getField('tax').value"
            " + this.getField('shipping').value;"
        ),
    )

    # Problem fields: self-dependency and dependency on a missing field.
    selfish_ref = _make_field(
        writer, "selfish", script="event.value = this.getField('selfish').value + 1;"
    )
    ghost_ref = _make_field(
        writer, "ghost", script="event.value = this.getField('missing_field').value;"
    )

    field_refs = [
        order_ref,
        subtotal_ref,
        tax_ref,
        shipping_ref,
        total_ref,
        selfish_ref,
        ghost_ref,
    ]
    calculation_refs = [subtotal_ref, tax_ref, shipping_ref, total_ref, selfish_ref, ghost_ref]
    if cyclic:
        loop_a_ref = _make_field(
            writer, "loop_a", script="event.value = this.getField('loop_b').value;"
        )
        loop_b_ref = _make_field(
            writer, "loop_b", script="event.value = this.getField('loop_a').value;"
        )
        field_refs += [loop_a_ref, loop_b_ref]
        calculation_refs += [loop_a_ref, loop_b_ref]

    # The same qualified field name declared twice.
    field_refs.append(_make_field(writer, "dup", value="first"))
    field_refs.append(_make_field(writer, "dup", value="second"))

    acro_form = DictionaryObject()
    acro_form[NameObject("/Fields")] = ArrayObject(field_refs)
    if include_co:
        acro_form[NameObject("/CO")] = ArrayObject(calculation_refs)
    writer.root_object[NameObject("/AcroForm")] = acro_form

    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    return stream


def _read_plan(stream, **kwargs):
    return PdfReader(stream).get_calculation_plan(**kwargs)


def test_calculation_plan__structure_and_stable_order():
    plan = _read_plan(_build_form_pdf(cyclic=False))

    # Cross-page widgets share a single field node; parent/child fields
    # get qualified names; duplicates are merged.
    assert plan.fields == (
        "order",
        "order.qty",
        "order.price",
        "subtotal",
        "tax",
        "shipping",
        "total",
        "selfish",
        "ghost",
        "dup",
    )
    assert plan.calculation_order == (
        "subtotal",
        "tax",
        "shipping",
        "total",
        "selfish",
        "ghost",
    )
    assert plan.dependencies["subtotal"] == ("order.qty", "order.price")
    assert plan.dependencies["tax"] == ("subtotal",)
    assert plan.dependencies["shipping"] == ("subtotal",)
    assert plan.dependencies["total"] == ("tax", "shipping")
    assert plan.dependencies["selfish"] == ()
    assert plan.dependencies["ghost"] == ()

    # Stable topological order: /CO order first, declaration order after.
    assert plan.is_acyclic
    assert plan.order == (
        "selfish",
        "ghost",
        "order",
        "order.qty",
        "order.price",
        "subtotal",
        "tax",
        "shipping",
        "total",
        "dup",
    )


def test_calculation_plan__fallback_without_calculation_order():
    plan = _read_plan(_build_form_pdf(cyclic=False, include_co=False))
    assert plan.calculation_order == ()
    assert plan.is_acyclic
    # Without /CO the field-tree declaration order is the fallback.
    assert plan.order == (
        "order",
        "order.qty",
        "order.price",
        "subtotal",
        "tax",
        "shipping",
        "total",
        "selfish",
        "ghost",
        "dup",
    )


def test_calculation_plan__problems_are_reported_with_positions():
    plan = _read_plan(_build_form_pdf(cyclic=True))

    assert plan.duplicate_fields == (DuplicateFieldName(name="dup", positions=(11, 12)),)
    assert plan.missing_dependencies == (
        MissingDependency(field="ghost", dependency="missing_field", position=8),
    )
    assert plan.self_loops == (SelfLoop(field="selfish", position=7),)
    assert plan.cycles == (DependencyCycle(fields=("loop_a", "loop_b", "loop_a")),)

    # A cyclic graph has no total order and cannot be executed.
    assert not plan.is_acyclic
    assert plan.order is None
    with pytest.raises(ValueError, match="loop_a -> loop_b -> loop_a"):
        plan.execute()


def test_calculation_plan__no_execution_by_default():
    plan = _read_plan(_build_form_pdf(cyclic=False))

    # Building the plan and executing without an adapter runs no script:
    # values are returned as currently stored in the document.
    result = plan.execute()
    assert list(result) == list(plan.order)
    assert result["order.qty"] == "2"
    assert result["order.price"] == "3"
    assert result["subtotal"] is None
    assert result["total"] is None

    # Overriding inputs still does not trigger any recalculation.
    result = plan.execute(values={"order.qty": "10"})
    assert result["order.qty"] == "10"
    assert result["subtotal"] is None


def test_calculation_plan__execute_with_adapter_updates_successors_only():
    plan = _read_plan(_build_form_pdf(cyclic=False))
    calls = []

    def adapter(name, script, values):
        calls.append((name, script))
        if name == "subtotal":
            return float(values["order.qty"]) * float(values["order.price"])
        if name == "tax":
            return round(float(values["subtotal"]) * 0.1, 2)
        if name == "shipping":
            return 0.0 if float(values["subtotal"]) > 100 else 5.0
        if name == "total":
            return float(values["tax"]) + float(values["shipping"])
        return None

    result = plan.execute(values={"order.qty": "4"}, adapter=adapter)
    assert result["subtotal"] == 12.0
    assert result["tax"] == 1.2
    assert result["shipping"] == 5.0
    assert result["total"] == 6.2
    # Non-successors keep their values.
    assert result["order.price"] == "3"
    assert result["dup"] == "first"
    # The adapter ran in plan order, with the field scripts passed along.
    assert [name for name, _ in calls] == list(plan.order)
    assert dict(calls)["subtotal"].startswith("event.value")
    assert dict(calls)["order"] is None

    # Only successors can be affected by a value update.
    assert plan.successors("subtotal") == ("tax", "shipping")
    assert plan.downstream("subtotal") == ("tax", "shipping", "total")
    assert plan.downstream("order.qty") == ("subtotal", "tax", "shipping", "total")
    assert plan.downstream("total") == ()
    with pytest.raises(ValueError, match="Unknown field"):
        plan.successors("nope")
    with pytest.raises(ValueError, match="Unknown field"):
        plan.downstream("nope")


def test_calculation_plan__explicit_dependencies():
    stream = _build_form_pdf(cyclic=False)
    plan = _read_plan(stream, dependencies={"total": ["order.qty"]})
    assert plan.dependencies["total"] == ("order.qty", "tax", "shipping")
    assert plan.is_acyclic

    with pytest.raises(ValueError, match="unknown fields"):
        _read_plan(_build_form_pdf(cyclic=False), dependencies={"nope": ["tax"]})

    with pytest.raises(ValueError, match="unknown fields"):
        plan.execute(values={"nope": "1"})


def test_calculation_plan__parent_child_inheritance():
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    a_ref = _make_field(writer, "a", value="1")
    b_ref = _make_field(writer, "b", value="2")

    parent = DictionaryObject()
    parent[NameObject("/FT")] = NameObject("/Tx")
    parent[NameObject("/T")] = TextStringObject("p")
    parent[NameObject("/V")] = TextStringObject("inherited")
    parent[NameObject("/AA")] = DictionaryObject(
        {
            NameObject("/C"): DictionaryObject(
                {
                    NameObject("/S"): NameObject("/JavaScript"),
                    NameObject("/JS"): TextStringObject(
                        "event.value = this.getField('a').value;"
                    ),
                }
            )
        }
    )
    parent_ref = writer._add_object(parent)
    # c1 inherits /V and /AA from its parent; c2 overrides both.
    c1_ref = _make_field(writer, "c1", parent=parent_ref)
    c2_ref = _make_field(
        writer,
        "c2",
        value="own",
        script="event.value = this.getField('b').value;",
        parent=parent_ref,
    )
    parent[NameObject("/Kids")] = ArrayObject([c1_ref, c2_ref])

    acro_form = DictionaryObject()
    acro_form[NameObject("/Fields")] = ArrayObject([a_ref, b_ref, parent_ref])
    writer.root_object[NameObject("/AcroForm")] = acro_form
    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)

    plan = PdfReader(stream).get_calculation_plan()
    assert plan.fields == ("a", "b", "p", "p.c1", "p.c2")
    assert plan.scripts["p"] == "event.value = this.getField('a').value;"
    assert plan.scripts["p.c1"] == plan.scripts["p"]
    assert plan.scripts["p.c2"] == "event.value = this.getField('b').value;"
    assert plan.dependencies["p.c1"] == ("a",)
    assert plan.dependencies["p.c2"] == ("b",)
    assert plan.initial_values["p.c1"] == "inherited"
    assert plan.initial_values["p.c2"] == "own"


def test_calculation_plan__read_only():
    plan = _read_plan(_build_form_pdf(cyclic=False))
    with pytest.raises(TypeError):
        plan.dependencies["subtotal"] = ()
    with pytest.raises(AttributeError):
        plan.order = ()


def test_calculation_plan__no_acroform():
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    plan = PdfReader(stream).get_calculation_plan()
    assert isinstance(plan, CalculationPlan)
    assert plan.fields == ()
    assert plan.order == ()
    assert plan.execute() == {}


def test_calculation_plan__existing_form_interfaces_untouched():
    stream = _build_form_pdf(cyclic=True)
    reader = PdfReader(stream)
    fields = reader.get_fields()
    assert "order.qty" in fields
    assert "order.price" in fields
    assert "subtotal" in fields
    assert reader.get_form_text_fields(full_qualified_name=True)["order.qty"] == "2"
