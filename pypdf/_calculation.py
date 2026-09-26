"""Read-only calculation plans for AcroForm fields.

This module builds a directed dependency graph for the calculation scripts
of an interactive form (AcroForm). The graph is derived from

* the AcroForm ``/CO`` (calculation order) array,
* the (fully qualified) field names of the field tree, and
* calculation dependency declarations, either extracted from the
  ``/AA`` ``/C`` (calculate) JavaScript actions of the fields or supplied
  explicitly by the caller.

The resulting :class:`CalculationPlan` is read-only: building it never
executes any script. Scripts may only be run through the optional
:meth:`CalculationPlan.execute` entry point, which delegates execution to
a caller-supplied JavaScript/callback adapter.
"""

import heapq
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, Optional

from ._utils import logger_warning
from .constants import FieldDictionaryAttributes as FA
from .constants import InteractiveFormDictEntries as AF
from .generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    EncodedStreamObject,
    IndirectObject,
)

if TYPE_CHECKING:
    from ._doc_common import PdfDocCommon

__all__ = [
    "CalculationPlan",
    "DependencyCycle",
    "DuplicateFieldName",
    "MissingDependency",
    "SelfLoop",
]

_INHERITABLE_ATTRIBUTES = (FA.FT, FA.V, FA.DV, FA.Ff, FA.AA)

_GET_FIELD_RE = re.compile(r"""getField\(\s*(['"])(?P<name>.*?)\1""")


@dataclass(frozen=True)
class DuplicateFieldName:
    """A fully qualified field name declared by more than one field dictionary."""

    name: str
    """The duplicated fully qualified field name."""
    positions: tuple[int, ...]
    """Declaration indexes (0-based, field-tree traversal order) of all occurrences."""


@dataclass(frozen=True)
class MissingDependency:
    """A calculation dependency referring to a field that does not exist."""

    field: str
    """The fully qualified name of the field declaring the dependency."""
    dependency: str
    """The referenced field name that could not be resolved."""
    position: int
    """Declaration index (0-based, field-tree traversal order) of *field*."""


@dataclass(frozen=True)
class SelfLoop:
    """A field whose calculation depends on itself."""

    field: str
    """The fully qualified name of the self-referencing field."""
    position: int
    """Declaration index (0-based, field-tree traversal order) of the field."""


@dataclass(frozen=True)
class DependencyCycle:
    """Evidence of a cycle in the calculation dependency graph."""

    fields: tuple[str, ...]
    """Field names forming the cycle; the first name is repeated at the end."""


# Adapter invoked by CalculationPlan.execute for each field, in plan order.
# It receives the fully qualified field name, the calculate script of the
# field (None when the field has no calculate action) and the current
# field-value mapping. Returning a value other than None stores it as the
# new value of the field; returning None leaves the value unchanged.
CalculationAdapter = Callable[[str, Optional[str], dict[str, Any]], Any]

def _deref(obj: Any) -> Any:
    if isinstance(obj, IndirectObject):
        return obj.get_object()
    return obj


def _qualified_name(obj: DictionaryObject) -> str:
    """Return the fully qualified name of a field, following /Parent.

    A /TM (mapping name) short-circuits the name, matching the key used
    by :meth:`PdfReader.get_fields`.
    """
    parts: list[str] = []
    guard: set[int] = set()
    current: Any = obj
    while isinstance(current, DictionaryObject):
        if id(current) in guard:
            break
        guard.add(id(current))
        mapping_name = current.get(FA.TM)
        if mapping_name is not None:
            return str(mapping_name)
        partial = current.get(FA.T)
        if partial is not None:
            parts.append(str(partial))
        current = _deref(current.get(FA.Parent))
    return ".".join(reversed(parts))


def _calculation_script(inherited: Mapping[str, Any]) -> Optional[str]:
    """Return the calculate (/AA /C) JavaScript inherited by a field."""
    additional_actions = _deref(inherited.get(FA.AA))
    if not isinstance(additional_actions, DictionaryObject):
        return None
    calculate_action = _deref(additional_actions.get("/C"))
    if not isinstance(calculate_action, DictionaryObject):
        return None
    if calculate_action.get("/S") != "/JavaScript":
        return None
    java_script = _deref(calculate_action.get("/JS"))
    if java_script is None:
        return None
    if isinstance(java_script, (EncodedStreamObject, DecodedStreamObject)):
        data = java_script.get_data()
        return data.decode("utf-8", "replace") if data else ""
    return str(java_script)


def _plain_value(value: Any) -> Any:
    """Convert an inherited /V value to plain Python values."""
    value = _deref(value)
    if value is None:
        return None
    if isinstance(value, (EncodedStreamObject, DecodedStreamObject)):
        data = value.get_data()
        return data.decode("utf-8", "replace") if data else ""
    if isinstance(value, ArrayObject):
        return [_plain_value(item) for item in value]
    return str(value)


@dataclass
class _FieldDeclaration:
    name: str
    position: int
    value: Any
    script: Optional[str]


def _collect_fields(acro_form: DictionaryObject) -> list[_FieldDeclaration]:
    """Walk the /Fields tree, honoring parent/child names and inheritance.

    Widget kids (dictionaries without /T or /TM) share the qualified name
    of their field and do not produce new declarations; a single field with
    widgets on several pages is therefore one node. Inheritable attributes
    (/FT, /V, /DV, /Ff, /AA) are inherited by descendants until overridden.
    """
    declarations: list[_FieldDeclaration] = []
    fields = _deref(acro_form.get(AF.Fields))
    if not isinstance(fields, ArrayObject):
        return declarations

    def walk(
        node: Any, prefix: str, inherited: dict[str, Any], guard: set[int]
    ) -> None:
        obj = _deref(node)
        if not isinstance(obj, DictionaryObject) or id(obj) in guard:
            return
        guard.add(id(obj))
        current_inherited = dict(inherited)
        for attribute in _INHERITABLE_ATTRIBUTES:
            if attribute in obj:
                current_inherited[attribute] = obj[attribute]
        qualified = prefix
        mapping_name = obj.get(FA.TM)
        partial = obj.get(FA.T)
        if mapping_name is not None:
            qualified = str(mapping_name)
        elif partial is not None:
            qualified = f"{prefix}.{partial}" if prefix else str(partial)
        if mapping_name is not None or partial is not None:
            declarations.append(
                _FieldDeclaration(
                    name=qualified,
                    position=len(declarations),
                    value=_plain_value(current_inherited.get(FA.V)),
                    script=_calculation_script(current_inherited),
                )
            )
        kids = _deref(obj.get(FA.Kids))
        if isinstance(kids, ArrayObject):
            for kid in kids:
                walk(kid, qualified, current_inherited, guard)

    for field in fields:
        walk(field, "", {}, set())
    return declarations


def _calculation_order_names(acro_form: DictionaryObject) -> list[str]:
    """Resolve the AcroForm /CO array to qualified field names."""
    calculation_order = _deref(acro_form.get(AF.CO))
    names: list[str] = []
    if not isinstance(calculation_order, ArrayObject):
        return names
    for entry in calculation_order:
        obj = _deref(entry)
        if not isinstance(obj, DictionaryObject):
            logger_warning(
"Ignoring non-dictionary entry in AcroForm /CO: %(entry)s",
                source=__name__,
                entry=obj,
            )
            continue
        name = _qualified_name(obj)
        if name:
            names.append(name)
    return names


def _script_dependencies(script: str) -> list[str]:
    """Extract getField("...") references from a calculate script."""
    return [match.group("name") for match in _GET_FIELD_RE.finditer(script)]


def _find_cycle(
    start: str,
    successors: Mapping[str, list[str]],
    remaining: set[str],
) -> Optional[list[str]]:
    """Return one closed loop reachable from *start* within *remaining*."""
    stack: list[tuple[str, int]] = [(start, 0)]
    path = [start]
    on_path = {start}
    while stack:
        node, edge_index = stack[-1]
        options = successors[node]
        if edge_index < len(options):
            stack[-1] = (node, edge_index + 1)
            nxt = options[edge_index]
            if nxt not in remaining:
                continue
            if nxt in on_path:
                cut = path.index(nxt)
                return path[cut:] + [nxt]
            on_path.add(nxt)
            path.append(nxt)
            stack.append((nxt, 0))
        else:
            stack.pop()
            on_path.discard(path.pop())
    return None
    return None


class CalculationPlan:
    """Read-only calculation plan for the fields of an AcroForm.

    The plan orders the form fields so that every field is calculated
    after the fields it depends on. It is built from the AcroForm ``/CO``
    array, the qualified field names and the calculation dependency
    declarations; it never executes any script by itself.

    Use :meth:`from_pdf` (or :meth:`PdfReader.get_calculation_plan`) to
    build a plan, and :meth:`execute` to optionally run the calculations
    through a caller-supplied JavaScript/callback adapter.
    """

    def __init__(
        self,
        *,
        fields: tuple[str, ...],
        positions: Mapping[str, int],
        calculation_order: tuple[str, ...],
        dependencies: Mapping[str, tuple[str, ...]],
        scripts: Mapping[str, str],
        initial_values: Mapping[str, Any],
        successors: Mapping[str, tuple[str, ...]],
        base_keys: Mapping[str, int],
        order: Optional[tuple[str, ...]],
        duplicate_fields: tuple[DuplicateFieldName, ...],
        missing_dependencies: tuple[MissingDependency, ...],
        self_loops: tuple[SelfLoop, ...],
        cycles: tuple[DependencyCycle, ...],
    ) -> None:
        self._fields = fields
        self._positions = positions
        self._calculation_order = calculation_order
        self._dependencies = MappingProxyType(dict(dependencies))
        self._scripts = MappingProxyType(dict(scripts))
        self._initial_values = MappingProxyType(dict(initial_values))
        self._successors = MappingProxyType(dict(successors))
        self._base_keys = MappingProxyType(dict(base_keys))
        self._order = order
        self._duplicate_fields = duplicate_fields
        self._missing_dependencies = missing_dependencies
        self._self_loops = self_loops
        self._cycles = cycles

    @classmethod
    def from_pdf(
        cls,
        pdf: "PdfDocCommon",
        dependencies: Optional[Mapping[str, Iterable[str]]] = None,
    ) -> "CalculationPlan":
        """Build a calculation plan for the AcroForm of *pdf*.

        Args:
            pdf: A :class:`PdfReader<pypdf.PdfReader>` or
                :class:`PdfWriter<pypdf.PdfWriter>` (or any object exposing
                the AcroForm through ``root_object``).
            dependencies: Optional mapping of fully qualified field names
                to the field names their calculation depends on. These
                declarations are merged with the dependencies extracted
                from the calculate (``/AA`` ``/C``) JavaScript actions.
                Declaring dependencies for a field that does not exist
                raises a ``ValueError``.

        Returns:
            A read-only :class:`CalculationPlan`. No script is executed.
        """
        from .constants import CatalogAttributes as CA

        acro_form = _deref(pdf.root_object.get(CA.ACRO_FORM))
        if not isinstance(acro_form, DictionaryObject):
            return cls(
                fields=(),
                positions={},
                calculation_order=(),
                dependencies={},
                scripts={},
                initial_values={},
                successors={},
                base_keys={},
                order=(),
                duplicate_fields=(),
                missing_dependencies=(),
                self_loops=(),
                cycles=(),
            )

        declarations = _collect_fields(acro_form)
        calculation_order = _calculation_order_names(acro_form)

        # Merge declarations: the first declaration of a qualified name
        # wins; later ones are reported as duplicates (PDF viewers share
        # the value of identically named fields).
        positions: dict[str, int] = {}
        values: dict[str, Any] = {}
        scripts: dict[str, str] = {}
        duplicate_positions: dict[str, list[int]] = {}
        for declaration in declarations:
            if declaration.name in positions:
                duplicate_positions.setdefault(
                    declaration.name, [positions[declaration.name]]
                ).append(declaration.position)
                continue
            positions[declaration.name] = declaration.position
            values[declaration.name] = declaration.value
            if declaration.script is not None:
                scripts[declaration.name] = declaration.script
        duplicate_fields = tuple(
            DuplicateFieldName(name=name, positions=tuple(pos))
            for name, pos in duplicate_positions.items()
        )

        explicit: dict[str, list[str]] = {}
        if dependencies:
            unknown = sorted(set(dependencies) - set(positions))
            if unknown:
                raise ValueError(
                    "Dependencies declared for unknown fields: "
                    + ", ".join(unknown)
                )
            explicit = {name: list(deps) for name, deps in dependencies.items()}

        # Directed graph: edge dependency -> field.
        edges: dict[str, list[str]] = {name: [] for name in positions}
        missing: list[MissingDependency] = []
        loops: list[SelfLoop] = []
        seen_missing: set[tuple[str, str]] = set()
        seen_loops: set[str] = set()
        for name in positions:
            declared = list(explicit.get(name, []))
            script = scripts.get(name)
            if script is not None:
                declared += [
                    dep
                    for dep in _script_dependencies(script)
                    if dep not in declared
                ]
            for dependency in declared:
                if dependency == name:
                    if name not in seen_loops:
                        seen_loops.add(name)
                        loops.append(SelfLoop(field=name, position=positions[name]))
                    continue
                if dependency not in positions:
                    key = (name, dependency)
                    if key not in seen_missing:
                        seen_missing.add(key)
                        missing.append(
                            MissingDependency(
                                field=name,
                                dependency=dependency,
                                position=positions[name],
                            )
                        )
                    continue
                if dependency not in edges[name]:
                    edges[name].append(dependency)

        # Base order for a stable topological sort: /CO positions first,
        # then the field-tree declaration order (fallback when /CO is
        # missing or incomplete).
        calculation_index: dict[str, int] = {}
        for index, name in enumerate(calculation_order):
            if name in positions and name not in calculation_index:
                calculation_index[name] = index
            elif name not in positions:
                logger_warning(
                    "AcroForm /CO references unknown field %(name)s",
                    source=__name__,
                    name=name,
                )
        base_keys = {
            name: calculation_index.get(name, len(calculation_order) + position)
            for name, position in positions.items()
        }

        successors: dict[str, list[str]] = {name: [] for name in positions}
        in_degree = {name: len(deps) for name, deps in edges.items()}
        for name, deps in edges.items():
            for dependency in deps:
                successors[dependency].append(name)

        heap = [
            (base_keys[name], name)
            for name in positions
            if in_degree[name] == 0
        ]
        heapq.heapify(heap)
        ordered: list[str] = []
        while heap:
            _, name = heapq.heappop(heap)
            ordered.append(name)
            for follower in successors[name]:
                in_degree[follower] -= 1
                if in_degree[follower] == 0:
                    heapq.heappush(heap, (base_keys[follower], follower))

        cycles: list[DependencyCycle] = []
        remaining = {name for name in positions if in_degree[name] > 0}
        accounted: set[str] = set()
        for start in sorted(remaining, key=base_keys.__getitem__):
            if start in accounted:
                continue
            loop = _find_cycle(start, successors, remaining)
            if loop is not None:
                cycles.append(DependencyCycle(fields=tuple(loop)))
                accounted.update(loop)

        return cls(
            fields=tuple(positions),
            positions=positions,
            calculation_order=tuple(calculation_order),
            dependencies={name: tuple(deps) for name, deps in edges.items()},
            scripts=scripts,
            initial_values=values,
            successors={name: tuple(s) for name, s in successors.items()},
            base_keys=base_keys,
            order=None if cycles else tuple(ordered),
            duplicate_fields=duplicate_fields,
            missing_dependencies=tuple(missing),
            self_loops=tuple(loops),
            cycles=tuple(cycles),
        )

    @property
    def fields(self) -> tuple[str, ...]:
        """Fully qualified field names, in field-tree declaration order."""
        return self._fields

    @property
    def calculation_order(self) -> tuple[str, ...]:
        """Field names listed in the AcroForm /CO array (may be empty)."""
        return self._calculation_order

    @property
    def dependencies(self) -> Mapping[str, tuple[str, ...]]:
        """Resolved calculation dependencies of each field."""
        return self._dependencies

    @property
    def scripts(self) -> Mapping[str, str]:
        """Calculate (/AA /C) JavaScript of each field, if any."""
        return self._scripts

    @property
    def initial_values(self) -> Mapping[str, Any]:
        """Current (inherited) /V values of the fields."""
        return self._initial_values

    @property
    def duplicate_fields(self) -> tuple[DuplicateFieldName, ...]:
        """Field names declared more than once, with their positions."""
        return self._duplicate_fields

    @property
    def missing_dependencies(self) -> tuple[MissingDependency, ...]:
        """Dependencies referencing fields that do not exist."""
        return self._missing_dependencies

    @property
    def self_loops(self) -> tuple[SelfLoop, ...]:
        """Fields whose calculation depends on itself."""
        return self._self_loops

    @property
    def cycles(self) -> tuple[DependencyCycle, ...]:
        """Evidence of dependency cycles; empty when the graph is acyclic."""
        return self._cycles

    @property
    def is_acyclic(self) -> bool:
        """Whether the dependency graph is free of cycles."""
        return not self._cycles

    @property
    def order(self) -> Optional[tuple[str, ...]]:
        """Stable topological calculation order, or None if cyclic.

        Fields listed in the AcroForm ``/CO`` array keep their relative
        order; all other fields follow in field-tree declaration order.
        """
        return self._order

    def successors(self, field: str) -> tuple[str, ...]:
        """Return the fields whose calculation directly depends on *field*."""
        try:
            return self._successors[field]
        except KeyError:
            raise ValueError(f"Unknown field: {field!r}") from None

    def downstream(self, field: str) -> tuple[str, ...]:
        """Return all fields affected by *field*, in calculation order.

        Updating the value of *field* can only influence these fields.
        """
        if field not in self._successors:
            raise ValueError(f"Unknown field: {field!r}")
        seen = {field}
        result: list[str] = []
        stack = list(self._successors[field])
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            result.append(name)
            stack.extend(self._successors[name])
        result.sort(key=self._base_keys.__getitem__)
        return tuple(result)

    def execute(
        self,
        values: Optional[Mapping[str, Any]] = None,
        adapter: Optional[CalculationAdapter] = None,
    ) -> dict[str, Any]:
        """Run the calculation plan and return the resulting field values.

        Fields are processed in calculation order, so a value update only
        affects the fields calculated after it (its successors).

        Args:
            values: Optional field values overriding the current ``/V``
                values before the plan is run.
            adapter: Optional JavaScript/callback adapter invoked for each
                field as ``adapter(name, script, values)``. ``script`` is
                the calculate JavaScript of the field (``None`` when the
                field has no calculate action). A return value other than
                ``None`` becomes the new value of the field. When no
                adapter is given, no script is executed and the current
                values are returned unchanged.

        Returns:
            A mapping of field names to values, in calculation order.

        Raises:
            ValueError: If the dependency graph contains a cycle; the
                cycle evidence is included in the message and nothing is
                executed.
        """
        if self._cycles:
            evidence = "; ".join(
                " -> ".join(cycle.fields) for cycle in self._cycles
            )
            raise ValueError(
                "Cannot execute a cyclic calculation plan: " + evidence
            )
        assert self._order is not None
        working = dict(self._initial_values)
        if values:
            unknown = sorted(set(values) - set(self._fields))
            if unknown:
                raise ValueError(
                    "Values supplied for unknown fields: " + ", ".join(unknown)
                )
            working.update(values)
        if adapter is not None:
            for name in self._order:
                new_value = adapter(name, self._scripts.get(name), working)
                if new_value is not None:
                    working[name] = new_value
        return {name: working.get(name) for name in self._order}

    def __repr__(self) -> str:
        return (
            f"CalculationPlan(fields={len(self._fields)}, "
            f"order={self._order!r}, cycles={self._cycles!r})"
        )
