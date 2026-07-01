"""Scenario DSL (mini-YAML) parsing and validation coverage.

Covers the happy path for every assertion key plus every fail-closed validation
branch: missing id, unknown keys, malformed integers/booleans/hex, cross-field
constraints, and structural errors.
"""
import pytest

from canzap.core import Assertion, Scenario, load_scenario, load_scenario_text


def _one(dsl: str) -> Assertion:
    sc = load_scenario_text(dsl)
    assert len(sc.assertions) == 1
    return sc.assertions[0]


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------


def test_top_level_name():
    sc = load_scenario_text("name: My Scenario\nassertions:\n  - id: 0x1A0\n")
    assert sc.name == "My Scenario"


def test_name_defaults_when_absent():
    sc = load_scenario_text("assertions:\n  - id: 0x1A0\n")
    assert sc.name == "scenario"


def test_quoted_name_is_stripped():
    sc = load_scenario_text('name: "Quoted Name"\nassertions:\n  - id: 0x1A0\n')
    assert sc.name == "Quoted Name"


def test_assertion_name_defaults_to_id_string():
    a = _one("assertions:\n  - id: 0x1A0\n")
    assert a.name == "0x1A0"


def test_all_keys_parse():
    a = _one(
        "assertions:\n"
        "  - name: everything\n"
        "    id: 0x2B1\n"
        "    present: true\n"
        "    byte: 1\n"
        "    equals: 0xFF\n"
        "    min_count: 2\n"
        "    max_count: 9\n"
        "    max_period_ms: 120\n"
        "    min_period_ms: 5\n"
        "    interface: can0\n"
    )
    assert a.name == "everything"
    assert a.can_id == 0x2B1
    assert a.present is True
    assert a.byte == 1 and a.equals == 0xFF
    assert a.min_count == 2 and a.max_count == 9
    assert a.max_period_ms == 120.0 and a.min_period_ms == 5.0
    assert a.interface == "can0"


def test_data_equals_parses_and_ignores_spaces():
    a = _one("assertions:\n  - id: 0x1\n    data_equals: DE AD BE EF\n")
    assert a.data_equals == bytes.fromhex("DEADBEEF")


@pytest.mark.parametrize("token,expected", [
    ("true", True), ("True", True), ("yes", True), ("on", True), ("1", True),
    ("false", False), ("no", False), ("off", False), ("0", False),
])
def test_boolean_tokens(token, expected):
    a = _one(f"assertions:\n  - id: 0x1\n    present: {token}\n")
    assert a.present is expected


@pytest.mark.parametrize("token,value", [
    ("0x1A0", 0x1A0), ("416", 416), ("0b101", 0b101), ("0X1a0", 0x1A0),
])
def test_integer_radix_forms(token, value):
    a = _one(f"assertions:\n  - id: {token}\n")
    assert a.can_id == value


def test_comments_and_blank_lines_ignored():
    a = _one(
        "# a comment\n"
        "assertions:\n"
        "\n"
        "  - id: 0x1A0   # inline comment\n"
        "    present: true\n"
    )
    assert a.can_id == 0x1A0 and a.present is True


def test_multiple_assertions_in_order():
    sc = load_scenario_text(
        "assertions:\n  - id: 0x1\n  - id: 0x2\n  - id: 0x3\n"
    )
    assert [a.can_id for a in sc.assertions] == [1, 2, 3]


def test_dash_key_on_same_line_as_first_field():
    # `- name: x` followed by indented keys is the common form
    sc = load_scenario_text(
        "assertions:\n  - name: first\n    id: 0x1\n  - name: second\n    id: 0x2\n"
    )
    assert [a.name for a in sc.assertions] == ["first", "second"]


def test_empty_assertions_block_is_valid():
    sc = load_scenario_text("name: empty\nassertions:\n")
    assert sc.assertions == []


# --------------------------------------------------------------------------
# validation / error paths
# --------------------------------------------------------------------------


def test_missing_id_rejected():
    with pytest.raises(ValueError, match="missing required 'id'"):
        load_scenario_text("assertions:\n  - name: x\n    present: true\n")


def test_unknown_key_rejected():
    with pytest.raises(ValueError, match="unknown key"):
        load_scenario_text("assertions:\n  - id: 0x1\n    prezent: true\n")


def test_non_integer_id_rejected():
    with pytest.raises(ValueError, match="'id'.*expected an integer"):
        load_scenario_text("assertions:\n  - id: notanumber\n")


def test_non_integer_min_count_rejected():
    with pytest.raises(ValueError, match="'min_count'.*expected an integer"):
        load_scenario_text("assertions:\n  - id: 0x1\n    min_count: lots\n")


def test_bad_boolean_rejected():
    with pytest.raises(ValueError, match="'present'.*expected a boolean"):
        load_scenario_text("assertions:\n  - id: 0x1\n    present: maybe\n")


def test_bad_data_equals_hex_rejected():
    with pytest.raises(ValueError, match="data_equals.*not valid hex"):
        load_scenario_text("assertions:\n  - id: 0x1\n    data_equals: XYZZ\n")


def test_bad_max_period_rejected():
    with pytest.raises(ValueError, match="max_period_ms.*must be a number"):
        load_scenario_text("assertions:\n  - id: 0x1\n    max_period_ms: soon\n")


def test_byte_without_equals_rejected():
    with pytest.raises(ValueError, match="'byte' and 'equals' must be used together"):
        load_scenario_text("assertions:\n  - id: 0x1\n    byte: 0\n")


def test_equals_without_byte_rejected():
    with pytest.raises(ValueError, match="'byte' and 'equals' must be used together"):
        load_scenario_text("assertions:\n  - id: 0x1\n    equals: 0xFF\n")


def test_negative_byte_rejected():
    with pytest.raises(ValueError, match="'byte' index must be >= 0"):
        load_scenario_text("assertions:\n  - id: 0x1\n    byte: -1\n    equals: 0x00\n")


def test_equals_out_of_byte_range_rejected():
    with pytest.raises(ValueError, match="'equals' must be a byte value"):
        load_scenario_text("assertions:\n  - id: 0x1\n    byte: 0\n    equals: 256\n")


def test_min_greater_than_max_count_rejected():
    with pytest.raises(ValueError, match="min_count.*>.*max_count"):
        load_scenario_text("assertions:\n  - id: 0x1\n    min_count: 5\n    max_count: 2\n")


def test_missing_assertions_block_rejected():
    with pytest.raises(ValueError, match="no 'assertions:' block"):
        load_scenario_text("name: lonely\n")


def test_unexpected_top_level_line_rejected():
    with pytest.raises(ValueError, match="unexpected top-level line"):
        load_scenario_text("name: t\ngarbage line here\nassertions:\n  - id: 0x1\n")


def test_key_outside_list_item_rejected():
    with pytest.raises(ValueError, match="outside a '- ' list item"):
        load_scenario_text("assertions:\n    id: 0x1\n")


def test_missing_colon_in_assertion_rejected():
    with pytest.raises(ValueError, match="expected 'key: value'"):
        load_scenario_text("assertions:\n  - id: 0x1\n    presenttrue\n")


def test_error_reports_assertion_start_line():
    # the second assertion (starting at line 4) has the unknown key
    dsl = (
        "assertions:\n"
        "  - id: 0x1\n"
        "    present: true\n"
        "  - id: 0x2\n"
        "    bogus: 1\n"
    )
    with pytest.raises(ValueError, match=r"near line 4"):
        load_scenario_text(dsl)


# --------------------------------------------------------------------------
# load_scenario (file) + Scenario dataclass
# --------------------------------------------------------------------------


def test_load_scenario_from_file(tmp_path):
    p = tmp_path / "s.canzap"
    p.write_text("name: fromfile\nassertions:\n  - id: 0x1A0\n    present: true\n")
    sc = load_scenario(str(p))
    assert sc.name == "fromfile" and sc.assertions[0].can_id == 0x1A0


def test_load_scenario_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_scenario("/no/such/scenario.canzap")


def test_scenario_dataclass_defaults():
    sc = Scenario(name="x")
    assert sc.assertions == []
