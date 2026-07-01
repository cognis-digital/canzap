"""Edge-case and error-path coverage for candump parsing.

Covers the standard log format, the plain console format, RTR frames, extended
vs. standard ID classification (including the zero-padded standard-ID case), and
every malformed-input branch of the parser.
"""
import pytest

from canzap.core import CanFrame, parse_candump, parse_candump_text


# --------------------------------------------------------------------------
# well-formed parses
# --------------------------------------------------------------------------


def test_timestamped_standard_frame():
    f = parse_candump("(1623241200.123456) can0 1A0#00FF12345678")
    assert f.timestamp == pytest.approx(1623241200.123456)
    assert f.interface == "can0"
    assert f.can_id == 0x1A0
    assert f.data == bytes.fromhex("00FF12345678")
    assert f.dlc == 6
    assert f.extended is False
    assert f.rtr is False


def test_console_format_without_timestamp():
    f = parse_candump("can0 200#01020304")
    assert f.timestamp == 0.0
    assert f.can_id == 0x200
    assert f.dlc == 4


def test_integer_timestamp_no_fraction():
    f = parse_candump("(1700000000) vcan0 100#00")
    assert f.timestamp == 1700000000.0
    assert f.interface == "vcan0"


def test_empty_data_field_is_zero_dlc():
    f = parse_candump("can0 7FF#")
    assert f.dlc == 0
    assert f.data == b""


def test_interface_name_variants():
    for iface in ("can0", "vcan1", "slcan-0", "can_fd0"):
        f = parse_candump(f"{iface} 100#00")
        assert f.interface == iface


def test_lowercase_and_uppercase_hex_equivalent():
    lo = parse_candump("can0 1a0#deadbeef")
    hi = parse_candump("can0 1A0#DEADBEEF")
    assert lo.can_id == hi.can_id == 0x1A0
    assert lo.data == hi.data


def test_full_64_byte_canfd_payload_ok():
    payload = "AB" * 64
    f = parse_candump(f"can0 100#{payload}")
    assert f.dlc == 64


# --------------------------------------------------------------------------
# extended / standard ID classification
# --------------------------------------------------------------------------


def test_value_above_std_range_is_extended():
    assert parse_candump("can0 800#00").extended is True
    assert parse_candump("can0 7FF#00").extended is False


def test_zero_padded_standard_id_stays_standard():
    # regression: "0700" is 0x700 (< 0x7FF) and must NOT be flagged extended
    f = parse_candump("can0 0700#DEADBEEF")
    assert f.can_id == 0x700
    assert f.extended is False


def test_j1939_29bit_ids_are_extended():
    for hid in ("18FEF100", "0CF00400", "1FFFFFFF"):
        f = parse_candump(f"can0 {hid}#00")
        assert f.extended is True
        assert f.can_id == int(hid, 16)


def test_id_above_29bit_max_rejected():
    with pytest.raises(ValueError, match="29-bit maximum"):
        parse_candump("can0 20000000#00")


# --------------------------------------------------------------------------
# RTR frames
# --------------------------------------------------------------------------


def test_rtr_frame_parses_with_no_data():
    f = parse_candump("(1.0) can0 123#R")
    assert f.rtr is True
    assert f.dlc == 0
    assert f.data == b""


def test_rtr_frame_extended_id():
    f = parse_candump("can0 18FF0000#R")
    assert f.rtr is True and f.extended is True


def test_rtr_frame_with_data_is_rejected():
    with pytest.raises(ValueError, match="RTR frame must not carry data"):
        parse_candump("can0 123#R00FF")


def test_rtr_flag_in_to_dict():
    assert parse_candump("can0 123#R").to_dict()["rtr"] is True
    assert parse_candump("can0 123#00").to_dict()["rtr"] is False


# --------------------------------------------------------------------------
# blank / comment lines
# --------------------------------------------------------------------------


@pytest.mark.parametrize("line", ["", "   ", "\t", "# comment", "   # indented comment"])
def test_blank_and_comment_lines_return_none(line):
    assert parse_candump(line) is None


# --------------------------------------------------------------------------
# malformed input error paths
# --------------------------------------------------------------------------


def test_non_hex_char_in_data_is_unparseable():
    # a non-hex char makes the whole line fail the frame grammar (the data field
    # only accepts hex), so it is reported as unparseable rather than bad-hex
    with pytest.raises(ValueError, match="unparseable"):
        parse_candump("can0 1A0#0BZ8")


def test_odd_length_data():
    with pytest.raises(ValueError, match="odd-length"):
        parse_candump("can0 1A0#0BB")


def test_missing_hash_separator():
    with pytest.raises(ValueError, match="unparseable"):
        parse_candump("can0 1A0 0BB8")


def test_garbage_line():
    with pytest.raises(ValueError, match="unparseable"):
        parse_candump("this is not a can frame")


def test_missing_interface():
    with pytest.raises(ValueError, match="unparseable"):
        parse_candump("1A0#0BB8")


def test_payload_over_64_bytes_rejected():
    with pytest.raises(ValueError, match="exceeds 64 bytes"):
        parse_candump("can0 100#" + "AB" * 65)


# --------------------------------------------------------------------------
# whole-log parsing
# --------------------------------------------------------------------------


def test_parse_text_skips_blanks_and_comments():
    text = "\n".join([
        "# header comment",
        "",
        "(1.0) can0 1A0#0BB8",
        "   ",
        "(1.1) can0 2B1#00",
        "# trailing",
    ])
    frames = parse_candump_text(text)
    assert len(frames) == 2
    assert [f.can_id for f in frames] == [0x1A0, 0x2B1]


def test_parse_text_reports_offending_line_number():
    text = "(1.0) can0 1A0#0BB8\n(1.1) can0 2B1#0BZ8\n"
    with pytest.raises(ValueError, match=r"line 2:"):
        parse_candump_text(text)


def test_parse_text_line_number_accounts_for_blanks():
    text = "\n\n\n(1.0) can0 1A0#ZZ\n"
    with pytest.raises(ValueError, match=r"line 4:"):
        parse_candump_text(text)


def test_parse_empty_text_yields_no_frames():
    assert parse_candump_text("") == []
    assert parse_candump_text("\n\n# just a comment\n") == []


def test_parse_text_preserves_order_and_timestamps():
    text = "(3.0) can0 100#00\n(1.0) can0 100#00\n(2.0) can0 100#00"
    ts = [f.timestamp for f in parse_candump_text(text)]
    assert ts == [3.0, 1.0, 2.0]  # parser does not reorder


# --------------------------------------------------------------------------
# CanFrame API
# --------------------------------------------------------------------------


def test_canframe_to_dict_shape():
    d = parse_candump("(1.5) can0 1A0#DEAD").to_dict()
    assert d == {
        "timestamp": 1.5,
        "interface": "can0",
        "id": 0x1A0,
        "id_hex": "0x1A0",
        "dlc": 2,
        "data": "DEAD",
        "extended": False,
        "rtr": False,
    }


def test_canframe_dlc_matches_data_length():
    f = CanFrame(timestamp=0.0, interface="can0", can_id=0x1, data=bytes(8))
    assert f.dlc == 8
