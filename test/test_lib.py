#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

from . import HidProbeArgs, PrivateTestData

import binascii
import logging
import struct
import pytest

from dataclasses import dataclass

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("source", ["0010-FR-TEC__Raptor-Mach-2"])
class TestFrTecRaptorMach2:
    def test_probe(self, bpf):
        probe_args = HidProbeArgs(rdesc_size=232)
        probe_args.rdesc[177] = 0xEF
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

        probe_args.rdesc[177] = 0x12  # random value
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

    def test_rdesc(self, bpf):
        rdesc = bytes(4096)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data[177] == 0x07


@pytest.mark.parametrize("source", ["0010-mouse_invert_y"])
class TestUserhacksInvertY:
    def test_probe(self, bpf):
        probe_args = HidProbeArgs()
        probe_args.rdesc_size = 123
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

        probe_args.rdesc_size = 71
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

    @pytest.mark.parametrize("y", [1, -1, 10, -256])
    def test_event(self, bpf, y):
        # this device has reports of size 9
        values = (0, 0, 0, y, 0, 0, 0, 0, 0)
        report = struct.pack("<3bh5b", *values)

        values = bpf.hid_bpf_device_event(report=report)
        values = struct.unpack("<3bh5b", values)
        y_out = values[3]
        assert y_out == -y


@pytest.mark.parametrize("source", ["0010-Rapoo__M50-Plus-Silent"])
class TestRapooM50Plus:
    def test_rdesc_fixup(self, bpf):
        rdesc = bytearray(4096)
        rdesc[17] = 0x03

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        rdesc[17] = 0x05
        assert data == rdesc


@pytest.mark.parametrize("source", ["0010-XPPen__DecoMini4"])
class TestXPPenDecoMini4:
    @pytest.mark.parametrize(
        "report,expected",
        [
            # Invalid report descriptor
            ("02 01 02 03 04 05 06 07", "02 01 02 03 04 05 06 07"),
            # Button 1
            ("06 00 05 00 00 00 00 00", "06 01 00 00 00 00 00 00"),
            # Button 2
            ("06 00 08 00 00 00 00 00", "06 02 00 00 00 00 00 00"),
            # Button 3
            ("06 04 00 00 00 00 00 00", "06 04 00 00 00 00 00 00"),
            # Button 4
            ("06 00 2c 00 00 00 00 00", "06 08 00 00 00 00 00 00"),
            # Button 5
            ("06 01 16 00 00 00 00 00", "06 10 00 00 00 00 00 00"),
            # Button 6
            ("06 01 1d 00 00 00 00 00", "06 20 00 00 00 00 00 00"),
            # Buttons 3 and 5
            ("06 05 16 00 00 00 00 00", "06 14 00 00 00 00 00 00"),
            # All buttons
            ("06 05 05 08 2c 16 1d 00", "06 3f 00 00 00 00 00 00"),
        ],
    )
    def test_button_events(self, bpf, report, expected):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected


@pytest.mark.parametrize("source", ["0010-TUXEDO__Sirius-16-Gen1-and-Gen2"])
class TestTUXEDOSirius16Gen1andGen2:
    @pytest.mark.parametrize(
        "report,expected",
        [
            pytest.param(
                "01 00 00 68 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                id="single-f13-key-press",
            ),
            pytest.param(
                "01 00 00 04 05 06 07 08 09 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "01 00 00 04 05 06 07 08 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                id="six-keys-and-then-f13-key-down",
            ),
            pytest.param(
                "01 00 00 68 68 68 68 68 68 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
                "01 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff ff ff ff ff ff fe ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
                id="edge-case-all-bits-set",
            ),
        ],
    )
    def test_button_events(self, bpf, report, expected):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected


@pytest.mark.parametrize("source", ["0010-XPPen__ACK05"])
class TestXPPenACK05:
    @pytest.mark.parametrize(
        "report,expected",
        [
            # anything but report ID 02 should be forwarded as such
            pytest.param(
                "04 f0 01 00 00 00 00 00 00 00 00 00",
                "04 f0 01 00 00 00 00 00 00 00 00 00",
                id="untouched-report",
            ),
            # button events are on report ID f0 with a size of 8, mostly untouched
            pytest.param(
                "02 f0 01 00 00 00 00 00 00 00 00 00",
                "f0 f0 01 00 00 00 00 00",
                id="single-button1-press",
            ),
            # CCW wheel events are button events with 0x02 changed to 0xff
            pytest.param(
                "02 f0 00 00 00 00 00 02 00 00 00 00",
                "f0 f0 00 00 00 00 00 ff",
                id="ccw-wheel",
            ),
            # battery reports are on f2 and of size 5
            pytest.param(
                "02 f2 01 00 00 00 00 00 00 00 00 00",
                "f2 f2 01 00 00",
                id="battery-report",
            ),
        ],
    )
    def test_button_events(self, bpf, report: str, expected: str):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected

    def test_probe(self, bpf):
        private = PrivateTestData(bpf)
        expected_output_data = binascii.unhexlify(
            "02 b0 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(
                " ", ""
            )
        )

        probe_args = HidProbeArgs()
        probe_args.rdesc_size = 37
        pa = bpf.probe(probe_args, private)
        assert pa.retval == -22
        assert len(private.output_reports) == 0

        probe_args.rdesc_size = 36
        pa = bpf.probe(probe_args, private)
        assert pa.retval == 0
        assert len(private.output_reports) == 1
        output_report = private.output_reports.pop()

        assert output_report.data == expected_output_data
        assert output_report.time == 0

    def test_delayed_callback(self, bpf):
        private = PrivateTestData(bpf)
        report = binascii.unhexlify(
            "02 f8 02 01 00 00 00 00 00 00 00 00".replace(" ", "")
        )
        expected_output_data = binascii.unhexlify(
            "02 b0 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(
                " ", ""
            )
        )

        # we need to call .probe() first to initialize the asyncs
        probe_args = HidProbeArgs()
        probe_args.rdesc_size = 36
        pa = bpf.probe(probe_args, private)
        assert pa.retval == 0
        assert len(private.output_reports) == 1
        output_report = private.output_reports.pop()

        assert output_report.data == expected_output_data
        assert output_report.time == 0

        event = bpf.hid_bpf_device_event(report, private)
        assert event == report

        assert len(private.output_reports) == 1
        output_report = private.output_reports.pop()

        assert output_report.data == expected_output_data
        assert output_report.time == 10


@pytest.mark.parametrize("source", ["0020-Huion__Inspiroy-2-S"])
class TestHuionInspiroy2S:
    @pytest.mark.parametrize("down_on_button", [True, False])
    @pytest.mark.parametrize("up_event_count", [1, 2, 3, 4])
    def test_eraser_tip_changes(self, bpf, down_on_button, up_event_count):
        @dataclass
        class Report:
            tip_switch: bool
            secondary_barrel_switch: bool
            in_range: bool = True

            def __bytes__(self) -> bytes:
                id = 0x8
                b1 = 0x0
                if self.in_range:
                    b1 |= 0x80
                if self.tip_switch:
                    b1 |= 0x1
                if self.secondary_barrel_switch:
                    b1 |= 0x4

                # For this test x/y values and pressure don't matter
                return bytes(
                    [id, b1, 0x59, 0x44, 0x47, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                )

            @classmethod
            def from_bytes(cls, bs: bytes) -> "Report":
                assert bs[0] == 0x8  # Report ID
                return cls(
                    tip_switch=(bs[1] & 0x1) != 0,
                    secondary_barrel_switch=(bs[1] & 0x4) != 0,
                    in_range=(bs[1] & 0x80) != 0,
                )

        # A "random" number of events after our button toggles
        filler_event_count = 10

        reports = [
            Report(tip_switch=False, secondary_barrel_switch=False),
            Report(tip_switch=True, secondary_barrel_switch=False),
            # Legitimate tip up/down
            Report(tip_switch=False, secondary_barrel_switch=False),
            Report(tip_switch=True, secondary_barrel_switch=False),
            # Press button
            Report(tip_switch=down_on_button, secondary_barrel_switch=True),
            *[Report(tip_switch=False, secondary_barrel_switch=True)] * up_event_count,
            *[Report(tip_switch=True, secondary_barrel_switch=True)] * filler_event_count,
            # Legitimate tip up/down
            Report(tip_switch=False, secondary_barrel_switch=True),
            Report(tip_switch=True, secondary_barrel_switch=True),
            *[Report(tip_switch=True, secondary_barrel_switch=True)] * filler_event_count,
            # Legitimate tip up/down
            # Release button
            Report(tip_switch=down_on_button, secondary_barrel_switch=False),
            *[Report(tip_switch=False, secondary_barrel_switch=False)] * up_event_count,
            *[Report(tip_switch=True, secondary_barrel_switch=False)] * filler_event_count,
            # Legitimate tip up event + prox-out
            Report(tip_switch=False, secondary_barrel_switch=False),
            Report(tip_switch=False, secondary_barrel_switch=False, in_range=False),
        ]  # fmt: skip

        expected = [
            Report(tip_switch=False, secondary_barrel_switch=False),
            Report(tip_switch=True, secondary_barrel_switch=False),
            # Legitimate tip up/down
            Report(tip_switch=False, secondary_barrel_switch=False),
            Report(tip_switch=True, secondary_barrel_switch=False),
            # Press button
            Report(tip_switch=True, secondary_barrel_switch=True),
            *[Report(tip_switch=True, secondary_barrel_switch=True)] * up_event_count,
            *[Report(tip_switch=True, secondary_barrel_switch=True)] * filler_event_count,
            # Legitimate tip up/down
            Report(tip_switch=False, secondary_barrel_switch=True),
            Report(tip_switch=True, secondary_barrel_switch=True),
            *[Report(tip_switch=True, secondary_barrel_switch=True)] * filler_event_count,
            # Release button
            Report(tip_switch=True, secondary_barrel_switch=False),
            *[Report(tip_switch=True, secondary_barrel_switch=False)] * up_event_count,
            *[Report(tip_switch=True, secondary_barrel_switch=False)] * filler_event_count,
            # Legitimate tip up event + prox-out
            Report(tip_switch=False, secondary_barrel_switch=False),
            Report(tip_switch=False, secondary_barrel_switch=False, in_range=False),
        ]  # fmt: skip

        events = [bpf.hid_bpf_device_event(report=bytes(report)) for report in reports]
        events = [Report.from_bytes(e) for e in events]

        assert events == expected


@pytest.mark.parametrize("source", ["0010-Huion__KeydialK20-Bluetooth"])
class TestHuionKeydialK20Bluetooth:
    @pytest.mark.parametrize("rdesc_size", [160, 114])
    def test_probe(self, bpf, rdesc_size):
        probe_args = HidProbeArgs(rdesc_size=rdesc_size)
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

    def test_probe_ignore_invalid_size(self, bpf):
        probe_args = HidProbeArgs(rdesc_size=123)
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

    @pytest.mark.parametrize(
        "modifier, button_key,expected_bit",
        [
            (0x00, 0x0E, 0),  # Button 1: K
            (0x00, 0x0A, 1),  # Button 2: G
            (0x00, 0x0F, 2),  # Button 3: L
            (0x00, 0x4C, 3),  # Button 4: Delete
            (0x00, 0x0C, 4),  # Button 5: I
            (0x00, 0x07, 5),  # Button 6: D
            (0x00, 0x05, 6),  # Button 7: B
            (0x00, 0x08, 7),  # Button 8: E
            (0x00, 0x16, 8),  # Button 9: S
            (0x00, 0x1D, 9),  # Button 10: Z
            (0x00, 0x06, 10),  # Button 11: C
            (0x00, 0x19, 11),  # Button 12: V
            (0x01, 0xFF, 12),  # Button 13: Control
            (0x04, 0xFF, 13),  # Button 14: Alt
            (0x02, 0xFF, 14),  # Button 15: Shift
            (0x00, 0x28, 15),  # Button 16: Return Enter
            (0x00, 0x2C, 16),  # Button 17: Spacebar
            (0x00, 0x11, 17),  # Button 18: N
        ],
    )
    def test_keyboard_button_events(self, bpf, modifier, button_key, expected_bit):
        report = bytearray(9)
        report[0] = 1  # Report ID
        report[1] = modifier
        report[4] = button_key

        data = bpf.hid_bpf_device_event(report=bytes(report))

        assert data[0] == 11  # OUR_REPORT_ID
        assert data[1] & 0x1 == 0  # btn_stylus
        assert data[2] == 0  # x
        assert data[3] == 0  # y

        # Check button state (bytes 4-7 as little-endian u32)
        button_state = struct.unpack("<I", data[4:8])[0]
        assert button_state == (1 << expected_bit)

    @pytest.mark.parametrize("is_press", [True, False])
    def test_center_button_event(self, bpf, is_press):
        report = bytearray(3)
        report[0] = 2  # Report ID
        report[1] = 0xCD if is_press else 0x00  # Play/Pause key (205)

        data = bpf.hid_bpf_device_event(report=bytes(report))

        assert data[0] == 11  # OUR_REPORT_ID
        assert data[1] & 0x1 == 0  # btn_stylus
        assert data[2] == 0  # x
        assert data[3] == 0  # y

        # Center button should map to button 19 (bit 18)
        button_state = struct.unpack("<I", data[4:8])[0]
        if is_press:
            assert button_state & (1 << 18) != 0
        else:
            assert button_state & (1 << 18) == 0

    @pytest.mark.parametrize(
        "wheel_value",
        [
            0xFF,  # Clockwise
            0x01,  # Counterclockwise
            0x00,  # No movement
        ],
    )
    def test_wheel_events(self, bpf, wheel_value):
        # Test Report ID 5 - wheel rotation events
        report = bytearray(7)
        report[0] = 5  # Report ID
        report[6] = wheel_value  # Wheel data

        data = bpf.hid_bpf_device_event(report=bytes(report))

        # Should be converted to vendor report format
        assert data[0] == 11  # OUR_REPORT_ID
        assert data[1] & 0x1 == 0  # btn_stylus
        assert data[2] == 0  # x
        assert data[3] == 0  # y
        assert data[8] == wheel_value


@pytest.mark.parametrize("source", ["0010-Gaomon__M6"])
class TestGaomonM6:
    @pytest.mark.parametrize("rdesc_size", [36, 119, 92])
    def test_probe(self, bpf, rdesc_size):
        probe_args = HidProbeArgs(rdesc_size=rdesc_size)
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

    def test_probe_ignore_invalid_size(self, bpf):
        probe_args = HidProbeArgs(rdesc_size=123)
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

    def test_rdesc(self, bpf):
        rdesc = bytes(36)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data[0] == 0x05  # Usage Page (Digitizers)

    @pytest.mark.parametrize(
        "report, expected",
        [
            pytest.param(
                "08 80 00 00 00 00 00 00 00 00 00 0a",
                "08 80 00 00 00 00 00 00 00 00 00 f6",
                id="pen-ytilt-invert",
            ),
            pytest.param(
                "08 e0 01 01 01 00 00 00 00 00 00 00",
                "09 00 00 00 01 00 00",
                id="button-1",
            ),
            pytest.param(
                "08 e0 00 00 00 02 00 00 00 00 00 00",
                "09 00 00 00 00 02 00",
                id="button-10",
            ),
            pytest.param(
                "08 e0 01 01 00 00 00 00 00 00 00 00",
                "09 00 00 00 00 00 00",
                id="button-release",
            ),
            pytest.param(
                "08 f0 00 00 00 01 00 00 00 00 00 00",
                "09 00 00 00 00 00 f2",
                id="wheel-pos-1",
            ),
            pytest.param(
                "08 f0 00 00 00 0c 00 00 00 00 00 00",
                "09 00 00 00 00 00 f3",
                id="wheel-pos-12",
            ),
            pytest.param(
                "08 f0 00 00 00 00 00 00 00 00 00 00",
                "09 00 00 00 00 00 00",
                id="wheel-release",
            ),
            # Invalid reports should remain unchanged
            pytest.param(
                "01 02 03 04 05 06 07 08 09 0a 0b 0c",
                "01 02 03 04 05 06 07 08 09 0a 0b 0c",
                id="invalid-report",
            ),
        ],
    )
    def test_events(self, bpf, report, expected):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected


# The XP-Pen Deco SE default-mode pad descriptor (100 or 102 bytes) is
# replaced wholesale with this 68-byte tablet pad descriptor, see the
# fixed_rdesc_pad in the BPF program.
DECO_SE_FIXED_PAD_RDESC = bytes.fromhex(
    "05010907a101850695017508050d0939a10005091901290815002501950875018102"
    "050d094495017501810295078101050109300931950275088102950375088101c0c0"
)
# The pen announces a +/-127 tilt range while only ever sending +/-60,
# see wrong_logical_range/correct_logical_range in the BPF program.
DECO_SE_WRONG_TILT_RANGE = bytes([0x15, 0x81, 0x25, 0x7F])
DECO_SE_CORRECT_TILT_RANGE = bytes([0x15, 0xC4, 0x25, 0x3C])


def _decose_pen(
    report_id=0x07,
    tilt_x=DECO_SE_WRONG_TILT_RANGE,
    tilt_y=DECO_SE_WRONG_TILT_RANGE,
):
    """A 109-byte pen descriptor with the report ID and tilt anchors set.

    The offsets match PEN_REPORT_ID_OFFSET (6), PEN_TILT_X_*_OFFSET (89)
    and PEN_TILT_Y_*_OFFSET (101) in the BPF program.
    """
    pen = bytearray(109)
    pen[6:8] = bytes([0x85, report_id])
    pen[89:93] = tilt_x
    pen[101:105] = tilt_y
    return bytes(pen)


@pytest.mark.parametrize("source", ["0010-XPPen__DecoSE"])
class TestXPPenDecoSE:
    @pytest.mark.parametrize("rdesc_size", [100, 102, 109, 211])
    def test_probe(self, bpf, rdesc_size):
        probe_args = HidProbeArgs(rdesc_size=rdesc_size)
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

    @pytest.mark.parametrize(
        "rdesc_size",
        [36, 68, 123],  # vendor interface, clean-mode pad, garbage
    )
    def test_probe_ignore_invalid_size(self, bpf, rdesc_size):
        probe_args = HidProbeArgs(rdesc_size=rdesc_size)
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

    @pytest.mark.parametrize("rdesc_size", [100, 102])
    def test_pad_rdesc_fixup(self, bpf, rdesc_size):
        # the pad descriptor is replaced wholesale, so the input
        # content does not matter
        rdesc = bytes(rdesc_size)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data == DECO_SE_FIXED_PAD_RDESC

    def test_bt_rdesc_fixup(self, bpf):
        # 211 bytes: the 102-byte pad descriptor directly followed by
        # the 109-byte pen descriptor. The pad part is replaced, the pen
        # part is moved up verbatim with only the tilt range corrected.
        rdesc = bytes(102) + _decose_pen()

        expected_pen = bytearray(_decose_pen())
        expected_pen[89:93] = DECO_SE_CORRECT_TILT_RANGE
        expected_pen[101:105] = DECO_SE_CORRECT_TILT_RANGE

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data == DECO_SE_FIXED_PAD_RDESC + bytes(expected_pen)

    def test_bt_rdesc_fixup_ignore_wrong_pen_report_id(self, bpf):
        # the guard requires the pen report ID (0x85 0x07) at offset 108
        rdesc = bytes(102) + _decose_pen(report_id=0x06)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data == rdesc

    def test_bt_rdesc_fixup_ignore_corrected_tilt(self, bpf):
        # the guard requires the wrong +/-127 tilt range on both axes
        rdesc = bytes(102) + _decose_pen(tilt_x=DECO_SE_CORRECT_TILT_RANGE)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data == rdesc

    def test_pen_rdesc_fixup(self, bpf):
        # standalone pen interface with the wrong +/-127 tilt range
        rdesc = _decose_pen()

        expected = bytearray(rdesc)
        expected[89:93] = DECO_SE_CORRECT_TILT_RANGE
        expected[101:105] = DECO_SE_CORRECT_TILT_RANGE

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data == bytes(expected)

    def test_pen_rdesc_fixup_ignore_correct_tilt(self, bpf):
        # already-corrected descriptors (clean mode) are left alone
        rdesc = _decose_pen(
            tilt_x=DECO_SE_CORRECT_TILT_RANGE,
            tilt_y=DECO_SE_CORRECT_TILT_RANGE,
        )

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data == rdesc

    @pytest.mark.parametrize(
        "report, expected",
        [
            pytest.param(
                "06 00 05 00 00 00 00 00",
                "06 01 00 00 00 00 00 00",
                id="button-1",
            ),
            pytest.param(
                "06 00 08 00 00 00 00 00",
                "06 02 00 00 00 00 00 00",
                id="button-2",
            ),
            pytest.param(
                "06 04 00 00 00 00 00 00",
                "06 04 00 00 00 00 00 00",
                id="button-3",
            ),
            pytest.param(
                "06 00 2c 00 00 00 00 00",
                "06 08 00 00 00 00 00 00",
                id="button-4",
            ),
            pytest.param(
                "06 01 16 00 00 00 00 00",
                "06 10 00 00 00 00 00 00",
                id="button-5",
            ),
            pytest.param(
                "06 01 1d 00 00 00 00 00",
                "06 20 00 00 00 00 00 00",
                id="button-6",
            ),
            pytest.param(
                "06 01 57 00 00 00 00 00",
                "06 40 00 00 00 00 00 00",
                id="button-7",
            ),
            pytest.param(
                "06 01 56 00 00 00 00 00",
                "06 80 00 00 00 00 00 00",
                id="button-8",
            ),
            pytest.param(
                "06 05 16 00 00 00 00 00",
                "06 14 00 00 00 00 00 00",
                id="buttons-3-and-5",
            ),
            pytest.param(
                "06 00 08 05 00 00 00 00",
                "06 03 00 00 00 00 00 00",
                id="buttons-1-and-2",
            ),
            pytest.param(
                "06 00 00 00 00 00 00 00",
                "06 00 00 00 00 00 00 00",
                id="buttons-released",
            ),
            # Non-pad reports should remain unchanged
            pytest.param(
                "02 01 02 03 04 05 06 07",
                "02 01 02 03 04 05 06 07",
                id="invalid-report",
            ),
        ],
    )
    def test_button_events(self, bpf, report, expected):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected
