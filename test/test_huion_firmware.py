# SPDX-License-Identifier: GPL-2.0-only
#
# Tests for the Huion/UGEE/Gaomon firmware ID handling (src/bpf/huion.h):
# the firmware ID is read from USB string descriptor 201 via
# hid_bpf_get_string_descriptor() where the kernel supports it, with a
# fallback to the HUION_FIRMWARE_ID udev property set by huion-switcher.

import ctypes
from dataclasses import dataclass

import pytest

from . import HidProbeArgs, PrivateTestData

LANGID_EN_US = 0x0409
INDEX_MAGIC = 200
INDEX_FIRMWARE_ID = 201


@dataclass
class Model:
    source: str
    firmware_id: str
    # report descriptor sizes of the interfaces disabled in vendor mode
    disabled_sizes: tuple[int, ...]
    # report descriptor size of the vendor interface
    vendor_size: int


MODELS = [
    Model("0010-Huion__Dial-2", "HUION_T216_230505", (148, 93), 18),
    Model("0010-Huion__Inspiroy-2-M", "HUION_T21k_221221", (133, 93), 36),
    Model("0010-Huion__Inspiroy-2-S", "HUION_T21j_221221", (65, 93), 18),
    Model("0020-Huion__Inspiroy-2-S", "HUION_T21j_221221", (65, 93), 18),
    Model("0010-Huion__Kamvas13Gen3", "HUION_M22c_230731", (368, 108), 36),
    Model("0010-Huion__Kamvas16Gen3", "HUION_M22d_230731", (328, 200), 36),
    Model("0010-Huion__KeydialK20", "HUION_T21h_230511", (135, 108), 18),
    Model("0010-Gaomon__M6", "GM001_T223_231109", (119, 92), 36),
]

# 18 bytes is the minimum huion-switcher accepts for the index 200 magic
MAGIC = bytes([20, 0x03]) + bytes(range(1, 19))


def set_udev_prop(bpf, value: bytes):
    prop = (ctypes.c_char * 64).in_dll(bpf.lib, "UDEV_PROP_HUION_FIRMWARE_ID")
    ctypes.memset(prop, 0, 64)
    prop.value = value


def uniq_of(pdata: PrivateTestData) -> bytes:
    return bytes(pdata.current_ctx.hid.contents.uniq).split(b"\0", 1)[0]


def fixup(bpf, size: int, pdata: PrivateTestData) -> bytes:
    rdesc = bytes(size)
    pdata.current_ctx.retval = 0
    return bpf.hid_bpf_rdesc_fixup(rdesc=rdesc, private_data=pdata)


def make_pdata(bpf, descriptors) -> PrivateTestData:
    pdata = PrivateTestData(bpf=bpf)
    pdata.string_descriptors = descriptors
    return pdata


def params():
    return [pytest.param(m.source, m, id=m.source) for m in MODELS]


@pytest.mark.parametrize("source, model", params())
class TestFirmwareId:
    def baseline(self, bpf, model, size) -> bytes:
        """Fixup result for a device with no firmware ID at all."""
        set_udev_prop(bpf, b"")
        return fixup(bpf, size, make_pdata(bpf, None))

    def test_kfunc_firmware_id_disables_firmware_mode(self, bpf, model):
        for size in model.disabled_sizes:
            base = self.baseline(bpf, model, size)
            pdata = make_pdata(
                bpf, {INDEX_FIRMWARE_ID: model.firmware_id, INDEX_MAGIC: MAGIC}
            )
            out = fixup(bpf, size, pdata)
            assert out != base, "firmware-mode interface not disabled"
            # only the firmware ID is read on a firmware-mode interface
            assert [(r.index, r.langid) for r in pdata.string_descriptor_requests] == [
                (INDEX_FIRMWARE_ID, LANGID_EN_US)
            ]
            assert uniq_of(pdata) == model.firmware_id.encode()

    def test_kfunc_switches_vendor_interface(self, bpf, model):
        pdata = make_pdata(
            bpf, {INDEX_FIRMWARE_ID: model.firmware_id, INDEX_MAGIC: MAGIC}
        )
        fixup(bpf, model.vendor_size, pdata)
        assert [r.index for r in pdata.string_descriptor_requests] == [
            INDEX_FIRMWARE_ID,
            INDEX_MAGIC,
        ]
        assert uniq_of(pdata) == model.firmware_id.encode()

    def test_udev_property_fallback(self, bpf, model):
        """Kernel without the kfunc (or non-USB): use huion-switcher's property"""
        for size in model.disabled_sizes:
            pdata = make_pdata(
                bpf, {INDEX_FIRMWARE_ID: model.firmware_id, INDEX_MAGIC: MAGIC}
            )
            expected = fixup(bpf, size, pdata)

            set_udev_prop(bpf, model.firmware_id.encode())
            pdata = make_pdata(bpf, None)
            out = fixup(bpf, size, pdata)
            set_udev_prop(bpf, b"")

            assert out == expected
            assert pdata.string_descriptor_requests == []
            assert uniq_of(pdata) == b""

    def test_wrong_prefix(self, bpf, model):
        """A different product sharing the PID must not be switched"""
        for size in model.disabled_sizes + (model.vendor_size,):
            base = self.baseline(bpf, model, size)
            pdata = make_pdata(
                bpf, {INDEX_FIRMWARE_ID: "HUION_X99z_000000", INDEX_MAGIC: MAGIC}
            )
            out = fixup(bpf, size, pdata)
            assert out == base
            assert INDEX_MAGIC not in [
                r.index for r in pdata.string_descriptor_requests
            ]
            assert uniq_of(pdata) == b""

    def test_kfunc_wins_over_stale_udev_property(self, bpf, model):
        """The device's own answer takes precedence over the udev property"""
        size = model.disabled_sizes[0]
        base = self.baseline(bpf, model, size)
        set_udev_prop(bpf, model.firmware_id.encode())
        pdata = make_pdata(
            bpf, {INDEX_FIRMWARE_ID: "HUION_X99z_000000", INDEX_MAGIC: MAGIC}
        )
        out = fixup(bpf, size, pdata)
        set_udev_prop(bpf, b"")
        assert out == base

    def test_existing_uniq_is_kept(self, bpf, model):
        size = model.disabled_sizes[0]
        pdata = make_pdata(
            bpf, {INDEX_FIRMWARE_ID: model.firmware_id, INDEX_MAGIC: MAGIC}
        )
        pdata.uniq = b"serial-1234"
        fixup(bpf, size, pdata)
        assert uniq_of(pdata) == b"serial-1234"

    def test_malformed_descriptor_falls_back(self, bpf, model):
        """A non-string or non-ASCII descriptor is ignored"""
        size = model.disabled_sizes[0]
        base = self.baseline(bpf, model, size)
        for bad in (
            bytes([4, 0x02, ord("H"), 0]),  # wrong bDescriptorType
            bytes([6, 0x03, 0x41, 0x30, 0x42, 0x30]),  # non-ASCII UTF-16
        ):
            pdata = make_pdata(bpf, {INDEX_FIRMWARE_ID: bad, INDEX_MAGIC: MAGIC})
            assert fixup(bpf, size, pdata) == base
            assert uniq_of(pdata) == b""


# The H610 Pro (userhacks) checks the firmware ID and the tablet parameters
# from the index 200 magic bytes in probe().
H610_MAGIC = bytes.fromhex("0e03409ca8610300ff07a00f0800")
H610_SIZES = (92, 244, 179)


def set_h610_udev_props(bpf, fw_id: bytes, magic_hex: bytes):
    set_udev_prop(bpf, fw_id)
    prop = (ctypes.c_char * 64).in_dll(bpf.lib, "UDEV_PROP_HUION_MAGIC_BYTES")
    ctypes.memset(prop, 0, 64)
    prop.value = magic_hex


@pytest.mark.parametrize("source", ["0010-Huion__H610-Pro"])
class TestHuionH610ProFirmware:
    @pytest.mark.parametrize("size", H610_SIZES)
    def test_probe_kfunc(self, bpf, size):
        set_h610_udev_props(bpf, b"", b"")
        pdata = make_pdata(
            bpf, {INDEX_FIRMWARE_ID: "HVAN0001", INDEX_MAGIC: H610_MAGIC}
        )
        pa = bpf.probe(HidProbeArgs(rdesc_size=size), private_data=pdata)
        assert pa.retval == 0
        assert [r.index for r in pdata.string_descriptor_requests] == [
            INDEX_FIRMWARE_ID,
            INDEX_MAGIC,
        ]

    def test_probe_kfunc_wrong_params(self, bpf):
        set_h610_udev_props(bpf, b"", b"")
        magic = bytearray(H610_MAGIC)
        magic[10] = 0xB0  # different resolution
        pdata = make_pdata(
            bpf, {INDEX_FIRMWARE_ID: "HVAN0001", INDEX_MAGIC: bytes(magic)}
        )
        pa = bpf.probe(HidProbeArgs(rdesc_size=H610_SIZES[0]), private_data=pdata)
        assert pa.retval == -22

    def test_probe_kfunc_wrong_firmware(self, bpf):
        set_h610_udev_props(bpf, b"", b"")
        pdata = make_pdata(
            bpf, {INDEX_FIRMWARE_ID: "HUION_T21j_1", INDEX_MAGIC: H610_MAGIC}
        )
        pa = bpf.probe(HidProbeArgs(rdesc_size=H610_SIZES[0]), private_data=pdata)
        assert pa.retval == -22

    def test_probe_udev_property_fallback(self, bpf):
        set_h610_udev_props(bpf, b"HVAN0001", H610_MAGIC.hex().encode())
        pa = bpf.probe(
            HidProbeArgs(rdesc_size=H610_SIZES[0]), private_data=make_pdata(bpf, None)
        )
        set_h610_udev_props(bpf, b"", b"")
        assert pa.retval == 0

    def test_probe_nothing(self, bpf):
        set_h610_udev_props(bpf, b"", b"")
        pa = bpf.probe(
            HidProbeArgs(rdesc_size=H610_SIZES[0]), private_data=make_pdata(bpf, None)
        )
        assert pa.retval == -22

    def test_rdesc_sets_uniq(self, bpf):
        pdata = make_pdata(bpf, {INDEX_FIRMWARE_ID: "HVAN0001"})
        fixup(bpf, H610_SIZES[2], pdata)
        assert uniq_of(pdata) == b"HVAN0001"
