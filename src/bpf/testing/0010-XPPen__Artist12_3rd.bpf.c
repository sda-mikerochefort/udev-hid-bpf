// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 David Revoy
 * Copyright (c) 2026 Red Hat, Inc
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_UGEE 0x28BD /* VID is shared with SinoWealth and Glorious and probably others */
#define PID_ARTIST_12_3RD 0x097D

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_ARTIST_12_3RD),
);

/*
 * Default report descriptor reports:
 * - a report descriptor for the pad buttons, reported as key sequences
 * - a report descriptor for the pen
 * - a vendor-specific report descriptor
 *
 * The Pad report descriptor, length: 177 bytes
 * #   0x05, 0x01,                    // Usage Page (Generic Desktop)            0
 * #   0x09, 0x02,                    // Usage (Mouse)                           2
 * #   0xa1, 0x01,                    // Collection (Application)                4
 * # ┅ 0x85, 0x09,                    //   Report ID (9)                         6
 * #   0x09, 0x01,                    //   Usage (Pointer)                       8
 * #   0xa1, 0x00,                    //   Collection (Physical)                 10
 * #   0x05, 0x09,                    //     Usage Page (Button)                 12
 * #   0x19, 0x01,                    //     UsageMinimum (1)                    14
 * #   0x29, 0x03,                    //     UsageMaximum (3)                    16
 * #   0x15, 0x00,                    //     Logical Minimum (0)                 18
 * #   0x25, 0x01,                    //     Logical Maximum (1)                 20
 * #   0x95, 0x03,                    //     Report Count (3)                    22
 * #   0x75, 0x01,                    //     Report Size (1)                     24
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                26
 * #   0x95, 0x05,                    //     Report Count (5)                    28
 * # ┇ 0x81, 0x01,                    //     Input (Cnst,Arr,Abs)                30
 * #   0x05, 0x01,                    //     Usage Page (Generic Desktop)        32
 * #   0x09, 0x30,                    //     Usage (X)                           34
 * #   0x09, 0x31,                    //     Usage (Y)                           36
 * #   0x26, 0xff, 0x7f,              //     Logical Maximum (32767)             38
 * #   0x95, 0x02,                    //     Report Count (2)                    41
 * #   0x75, 0x10,                    //     Report Size (16)                    43
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                45
 * #   0x05, 0x0d,                    //     Usage Page (Digitizers)             47
 * #   0x09, 0x30,                    //     Usage (Tip Pressure)                49
 * #   0x26, 0xff, 0x07,              //     Logical Maximum (2047)              51
 * #   0x95, 0x01,                    //     Report Count (1)                    54
 * #   0x75, 0x10,                    //     Report Size (16)                    56
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                58
 * #   0xc0,                          //   End Collection                        60
 * #   0xc0,                          // End Collection                          61
 * #   0x05, 0x01,                    // Usage Page (Generic Desktop)            62
 * #   0x09, 0x02,                    // Usage (Mouse)                           64
 * #   0xa1, 0x01,                    // Collection (Application)                66
 * #   0x09, 0x01,                    //   Usage (Pointer)                       68
 * #   0xa1, 0x00,                    //   Collection (Physical)                 70
 * # ┅ 0x85, 0x01,                    //     Report ID (1)                       72
 * #   0x05, 0x09,                    //     Usage Page (Button)                 74
 * #   0x19, 0x01,                    //     UsageMinimum (1)                    76
 * #   0x29, 0x05,                    //     UsageMaximum (5)                    78
 * #   0x95, 0x05,                    //     Report Count (5)                    80
 * #   0x75, 0x01,                    //     Report Size (1)                     82
 * #   0x15, 0x00,                    //     Logical Minimum (0)                 84
 * #   0x25, 0x01,                    //     Logical Maximum (1)                 86
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                88
 * #   0x95, 0x03,                    //     Report Count (3)                    90
 * # ┇ 0x81, 0x01,                    //     Input (Cnst,Arr,Abs)                92
 * #   0x05, 0x01,                    //     Usage Page (Generic Desktop)        94
 * #   0x09, 0x30,                    //     Usage (X)                           96
 * #   0x09, 0x31,                    //     Usage (Y)                           98
 * #   0x95, 0x02,                    //     Report Count (2)                    100
 * #   0x75, 0x10,                    //     Report Size (16)                    102
 * #   0x16, 0x00, 0x80,              //     Logical Minimum (-32768)            104
 * #   0x26, 0xff, 0x7f,              //     Logical Maximum (32767)             107
 * # ┇ 0x81, 0x06,                    //     Input (Data,Var,Rel)                110
 * #   0x09, 0x38,                    //     Usage (Wheel)                       112
 * #   0x15, 0x81,                    //     Logical Minimum (-127)              114
 * #   0x25, 0x7f,                    //     Logical Maximum (127)               116
 * #   0x95, 0x01,                    //     Report Count (1)                    118
 * #   0x75, 0x08,                    //     Report Size (8)                     120
 * # ┇ 0x81, 0x06,                    //     Input (Data,Var,Rel)                122
 * #   0x05, 0x0c,                    //     Usage Page (Consumer)               124
 * #   0x0a, 0x38, 0x02,              //     Usage (AC Pan)                      126
 * #   0x95, 0x01,                    //     Report Count (1)                    129
 * #   0x75, 0x08,                    //     Report Size (8)                     131
 * # ┇ 0x81, 0x06,                    //     Input (Data,Var,Rel)                133
 * #   0xc0,                          //   End Collection                        135
 * #   0xc0,                          // End Collection                          136
 * #   0x05, 0x01,                    // Usage Page (Generic Desktop)            137
 * #   0x09, 0x06,                    // Usage (Keyboard)                        139
 * #   0xa1, 0x01,                    // Collection (Application)                141
 * # ┅ 0x85, 0x06,                    //   Report ID (6)                         143
 * #   0x05, 0x07,                    //   Usage Page (Keyboard/Keypad)          145
 * #   0x19, 0xe0,                    //   UsageMinimum (224)                    147
 * #   0x29, 0xe7,                    //   UsageMaximum (231)                    149
 * #   0x15, 0x00,                    //   Logical Minimum (0)                   151
 * #   0x25, 0x01,                    //   Logical Maximum (1)                   153
 * #   0x75, 0x01,                    //   Report Size (1)                       155
 * #   0x95, 0x08,                    //   Report Count (8)                      157
 * # ┇ 0x81, 0x02,                    //   Input (Data,Var,Abs)                  159
 * #   0x05, 0x07,                    //   Usage Page (Keyboard/Keypad)          161
 * #   0x19, 0x00,                    //   UsageMinimum (0)                      163
 * #   0x29, 0xff,                    //   UsageMaximum (255)                    165
 * #   0x26, 0xff, 0x00,              //   Logical Maximum (255)                 167
 * #   0x75, 0x08,                    //   Report Size (8)                       170
 * #   0x95, 0x06,                    //   Report Count (6)                      172
 * # ┇ 0x81, 0x00,                    //   Input (Data,Arr,Abs)                  174
 * #   0xc0,                          // End Collection                          176
 *
 * The pen report descriptor, length 113 bytes
 * #   0x05, 0x0d,                    // Usage Page (Digitizers)                 0
 * #   0x09, 0x02,                    // Usage (Pen)                             2
 * #   0xa1, 0x01,                    // Collection (Application)                4
 * # ┅ 0x85, 0x07,                    //   Report ID (7)                         6
 * #   0x09, 0x20,                    //   Usage (Stylus)                        8
 * #   0xa1, 0x00,                    //   Collection (Physical)                 10
 * #   0x09, 0x42,                    //     Usage (Tip Switch)                  12
 * #   0x09, 0x44,                    //     Usage (Barrel Switch)               14
 * #   0x09, 0x45,                    //     Usage (Eraser)                      16
 * #   0x09, 0x3c,                    //     Usage (Invert)                      18
 * #   0x15, 0x00,                    //     Logical Minimum (0)                 20
 * #   0x25, 0x01,                    //     Logical Maximum (1)                 22
 * #   0x75, 0x01,                    //     Report Size (1)                     24
 * #   0x95, 0x04,                    //     Report Count (4)                    26
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                28
 * #   0x95, 0x01,                    //     Report Count (1)                    30
 * # ┇ 0x81, 0x03,                    //     Input (Cnst,Var,Abs)                32
 * #   0x09, 0x32,                    //     Usage (In Range)                    34
 * #   0x15, 0x00,                    //     Logical Minimum (0)                 36
 * #   0x25, 0x01,                    //     Logical Maximum (1)                 38
 * #   0x95, 0x01,                    //     Report Count (1)                    40
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                42
 * #   0x95, 0x02,                    //     Report Count (2)                    44
 * # ┇ 0x81, 0x03,                    //     Input (Cnst,Var,Abs)                46
 * #   0x75, 0x10,                    //     Report Size (16)                    48
 * #   0x95, 0x01,                    //     Report Count (1)                    50
 * #   0x35, 0x00,                    //     Physical Minimum (0)                52
 * #   0xa4,                          //     Push                                54
 * #   0x05, 0x01,                    //     Usage Page (Generic Desktop)        55
 * #   0x09, 0x30,                    //     Usage (X)                           57
 * #   0x65, 0x13,                    //     Unit (EnglishLinear: in)            59
 * #   0x55, 0x0d,                    //     Unit Exponent (-3)                  61
 * #   0x46, 0x85, 0x28,              //     Physical Maximum (10373)            63
 * #   0x26, 0xff, 0x7f,              //     Logical Maximum (32767)             66
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                69
 * #   0x09, 0x31,                    //     Usage (Y)                           71
 * #   0x46, 0xd6, 0x16,              //     Physical Maximum (5846)             73
 * #   0x26, 0xff, 0x7f,              //     Logical Maximum (32767)             76
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                79
 * #   0xb4,                          //     Pop                                 81
 * #   0x09, 0x30,                    //     Usage (X)                           82
 * #   0x45, 0x00,                    //     Physical Maximum (0)                84
 * #   0x26, 0xff, 0x3f,              //     Logical Maximum (16383)             86
 * # ┇ 0x81, 0x42,                    //     Input (Data,Var,Abs,Null)           89
 * #   0x09, 0x3d,                    //     Usage (Start)                       91
 * #   0x15, 0x81,                    //     Logical Minimum (-127)              93
 * #   0x25, 0x7f,                    //     Logical Maximum (127)               95
 * #   0x75, 0x08,                    //     Report Size (8)                     97
 * #   0x95, 0x01,                    //     Report Count (1)                    99
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                101
 * #   0x09, 0x3e,                    //     Usage (Select)                      103
 * #   0x15, 0x81,                    //     Logical Minimum (-127)              105
 * #   0x25, 0x7f,                    //     Logical Maximum (127)               107
 * # ┇ 0x81, 0x02,                    //     Input (Data,Var,Abs)                109
 * #   0xc0,                          //   End Collection                        111
 * #   0xc0,                          // End Collection                          112
 *
 * The device's pad descriptor reports keyboard modifier+keycode pairs instead
 * of proper button events. Switching to raw mode and using the vendor
 * collection makes things much easier to deal with
 *
 * Pad report structure (Report ID 6, 8 bytes) (kept for documentation purpose):
 *   Byte 0: Report ID (0x06)
 *   Byte 1: Button bits 0-7   (buttons 1-8, bitmask 0x01-0x80)
 *   Byte 2: Button bits 8-9   (buttons 9-10, bitmask 0x01-0x02)
 *   Byte 3: Button bits 10-11 (buttons 11-12 mapped to BTN_A/BTN_B, bitmask 0x01-0x02)
 *   Bytes 4-7: Unused (zeroed)
 *
 * Default pad button mapping (top → bottom):
 * Buttons released: 06 00 00 00 00 00 00 00
 * Button 1:  06 00 08 00 00 00 00 00 → 0x45		→ E
 * Button 2:  06 00 05 00 00 00 00 00 → 0x30		→ B
 * Button 3:  06 04 00 00 00 00 00 00 → 0xe2		→ LeftAlt
 * Button 4:  06 02 00 00 00 00 00 00 → 0xe1		→ LeftShift
 *
 * Button 9:  06 01 2d 00 00 00 00 00 → 0xe0 + 0x38	→ Ctrl+Minus (top wheel, CW)
 * Button 10: 06 01 2e 00 00 00 00 00 → 0xe0 + 0x27	→ Ctrl+Equals (top wheel, ACW)
 *
 * Button 11 (BTN_A): 06 00 2f 00 00 00 00 00 → 0x2f	→ LeftBrace (bottom wheel, CW)
 * Button 12 (BTN_B): 06 00 30 00 00 00 00 00 → 0x30	→ RightBrace (bottom wheel, ACW)
 *
 * Button 5:  06 01 00 00 00 00 00 00 → 0xe0		→ LeftControl
 * Button 6:  06 00 2c 00 00 00 00 00 → 0x2c		→ Space
 * Button 7:  06 01 16 00 00 00 00 00 → 0xe0 + 0x16	→ Ctrl+S
 * Button 8:  06 01 1d 00 00 00 00 00 → 0xe0 + 0x1d	→ Ctrl+Z
 *
 * The stylus eraser usage (0x09, 0x45) is remapped to a secondary barrel
 * switch (0x09, 0x5a) in the vendor collection, since it's a drawing-tablet
 * that requires a top barrel buttons on the stylus instead of an eraser mode by
 * default.
 *
 * The tablet supports 16K range of pressure, but the legacy XP-Pen vendor
 * collection only supports 8K. There is an extra byte at the end of the report
 * to say when we are above 8K, which makes the device event a tad complex.
 */

#define STYLUS_REPORT_DESCRIPTOR_LENGTH 113
#define PAD_REPORT_DESCRIPTOR_LENGTH 177
#define VENDOR_REPORT_DESCRIPTOR_LENGTH 36
#define PAD_REPORT_LENGTH 9
#define PEN_REPORT_ID 7
#define RAW_PAD_REPORT_ID 0xf0
#define RAW_STYLUS_ID_REPORT_ID 0xf6
#define VENDOR_REPORT_ID 2
#define VENDOR_REPORT_LENGTH 14

static const __u8 disabled_rdesc[] = {
	// Make sure we match our original report length
	FixedSizeVendorReport(VENDOR_REPORT_LENGTH)
};

static const __u8 fixed_rdesc_vendor[] = {
	UsagePage_GenericDesktop
	Usage_GD_Keypad
	CollectionApplication(
		// -- Byte 0 in report
		ReportId(RAW_PAD_REPORT_ID)
		// Byte 1 in report - same as report ID
		ReportCount(1)
		ReportSize(8)
		Input(Const) // padding (internal report ID)
		LogicalMinimum_i8(0)
		LogicalMaximum_i8(1)
		UsagePage_Digitizers
		Usage_Dig_TabletFunctionKeys
		CollectionPhysical(
			// Byte 2-3 is the button state
			UsagePage_Button
			UsageMinimum_i8(0x01)
			UsageMaximum_i8(0x08)
			LogicalMinimum_i8(0x0)
			LogicalMaximum_i8(0x1)
			ReportCount(8)
			ReportSize(1)
			Input(Var|Abs)
			ReportCount(8) // padding
			Input(Const)
			// Byte 4 in report - just exists so we get to be a tablet pad
			UsagePage_Digitizers
			Usage_Dig_BarrelSwitch // BTN_STYLUS
			ReportCount(1)
			ReportSize(1)
			Input(Var|Abs)
			ReportCount(7) // padding
			Input(Const)
			// Bytes 5/6 in report - just exists so we get to be a tablet pad
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			ReportCount(2)
			ReportSize(8)
			Input(Var|Abs)
			// Byte 7 in report are the 2 wheels
			Usage_GD_Wheel
			LogicalMinimum_i8(-127)
			LogicalMaximum_i8(127)
			ReportCount(1)
			ReportSize(8)
			Input(Var|Rel)
			UsagePage_Consumer
			Usage_Con_ACPan
			Input(Var|Rel)      // byte 8
		)
	)
	UsagePage_Digitizers
	Usage_Dig_Pen
	CollectionApplication(
		/* Byte 0 in report is the report ID */
		ReportId(PEN_REPORT_ID)
		Usage_Dig_Stylus
		CollectionPhysical(
			Usage_Dig_TipSwitch
			Usage_Dig_BarrelSwitch
			Usage_Dig_SecondaryBarrelSwitch // maps eraser to BTN_STYLUS2
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(1)
			ReportSize(1)
			ReportCount(3)
			Input(Var|Abs)
			ReportCount(2)  // Padding
			Input(Const)
			Usage_Dig_InRange
			ReportCount(1)
			Input(Var|Abs)
			ReportCount(2)  // Padding
			Input(Const)
			ReportSize(16)
			ReportCount(1)
			PhysicalMinimum_i16(0)
			PushPop(
				UsagePage_GenericDesktop
				Unit(cm)
				UnitExponent(-1)
				PhysicalMaximum_i16(264)
				LogicalMinimum_i16(0)
				LogicalMaximum_i16(52694)
				Usage_GD_X
				Input(Var|Abs) // Bytes 2+3
				PhysicalMaximum_i16(149)
				LogicalMinimum_i16(0)
				LogicalMaximum_i16(29697)
				Usage_GD_Y
				Input(Var|Abs) // Bytes 4+5
			)
			UsagePage_Digitizers
			Usage_Dig_TipPressure
			LogicalMinimum_i16(0)
			LogicalMaximum_i16(16383)
			Input(Var|Abs) // Byte 6+7
			Usage_Dig_XTilt
			LogicalMinimum_i8(-60)
			LogicalMaximum_i8(60)
			ReportSize(8)
			ReportCount(1)
			Input(Var|Abs) // Byte 8
			Usage_Dig_YTilt
			LogicalMinimum_i8(-60)
			LogicalMaximum_i8(60)
			Input(Var|Abs) // Byte 9
		)
	)
};

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(xppen_artist12_3rd_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);
	__s32 rdesc_size = hctx->size;

	if (!data)
		return 0; /* EPERM check */

	if (rdesc_size == VENDOR_REPORT_DESCRIPTOR_LENGTH) {
		/*
		 * The vendor fixed rdesc is appended after the current one,
		 * to keep the output reports working.
		 */
		__builtin_memcpy(data + rdesc_size, fixed_rdesc_vendor, sizeof(fixed_rdesc_vendor));
		return sizeof(fixed_rdesc_vendor) + rdesc_size;
	}

	hid_set_name(hctx->hid, "Disabled by HID-BPF XPPen Artist 12 3rd");

	__builtin_memcpy(data, disabled_rdesc, sizeof(disabled_rdesc));
	return sizeof(disabled_rdesc);
}

static int switch_to_raw_mode(struct hid_bpf_ctx *hid)
{
	static __u8 magic_0[32] = {0x02, 0xb0, 0x04, 0x00, 0x00};
	int err;

	/*
	 * The proprietary driver sends the 2 following packets after the
	 * above one.
	 * These don't seem to have any effect, so we don't send them to save
	 * some processing time.
	 *
	 * static __u8 magic_1[32] = {0x02, 0xb4, 0x01, 0x00, 0x01};
	 * static __u8 magic_2[32] = {0x02, 0xb4, 0x01, 0x00, 0x02};
	 */

	err = hid_bpf_hw_output_report(hid, magic_0, sizeof(magic_0));
	if (err < 0)
		return err;

	return 0;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(xppen_artist12_3rd_device_event, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, VENDOR_REPORT_LENGTH);
	int ret = 0;

	if (!data)
		return 0; /* EPERM check */

	if (data[0] != VENDOR_REPORT_ID)
		return 0;

	/* button event */
	if (data[1] == RAW_PAD_REPORT_ID) {
		data[0] = data[1];
		switch (data[7]) {
		case 0x02:
			data[7] = 0xff;
			break;
		case 0x04:
			data[7] = 0x00;
			data[8] = 0x01;
			break;
		case 0x08:
			data[7] = 0x00;
			data[8] = 0xff;
			break;
		}
		ret = PAD_REPORT_LENGTH;
	} else if (data[1] != RAW_STYLUS_ID_REPORT_ID) {
		data[0] = PEN_REPORT_ID;

		if (data[13] & 0x01) {
			/* higher than 8192 pressure */
			u16 *raw_pressure = (u16 *)&data[6];
			u16 pressure = hid_bpf_le16_to_cpu(*raw_pressure);

			pressure += 8192;
			*raw_pressure = hid_bpf_cpu_to_le16(pressure);
		}
	}

	return ret;
}

HID_BPF_OPS(xppen_artist12_3rd) = {
	.hid_rdesc_fixup = (void *)xppen_artist12_3rd_rdesc_fixup,
	.hid_device_event = (void *)xppen_artist12_3rd_device_event,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	switch (ctx->rdesc_size) {
	case PAD_REPORT_DESCRIPTOR_LENGTH:
	case STYLUS_REPORT_DESCRIPTOR_LENGTH:
	case VENDOR_REPORT_DESCRIPTOR_LENGTH:
		ctx->retval = 0;
		break;
	default:
		ctx->retval = -EINVAL;
	}

	if (ctx->rdesc_size == VENDOR_REPORT_DESCRIPTOR_LENGTH) {
		struct hid_bpf_ctx *hctx = hid_bpf_allocate_context(ctx->hid);

		if (!hctx) {
			ctx->retval = -EINVAL;
			return 0;
		}

		ctx->retval = switch_to_raw_mode(hctx);

		hid_bpf_release_context(hctx);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
