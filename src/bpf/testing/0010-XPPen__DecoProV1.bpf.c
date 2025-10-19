// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Higgins Dragon
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_UGEE 0x28BD
#define PID_DECO_PRO_M 0x0904
#define PID_DECO_PRO_MW 0x0934
#define PID_DECO_PRO_S 0x0909
#define PID_DECO_PRO_SW 0x0933

/*
 * The Deco Pro M and MW are essentially the same over USB but the MW has bluetooth.
 * The S and SW tablets also have the same button layouts and are part of the same series,
 * so they should work as well.
 */
HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_DECO_PRO_M),
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_DECO_PRO_MW),
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_DECO_PRO_S),
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_DECO_PRO_SW),
);

/*
 * DESCRIPTOR 0
 *
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
 * # 0x09, 0x02,                    // Usage (Mouse)                       2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x85, 0x09,                    //  Report ID (9)                      6
 * # 0x09, 0x01,                    //  Usage (Pointer)                    8
 * # 0xa1, 0x00,                    //  Collection (Physical)              10
 * # 0x05, 0x09,                    //   Usage Page (Button)               12
 * # 0x19, 0x01,                    //   Usage Minimum (1)                 14
 * # 0x29, 0x03,                    //   Usage Maximum (3)                 16
 * # 0x15, 0x00,                    //   Logical Minimum (0)               18
 * # 0x25, 0x01,                    //   Logical Maximum (1)               20
 * # 0x95, 0x03,                    //   Report Count (3)                  22
 * # 0x75, 0x01,                    //   Report Size (1)                   24
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              26
 * # 0x95, 0x05,                    //   Report Count (5)                  28
 * # 0x81, 0x01,                    //   Input (Cnst,Arr,Abs)              30
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      32
 * # 0x09, 0x30,                    //   Usage (X)                         34
 * # 0x09, 0x31,                    //   Usage (Y)                         36
 * # 0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           38
 * # 0x95, 0x02,                    //   Report Count (2)                  41
 * # 0x75, 0x10,                    //   Report Size (16)                  43
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              45
 * # 0x05, 0x0d,                    //   Usage Page (Digitizers)           47
 * # 0x09, 0x30,                    //   Usage (Tip Pressure)              49
 * # 0x26, 0xff, 0x07,              //   Logical Maximum (2047)            51
 * # 0x95, 0x01,                    //   Report Count (1)                  54
 * # 0x75, 0x10,                    //   Report Size (16)                  56
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              58
 * # 0xc0,                          //  End Collection                     60
 * # 0xc0,                          // End Collection                      61
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        62
 * # 0x09, 0x02,                    // Usage (Mouse)                       64
 * # 0xa1, 0x01,                    // Collection (Application)            66
 * # 0x09, 0x01,                    //  Usage (Pointer)                    68
 * # 0xa1, 0x00,                    //  Collection (Physical)              70
 * # 0x85, 0x01,                    //   Report ID (1)                     72
 * # 0x05, 0x09,                    //   Usage Page (Button)               74
 * # 0x19, 0x01,                    //   Usage Minimum (1)                 76
 * # 0x29, 0x05,                    //   Usage Maximum (5)                 78
 * # 0x95, 0x05,                    //   Report Count (5)                  80
 * # 0x75, 0x01,                    //   Report Size (1)                   82
 * # 0x15, 0x00,                    //   Logical Minimum (0)               84
 * # 0x25, 0x01,                    //   Logical Maximum (1)               86
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              88
 * # 0x95, 0x03,                    //   Report Count (3)                  90
 * # 0x81, 0x01,                    //   Input (Cnst,Arr,Abs)              92
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      94
 * # 0x09, 0x30,                    //   Usage (X)                         96
 * # 0x09, 0x31,                    //   Usage (Y)                         98
 * # 0x95, 0x02,                    //   Report Count (2)                  100
 * # 0x75, 0x10,                    //   Report Size (16)                  102
 * # 0x16, 0x00, 0x80,              //   Logical Minimum (-32768)          104
 * # 0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           107
 * # 0x81, 0x06,                    //   Input (Data,Var,Rel)              110
 * # 0x09, 0x38,                    //   Usage (Wheel)                     112
 * # 0x15, 0x81,                    //   Logical Minimum (-127)            114
 * # 0x25, 0x7f,                    //   Logical Maximum (127)             116
 * # 0x95, 0x01,                    //   Report Count (1)                  118
 * # 0x75, 0x08,                    //   Report Size (8)                   120
 * # 0x81, 0x06,                    //   Input (Data,Var,Rel)              122
 * # 0x05, 0x0c,                    //   Usage Page (Consumer Devices)     124
 * # 0x0a, 0x38, 0x02,              //   Usage (AC Pan)                    126
 * # 0x95, 0x01,                    //   Report Count (1)                  129
 * # 0x75, 0x08,                    //   Report Size (8)                   131
 * # 0x81, 0x06,                    //   Input (Data,Var,Rel)              133
 * # 0xc0,                          //  End Collection                     135
 * # 0xc0,                          // End Collection                      136
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        137
 * # 0x09, 0x06,                    // Usage (Keyboard)                    139
 * # 0xa1, 0x01,                    // Collection (Application)            141
 * # 0x85, 0x06,                    //  Report ID (6)                      143
 * # 0x05, 0x07,                    //  Usage Page (Keyboard)              145
 * # 0x19, 0xe0,                    //  Usage Minimum (224)                147
 * # 0x29, 0xe7,                    //  Usage Maximum (231)                149
 * # 0x15, 0x00,                    //  Logical Minimum (0)                151
 * # 0x25, 0x01,                    //  Logical Maximum (1)                153
 * # 0x75, 0x01,                    //  Report Size (1)                    155
 * # 0x95, 0x08,                    //  Report Count (8)                   157
 * # 0x81, 0x02,                    //  Input (Data,Var,Abs)               159
 * # 0x05, 0x07,                    //  Usage Page (Keyboard)              161
 * # 0x19, 0x00,                    //  Usage Minimum (0)                  163
 * # 0x29, 0xff,                    //  Usage Maximum (255)                165
 * # 0x26, 0xff, 0x00,              //  Logical Maximum (255)              167
 * # 0x75, 0x08,                    //  Report Size (8)                    170
 * # 0x95, 0x06,                    //  Report Count (6)                   172
 * # 0x81, 0x00,                    //  Input (Data,Arr,Abs)               174
 * # 0xc0,                          // End Collection                      176
 * #
 * R: 177 05 01 09 02 a1 01 85 09 09 01 a1 00 05 09 19 01 29 03 15 00 25 01 95 03 75 01 81 02 95 05 81 01 05 01 09 30 09 31 26 ff 7f 95 02 75 10 81 02 05 0d 09 30 26 ff 07 95 01 75 10 81 02 c0 c0 05 01 09 02 a1 01 09 01 a1 00 85 01 05 09 19 01 29 05 95 05 75 01 15 00 25 01 81 02 95 03 81 01 05 01 09 30 09 31 95 02 75 10 16 00 80 26 ff 7f 81 06 09 38 15 81 25 7f 95 01 75 08 81 06 05 0c 0a 38 02 95 01 75 08 81 06 c0 c0 05 01 09 06 a1 01 85 06 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 05 07 19 00 29 ff 26 ff 00 75 08 95 06 81 00 c0
 * N: 11 inch PenTablet
 * I: 3 28bd 0904
 *
 * Key Layout:
 *
 * 1 2
 * 3 4
 *
 * 5 6
 * 7 8
 *
 * Key events:
 * Buttons released: 06 00 00 00 00 00 00 00
 * Button 1:         06 00 05 00 00 00 00 00 -> b
 * Button 2:         06 00 08 00 00 00 00 00 -> e
 * Button 3:         06 04 00 00 00 00 00 00 -> LAlt
 * Button 4:         06 00 2c 00 00 00 00 00 -> Space
 * Button 5:         06 00 19 00 00 00 00 00 -> v
 * Button 6:         06 01 16 00 00 00 00 00 -> LControl + s
 * Button 7:         06 01 1d 00 00 00 00 00 -> LControl + z
 * Button 8:         06 05 11 00 00 00 00 00 -> LControl + LAlt + n
 *
 * When multiple buttons are pressed at the same time, the values used to
 * identify the buttons are identical, but they appear in different bytes of the
 * record. For example, when button 2 (0x08) and button 1 (0x05) are pressed,
 * this is the report:
 *
 *   Buttons 2 and 1:  06 00 08 05 00 00 00 00 -> e + b
 *
 * Buttons 1, 2, 4, 5 and 6 can be matched by finding their values in the
 * report.
 *
 * Button 3 is pressed when the 3rd bit is 1. For example, pressing buttons 3
 * and 5 generates this report:
 *
 *   Buttons 3 and 5:  06 05 16 00 00 00 00 00 -> LControl + LAlt + s
 *                        -- --
 *                         |  |
 *                         |  `- Button 5 (0x16)
 *                         `- 0x05 = 0101. Button 3 is pressed
 *                                    ^
 *
 * pad_buttons contains a list of buttons that can be matched in
 * HID_BPF_DEVICE_EVENT. Button 3 as it has a dedicated bit.
 *
 *
 * DESCRIPTOR 1
 *
 * # 0x05, 0x0d,                    // Usage Page (Digitizers)             0
 * # 0x09, 0x02,                    // Usage (Pen)                         2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x85, 0x07,                    //  Report ID (7)                      6
 * # 0x09, 0x20,                    //  Usage (Stylus)                     8
 * # 0xa1, 0x00,                    //  Collection (Physical)              10
 * # 0x09, 0x42,                    //   Usage (Tip Switch)                12
 * # 0x09, 0x44,                    //   Usage (Barrel Switch)             14
 * # 0x09, 0x45,                    //   Usage (Eraser)                    16
 * # 0x15, 0x00,                    //   Logical Minimum (0)               18
 * # 0x25, 0x01,                    //   Logical Maximum (1)               20
 * # 0x75, 0x01,                    //   Report Size (1)                   22
 * # 0x95, 0x03,                    //   Report Count (3)                  24
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              26
 * # 0x95, 0x02,                    //   Report Count (2)                  28
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)              30
 * # 0x09, 0x32,                    //   Usage (In Range)                  32
 * # 0x95, 0x01,                    //   Report Count (1)                  34
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              36
 * # 0x95, 0x02,                    //   Report Count (2)                  38
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)              40
 * # 0x75, 0x10,                    //   Report Size (16)                  42
 * # 0x95, 0x01,                    //   Report Count (1)                  44
 * # 0x35, 0x00,                    //   Physical Minimum (0)              46
 * # 0xa4,                          //   Push                              48
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      49
 * # 0x09, 0x30,                    //   Usage (X)                         51
 * # 0x65, 0x13,                    //   Unit (EnglishLinear: in)          53
 * # 0x55, 0x0d,                    //   Unit Exponent (-3)                55
 * # 0x46, 0xe8, 0x2a,              //   Physical Maximum (10984)          57
 * # 0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           60
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              63
 * # 0x09, 0x31,                    //   Usage (Y)                         65
 * # 0x46, 0x25, 0x18,              //   Physical Maximum (6181)           67
 * # 0x26, 0xff, 0x7f,              //   Logical Maximum (32767)           70
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              73
 * # 0xb4,                          //   Pop                               75
 * # 0x09, 0x30,                    //   Usage (Tip Pressure)              76
 * # 0x45, 0x00,                    //   Physical Maximum (0)              78
 * # 0x26, 0xff, 0x1f,              //   Logical Maximum (8191)            80
 * # 0x81, 0x42,                    //   Input (Data,Var,Abs,Null)         83
 * # 0x09, 0x3d,                    //   Usage (X Tilt)                    85
 * # 0x15, 0x81,                    //   Logical Minimum (-127)            87 <- Change to -60
 * # 0x25, 0x7f,                    //   Logical Maximum (127)             89 <- Change to 60
 * # 0x75, 0x08,                    //   Report Size (8)                   91
 * # 0x95, 0x01,                    //   Report Count (1)                  93
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              95
 * # 0x09, 0x3e,                    //   Usage (Y Tilt)                    97
 * # 0x15, 0x81,                    //   Logical Minimum (-127)            99 <- Change to -60
 * # 0x25, 0x7f,                    //   Logical Maximum (127)             101 <- Change to 60
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              103
 * # 0xc0,                          //  End Collection                     105
 * # 0xc0,                          // End Collection                      106
 * #
 * R: 107 05 0d 09 02 a1 01 85 07 09 20 a1 00 09 42 09 44 09 45 15 00 25 01 75 01 95 03 81 02 95 02 81 03 09 32 95 01 81 02 95 02 81 03 75 10 95 01 35 00 a4 05 01 09 30 65 13 55 0d 46 e8 2a 26 ff 7f 81 02 09 31 46 25 18 26 ff 7f 81 02 b4 09 30 45 00 26 ff 1f 81 42 09 3d 15 81 25 7f 75 08 95 01 81 02 09 3e 15 81 25 7f 81 02 c0 c0
 * N: 11 inch PenTablet
 * I: 3 28bd 0904
 *
 */

#define PEN_REPORT_DESCRIPTOR_LENGTH 107
#define PAD_REPORT_DESCRIPTOR_LENGTH 177
#define PAD_DIAL_REPORT_ID 1
#define PAD_REPORT_LENGTH 8
#define PAD_REPORT_ID 6
#define PAD_NUM_BUTTONS 8

static const __u8 fixed_rdesc_pad[] = {
	UsagePage_GenericDesktop
	Usage_GD_Mouse
	CollectionApplication(
		ReportId(9)
		Usage_GD_Pointer
		CollectionPhysical(
			UsagePage_Button
			UsageMinimum_i8(1)
			UsageMaximum_i8(3)
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(1)
			ReportCount(3)
			ReportSize(1)
			Input(Var|Abs)
			ReportCount(5)
			Input(Const)
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			LogicalMaximum_i16(32767)
			ReportCount(2)
			ReportSize(16)
			Input(Var|Abs)
			UsagePage_Digitizers
			Usage_Dig_TipPressure
			LogicalMaximum_i16(2047)
			ReportCount(1)
			ReportSize(16)
			Input(Var|Abs)
		)
	)
	UsagePage_GenericDesktop
	Usage_GD_Mouse
	CollectionApplication(
		Usage_GD_Pointer
		CollectionPhysical(
			ReportId(1)
			UsagePage_Button
			UsageMinimum_i8(1)
			UsageMaximum_i8(5)
			ReportCount(5)
			ReportSize(1)
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(1)
			Input(Var|Abs)
			ReportCount(3)
			Input(Const)
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			ReportCount(2)
			ReportSize(16)
			LogicalMinimum_i16(-32768)
			LogicalMaximum_i16(32767)
			Input(Var|Rel)
			UsagePage_Consumer
			Usage_Con_ACPan
			ReportCount(1)
			ReportSize(8)
			Input(Var|Rel)
		)
	)
	UsagePage_GenericDesktop
	Usage_GD_Keyboard
	CollectionApplication(
		// Byte 0: Report ID
		ReportId(PAD_REPORT_ID)
		ReportCount(1)
		ReportSize(8)
		UsagePage_Digitizers
		Usage_Dig_TabletFunctionKeys
		CollectionPhysical(
			// Byte 1: Button State
			UsagePage_Button
			UsageMinimum_i8(1)
			UsageMaximum_i8(PAD_NUM_BUTTONS)
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(1)
			ReportCount(PAD_NUM_BUTTONS)
			ReportSize(1)
			Input(Var|Abs)
			// Byte 2: Dial
			UsagePage_GenericDesktop
			Usage_GD_Dial
			ReportCount(1)
			ReportSize(8)
			LogicalMinimum_i8(-1)
			LogicalMaximum_i8(1)
			Input(Var|Rel)
			// Byte 3: Exists to be a tablet pad
			UsagePage_Digitizers
			Usage_Dig_BarrelSwitch // BTN_STYLUS
			ReportCount(1)
			ReportSize(1)
			Input(Var|Abs)
			ReportCount(7) // padding
			Input(Const)
			// Bytes 4, 5: Exists to be a tablet pad
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			ReportCount(2)
			ReportSize(8)
			Input(Var|Abs)
			// Bytes 6, 7: Padding
			ReportCount(2)
			ReportSize(8)
			Input(Const)
		)
	)
};

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(xppen_decoprov1_rdesc_fixup, struct hid_bpf_ctx *hid_ctx)
{
	__u8 *data = hid_bpf_get_data(hid_ctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);
	__s32 rdesc_size = hid_ctx->size;

	const __u8 wrong_logical_range[] = { 0x15, 0x81, 0x25, 0x7f };
	const __u8 correct_logical_range[] = { 0x15, 0xc4, 0x25, 0x3c };

	if (!data)
		return 0; /* EPERM check */

	if (rdesc_size == PAD_REPORT_DESCRIPTOR_LENGTH) {
		__builtin_memcpy(data, fixed_rdesc_pad, sizeof(fixed_rdesc_pad));
		return sizeof(fixed_rdesc_pad);
	} else if (rdesc_size == PEN_REPORT_DESCRIPTOR_LENGTH) {
		// Fix tilt to -60/60
		if (__builtin_memcmp(&data[87], wrong_logical_range, sizeof(wrong_logical_range)) == 0)
			__builtin_memcpy(&data[87], correct_logical_range, sizeof(correct_logical_range));
		if (__builtin_memcmp(&data[99], wrong_logical_range, sizeof(wrong_logical_range)) == 0)
			__builtin_memcpy(&data[99], correct_logical_range, sizeof(correct_logical_range));
	}

	return 0;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(xppen_decoprov1_device_event, struct hid_bpf_ctx *hid_ctx)
{
	static const __u8 pad_buttons[] = { 0x05, 0x08, 0x00, 0x2c, 0x19, 0x16, 0x1d, 0x11 };
	__u8 *data = hid_bpf_get_data(hid_ctx, 0 /* offset */, PAD_REPORT_LENGTH /* size */);

	if (!data)
		return 0; /* EPERM check */

	__u8 report_id = data[0];
	__u8 button_mask = 0;
	__s8 pad_dial = 0;

	/*
	 * The reading for the dial is report ID 1 with byte 6 as clockwise/counter, no gradient.
	 * It is basically a mouse wheel but reporting it as a dial allows the user to determine
	 * which action they want to set it to in tablet settings, even if that is just making it
	 * a mouse wheel again.
	 *
	 * 01 00 00 00 00 00 (01) 00    clockwise
	 * 01 00 00 00 00 00 (ff) 00    counter-clockwise
	 *
	 * Setting the dial 1 for clockwise and -1 for counter clockwise.
	 */
	if (report_id == PAD_DIAL_REPORT_ID && data[6] != 0) {
		pad_dial = (data[6] == 0x01) ? 1 : -1;
		report_id = PAD_REPORT_ID;
	}

	if (report_id == PAD_REPORT_ID) {
		size_t d, b;

		/*
		 * Because Button 8 also includes LAlt, need to make sure that LControl
		 * is also not active otherwise both 3 and 8 will activate when 8 is pressed.
		 *
		 * But as a result, if holding down button 3 it will deactivate temporarily when
		 * 7 is pressed or toggle off when 8 is pressed.
		 *
		 * Given that there are two banks of buttons on top and bottom, this requires both
		 * hands or a really awkward hand position to achieve, so will likely not happen
		 * in regular use. Checking each button in a switch/case would prevent multiple
		 * buttons from being registered at once, which can be useful enough to leave as is.
		 */
		if (data[1] & BIT(2) && !(data[1] & BIT(0)))
			button_mask |= BIT(2);

		for (d = 2; d < 8; d++) {
			for (b = 0; b < sizeof(pad_buttons); b++) {
				if (data[d] != 0 && data[d] == pad_buttons[b])
					button_mask |= BIT(b);
			}
		}

		__u8 report[8] = { PAD_REPORT_ID, button_mask, pad_dial, 0x00 };

		__builtin_memcpy(data, report, sizeof(report));
	}

	return 0;
}

HID_BPF_OPS(xppen_decoprov1) = {
	.hid_rdesc_fixup = (void *)xppen_decoprov1_rdesc_fixup,
	.hid_device_event = (void *)xppen_decoprov1_device_event,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	switch (ctx->rdesc_size) {
	case PAD_REPORT_DESCRIPTOR_LENGTH:
	case PEN_REPORT_DESCRIPTOR_LENGTH:
		ctx->retval = 0;
		break;
	default:
		ctx->retval = -EINVAL;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
