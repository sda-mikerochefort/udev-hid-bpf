// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Xubai Wang
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_GAOMON 0x256C
#define PID_M6 0x0064

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_GAOMON, PID_M6),
);

/*
 * Filled in by udev-hid-bpf.
 * huion-switcher always uses HUION_FIRMWARE_ID, not GAOMON.
 */
char UDEV_PROP_HUION_FIRMWARE_ID[64];

/*
 * The device's magic bytes:
 *
 *       [LogicalMaximum, X]    [LogicalMaximum, Y]    [LogicalMaximum, Pressure] [  LPI]
 * 16 03 [            70 c6] 00 [            06 7c] 00 [                   ff 3f] [d8 13] 03 0d 10 01 04 3c 3e 08 01 00
 */

/**
 * The prefix of the firmware ID we expect for this device.
 * The full firmware id has a date suffix, e.g. GM001_T223_240315
 */
char EXPECTED_FIRMWARE_ID[] = "GM001_T223_";

/*
 * How the BPF program works: The tablet has two mode, firmware and tablet mode.
 * In firmware mode (default): only pen and left 12 buttons works, while ring
 * and the ring button does not. The buttons are encoded as keyboard combinations.
 * In tablet mode it use a vendor specific HID report to report everything instead.
 * The device have three interfaces, depending on the mode some interfaces are mute.
 *
 * To switch the tablet, userspace tools like https://github.com/whot/huion-switcher
 * can be used.
 *
 * This BPF works for both modes, but only tablet mode has access to ring and ring
 * button. If huion-switcher tool set the HUION_FIRMWARE_ID udev property, we can
 * disable the firmware pad and pen reports (by making them vendor collections).
 *
 * Default report descriptor for the first exposed hidraw mode:
 *
 * # GAOMON GAOMON_M6
 * # 0x06, 0x00, 0xff,              // Usage Page (Vendor Defined Page 1)  0
 * # 0x09, 0x01,                    // Usage (Vendor Usage 1)              3
 * # 0xa1, 0x01,                    // Collection (Application)            5
 * # 0x85, 0x08,                    //  Report ID (8)                      7
 * # 0x75, 0x58,                    //  Report Size (88)                   9
 * # 0x95, 0x01,                    //  Report Count (1)                   11
 * # 0x09, 0x01,                    //  Usage (Vendor Usage 1)             13
 * # 0x81, 0x02,                    //  Input (Data,Var,Abs)               15
 * # 0xc0,                          // End Collection                      17
 * # 0x06, 0x00, 0xff,              // Usage Page (Vendor Defined Page 1)  18
 * # 0x09, 0x01,                    // Usage (Vendor Usage 1)              21
 * # 0xa1, 0x01,                    // Collection (Application)            23
 * # 0x85, 0x16,                    //  Report ID (22)                     25
 * # 0x75, 0x08,                    //  Report Size (8)                    27
 * # 0x95, 0x07,                    //  Report Count (7)                   29
 * # 0x09, 0x01,                    //  Usage (Vendor Usage 1)             31
 * # 0xb1, 0x02,                    //  Feature (Data,Var,Abs)             33
 * # 0xc0,                          // End Collection                      35
 * #
 * R: 36 06 00 ff 09 01 a1 01 85 08 75 58 95 01 09 01 81 02 c0 06 00 ff 09 01 a1 01 85 16 75 08 95 07 09 01 b1 02 c0
 *
 * This rdesc does nothing until the tablet is switched to raw mode.
 *
 *
 * Second hidraw node is the Pen. This one sends events until the tablet is
 * switched to rw mode, then it's mute.
 *
 * # GAOMON GAOMON_M6
 * # 0x05, 0x0d,                    // Usage Page (Digitizers)             0
 * # 0x09, 0x02,                    // Usage (Pen)                         2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x85, 0x0a,                    //  Report ID (10)                     6
 * # 0x09, 0x20,                    //  Usage (Stylus)                     8
 * # 0xa1, 0x01,                    //  Collection (Application)           10
 * # 0x09, 0x42,                    //   Usage (Tip Switch)                12
 * # 0x09, 0x44,                    //   Usage (Barrel Switch)             14
 * # 0x09, 0x43,                    //   Usage (Secondary Tip Switch)      16
 * # 0x09, 0x3c,                    //   Usage (Invert)                    18
 * # 0x09, 0x45,                    //   Usage (Eraser)                    20
 * # 0x15, 0x00,                    //   Logical Minimum (0)               22
 * # 0x25, 0x01,                    //   Logical Maximum (1)               24
 * # 0x75, 0x01,                    //   Report Size (1)                   26
 * # 0x95, 0x06,                    //   Report Count (6)                  28
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              30
 * # 0x09, 0x32,                    //   Usage (In Range)                  32
 * # 0x75, 0x01,                    //   Report Size (1)                   34
 * # 0x95, 0x01,                    //   Report Count (1)                  36
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              38
 * # 0x81, 0x03,                    //   Input (Cnst,Var,Abs)              40
 * # 0x05, 0x01,                    //   Usage Page (Generic Desktop)      42
 * # 0xa4,                          //   Push                              44
 * # 0x09, 0x30,                    //   Usage (X)                         45
 * # 0x55, 0x0d,                    //   Unit Exponent (-3)                47
 * # 0x65, 0x13,                    //   Unit (EnglishLinear: in)          49
 * # 0x35, 0x00,                    //   Physical Minimum (0)              51
 * # 0x46, 0x10, 0x27,              //   Physical Maximum (10000)          53
 * # 0x27, 0x70, 0xc6, 0x00, 0x00,  //   Logical Maximum (50800)           56
 * # 0x75, 0x10,                    //   Report Size (16)                  61
 * # 0x95, 0x01,                    //   Report Count (1)                  63
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              65
 * # 0x09, 0x31,                    //   Usage (Y)                         67
 * # 0x55, 0x0d,                    //   Unit Exponent (-3)                69
 * # 0x65, 0x13,                    //   Unit (EnglishLinear: in)          71
 * # 0x35, 0x00,                    //   Physical Minimum (0)              73
 * # 0x46, 0x6a, 0x18,              //   Physical Maximum (6250)           75
 * # 0x27, 0x06, 0x7c, 0x00, 0x00,  //   Logical Maximum (31750)           78
 * # 0x75, 0x10,                    //   Report Size (16)                  83
 * # 0x95, 0x01,                    //   Report Count (1)                  85
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              87
 * # 0xb4,                          //   Pop                               89
 * # 0x05, 0x0d,                    //   Usage Page (Digitizers)           90
 * # 0x09, 0x30,                    //   Usage (Tip Pressure)              92
 * # 0x26, 0xff, 0x3f,              //   Logical Maximum (16383)           94
 * # 0x75, 0x10,                    //   Report Size (16)                  97
 * # 0x95, 0x01,                    //   Report Count (1)                  99
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              101
 * # 0x09, 0x3d,                    //   Usage (X Tilt)                    103
 * # 0x09, 0x3e,                    //   Usage (Y Tilt)                    105
 * # 0x15, 0x81,                    //   Logical Minimum (-127)            107
 * # 0x25, 0x7f,                    //   Logical Maximum (127)             109
 * # 0x75, 0x08,                    //   Report Size (8)                   111
 * # 0x95, 0x02,                    //   Report Count (2)                  113
 * # 0x81, 0x02,                    //   Input (Data,Var,Abs)              115
 * # 0xc0,                          //  End Collection                     117
 * # 0xc0,                          // End Collection                      118
 * #
 * R: 119 05 0d 09 02 a1 01 85 0a 09 20 a1 01 09 42 09 44 09 43 09 3c 09 45 15 00 25 01 75 01 95 06 81 02 09 32 75 01 95 01 81 02 81 03 05 01 a4 09 30 55 0d 65 13 35 00 46 10 27 27 70 c6 00 00 75 10 95 01 81 02 09 31 55 0d 65 13 35 00 46 6a 18 27 06 7c 00 00 75 10 95 01 81 02 b4 05 0d 09 30 26 ff 3f 75 10 95 01 81 02 09 3d 09 3e 15 81 25 7f 75 08 95 02 81 02 c0 c0
 *
 *
 * Third hidraw mode is the pad which sends a combination of keyboard shortcuts until
 * the tablet is switched to raw mode, then it's mute:
 *
 * # GAOMON GAOMON_M6
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
 * # 0x09, 0x06,                    // Usage (Keyboard)                    2
 * # 0xa1, 0x01,                    // Collection (Application)            4
 * # 0x85, 0x03,                    //  Report ID (3)                      6
 * # 0x05, 0x07,                    //  Usage Page (Keyboard)              8
 * # 0x19, 0xe0,                    //  Usage Minimum (224)                10
 * # 0x29, 0xe7,                    //  Usage Maximum (231)                12
 * # 0x15, 0x00,                    //  Logical Minimum (0)                14
 * # 0x25, 0x01,                    //  Logical Maximum (1)                16
 * # 0x75, 0x01,                    //  Report Size (1)                    18
 * # 0x95, 0x08,                    //  Report Count (8)                   20
 * # 0x81, 0x02,                    //  Input (Data,Var,Abs)               22
 * # 0x05, 0x07,                    //  Usage Page (Keyboard)              24
 * # 0x19, 0x00,                    //  Usage Minimum (0)                  26
 * # 0x29, 0xff,                    //  Usage Maximum (255)                28
 * # 0x26, 0xff, 0x00,              //  Logical Maximum (255)              30
 * # 0x75, 0x08,                    //  Report Size (8)                    33
 * # 0x95, 0x06,                    //  Report Count (6)                   35
 * # 0x81, 0x00,                    //  Input (Data,Arr,Abs)               37
 * # 0xc0,                          // End Collection                      39
 * # 0x05, 0x0c,                    // Usage Page (Consumer Devices)       40
 * # 0x09, 0x01,                    // Usage (Consumer Control)            42
 * # 0xa1, 0x01,                    // Collection (Application)            44
 * # 0x85, 0x04,                    //  Report ID (4)                      46
 * # 0x19, 0x01,                    //  Usage Minimum (1)                  48
 * # 0x2a, 0x9c, 0x02,              //  Usage Maximum (668)                50
 * # 0x15, 0x01,                    //  Logical Minimum (1)                53
 * # 0x26, 0x9c, 0x02,              //  Logical Maximum (668)              55
 * # 0x95, 0x01,                    //  Report Count (1)                   58
 * # 0x75, 0x10,                    //  Report Size (16)                   60
 * # 0x81, 0x00,                    //  Input (Data,Arr,Abs)               62
 * # 0xc0,                          // End Collection                      64
 * # 0x05, 0x01,                    // Usage Page (Generic Desktop)        65
 * # 0x09, 0x80,                    // Usage (System Control)              67
 * # 0xa1, 0x01,                    // Collection (Application)            69
 * # 0x85, 0x05,                    //  Report ID (5)                      71
 * # 0x19, 0x81,                    //  Usage Minimum (129)                73
 * # 0x29, 0x83,                    //  Usage Maximum (131)                75
 * # 0x15, 0x00,                    //  Logical Minimum (0)                77
 * # 0x25, 0x01,                    //  Logical Maximum (1)                79
 * # 0x75, 0x01,                    //  Report Size (1)                    81
 * # 0x95, 0x03,                    //  Report Count (3)                   83
 * # 0x81, 0x02,                    //  Input (Data,Var,Abs)               85
 * # 0x95, 0x05,                    //  Report Count (5)                   87
 * # 0x81, 0x01,                    //  Input (Cnst,Arr,Abs)               89
 * # 0xc0,                          // End Collection                      91
 * #
 * R: 92 05 01 09 06 a1 01 85 03 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 05 07 19 00 29 ff 26 ff 00 75 08 95 06 81 00 c0 05 0c 09 01 a1 01 85 04 19 01 2a 9c 02 15 01 26 9c 02 95 01 75 10 81 00 c0 05 01 09 80 a1 01 85 05 19 81 29 83 15 00 25 01 75 01 95 03 81 02 95 05 81 01 c0
 */

#define VENDOR_DESCRIPTOR_LENGTH 36
#define PEN_DESCRIPTOR_LENGTH 119
#define PAD_DESCRIPTOR_LENGTH 92

#define VENDOR_REPORT_ID 8
#define VENDOR_REPORT_LENGTH 12

/*
 * VENDOR MODE
 *
 *	report_subtype = (data[1] >> 4) & 0x0f
 *
 *	REPORT SUBTYPES
 *		0x0e	Buttons
 *			(data[4] & 0x01)*	button 1 (top ring button)
 *			(data[4] & 0x02)	button 2
 *			(data[4] & 0x04)	button 3
 *			(data[4] & 0x08)	button 4
 *			(data[4] & 0x10)	button 5
 *			(data[4] & 0x20)	button 6
 *			(data[4] & 0x40)	button 7
 *			(data[4] & 0x80)	button 8
 *			(data[5] & 0x01)	button 9
 *			(data[5] & 0x02)	button 10
 *			(data[5] & 0x04)	button 11
 *			(data[5] & 0x08)	button 12
 *			(data[5] & 0x10)	button 13
 *
 *			The order of button 2-13 is row major (first from
 *			left to right, then top to bottom).
 *
 *			All tablet buttons release with the same report (last
 *			two bytes may be affected by previous pen tilt):
				08 e0 01 01 00 00 00 00 00 00 00 00
 *
 *		0x0f	Ring (counter-clockwise)
 *			(data[5] & 0x01)	position 1 (top)
 *			(data[5] & 0x02)	position 2
 *			(data[5] & 0x03)	position 3
 *			(data[5] & 0x04)	position 4
 *			(data[5] & 0x05)	position 5
 *			(data[5] & 0x06)	position 6
 *			(data[5] & 0x07)	position 7
 *			(data[5] & 0x08)	position 8
 *			(data[5] & 0x09)	position 9
 *			(data[5] & 0x0a)	position 10
 *			(data[5] & 0x0b)	position 11
 *			(data[5] & 0x0c)	position 12
 *
 *			All position release with the same report (last
 *			two bytes may be affected by previous pen tilt):
 *				08 f0 01 01 00 00 00 00 00 00 00 00
 *
 *		0x08/0x00	Pen
 *			report_subtype == 0x08:	in-range
 *			report_subtype == 0x00:	out-of-range
 *
 *			Switches:
 *
 *			(data[1] & 0x01)	tip switch
 *			(data[1] & 0x02)	barrel switch
 *			(data[1] & 0x04)	secondary barrel switch
 *
 *			The pen does not have eraser or invert.
 *
 *			data[2], data[3]	X (little-endian, maxium 0xc670)
 *			data[4], data[5]	Y (little-endian, maxium 0x7c06)
 *			data[6], data[7]	Pressure (little-endian, maxium 0x3fff)
 *			data[10]		X tilt (signed, -60 to +60)
 *			data[11]		Y tilt (signed, -60 to +60)
 */

#define VENDOR_REPORT_SUBTYPE_PEN 0x08
#define VENDOR_REPORT_SUBTYPE_PEN_OUT 0x00
#define VENDOR_REPORT_SUBTYPE_BUTTONS 0x0e
#define VENDOR_REPORT_SUBTYPE_WHEELS 0x0f

#define CUSTOM_PAD_REPORT_ID 9

static const __u8 fixed_rdesc_vendor[] = {
	/* Pen Collection */
	UsagePage_Digitizers
	Usage_Dig_Pen
	CollectionApplication(
		ReportId(VENDOR_REPORT_ID)
		UsagePage_Digitizers
		Usage_Dig_Pen
		CollectionPhysical(
			/* byte 1: switches + padding + in_range */
			/* switches */
			ReportSize(1)
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(1)
			ReportCount(3)
			Usage_Dig_TipSwitch
			Usage_Dig_BarrelSwitch
			Usage_Dig_SecondaryBarrelSwitch
			Input(Var|Abs)
			/* padding */
			ReportCount(4)
			Input(Const)
			/* in range */
			ReportCount(1)
			Usage_Dig_InRange
			Input(Var|Abs)
			/* bytes 2-5: x y */
			ReportSize(16)
			ReportCount(1)
			PushPop(
				UsagePage_GenericDesktop
				Unit(cm)
				UnitExponent(-3)
				LogicalMinimum_i16(0)
				PhysicalMinimum_i16(0)
				/*
				 * This tablet has a logical maximum of 50800 x 31750
				 * and physical maxium 254 x 158.75 mm.
				 */
				/* X */
				LogicalMaximum_i16(50800)
				PhysicalMaximum_i16(25400)
				Usage_GD_X
				Input(Var|Abs)
				/* Y */
				LogicalMaximum_i16(31750)
				PhysicalMaximum_i16(15875)
				Usage_GD_Y
				Input(Var|Abs)
			)
			/* bytes 6-7: pressure */
			LogicalMinimum_i16(0)
			LogicalMaximum_i16(16383)
			Usage_Dig_TipPressure
			Input(Var|Abs)
			/* byte 8-9: padding */
			ReportCount(1)
			Input(Const)
			/* byte 10-11: tilt */
			ReportSize(8)
			ReportCount(2)
			PushPop(
				Unit(deg)
				UnitExponent(0)
				LogicalMinimum_i8(-60)
				PhysicalMinimum_i8(-60)
				LogicalMaximum_i8(60)
				PhysicalMaximum_i8(60)
				Usage_Dig_XTilt
				Usage_Dig_YTilt
				Input(Var|Abs)
			)
		)
	)
	/* Pad Collection */
	UsagePage_GenericDesktop
	Usage_GD_Keypad
	CollectionApplication(
		ReportId(CUSTOM_PAD_REPORT_ID)
		LogicalMinimum_i8(0)
		LogicalMaximum_i8(1)
		UsagePage_Digitizers
		Usage_Dig_TabletFunctionKeys
		CollectionPhysical(
			/* byte 1: barrel switch + padding (vestigial) */
			ReportSize(1)
			ReportCount(1)
			Usage_Dig_BarrelSwitch
			Input(Var|Abs)
			ReportCount(7)
			Input(Const)
			/* bytes 2-3: X/Y dummy (vestigial) */
			ReportSize(8)
			ReportCount(2)
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			Input(Var|Abs)
			/* byte 4-5: buttons 0-9, 10-12 */
			ReportSize(1)
			ReportCount(10)
			UsagePage_Button
			UsageMinimum_i8(1)
			UsageMaximum_i8(10)
			Input(Var|Abs)
			ReportCount(3)
			UsagePage_Button
			UsageMinimum_i8(0x31)
			UsageMaximum_i8(0x33)
			Input(Var|Abs)
			// ReportCount(3)
			Input(Const)
			/* byte 6: ring (abs wheel) */
			ReportSize(4)
			ReportCount(1)
			UsagePage_GenericDesktop
			Usage_GD_Wheel
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(11)
			Input(Var|Abs)
			/* ABS_MISC terminator */
			UsagePage_Digitizers
			Usage_Dig_ScanTime
			LogicalMinimum_i8(0)
			LogicalMaximum_i8(15)
			Input(Var|Abs)
		)
		FixedSizeVendorReport(VENDOR_REPORT_LENGTH)
	)
};

static const __u8 disabled_rdesc_pen[] = {
	FixedSizeVendorReport(10)
};

static const __u8 disabled_rdesc_pad[] = {
	FixedSizeVendorReport(8)
};

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(hid_fix_rdesc_gaomon_m6, struct hid_bpf_ctx *hid_ctx)
{
	__u8 *data = hid_bpf_get_data(hid_ctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);
	__s32 rdesc_size = hid_ctx->size;
	__u8 have_fw_id;

	if (!data)
		return 0;

	have_fw_id = __builtin_memcmp(UDEV_PROP_HUION_FIRMWARE_ID,
					EXPECTED_FIRMWARE_ID,
					sizeof(EXPECTED_FIRMWARE_ID) - 1) == 0;
	if (have_fw_id) {
		/* Disable unused pen and pad in vendor mode */
		if (rdesc_size == PEN_DESCRIPTOR_LENGTH) {
			__builtin_memcpy(data, disabled_rdesc_pen,
					 sizeof(disabled_rdesc_pen));
			return sizeof(disabled_rdesc_pen);
		}
		if (rdesc_size == PAD_DESCRIPTOR_LENGTH) {
			__builtin_memcpy(data, disabled_rdesc_pad,
					 sizeof(disabled_rdesc_pad));
			return sizeof(disabled_rdesc_pad);
		}
	}

	/* Always fix vendor descriptor in case udev property is not set. */
	if (rdesc_size == VENDOR_DESCRIPTOR_LENGTH) {
		__builtin_memcpy(data, fixed_rdesc_vendor, sizeof(fixed_rdesc_vendor));
		return sizeof(fixed_rdesc_vendor);
	}

	return 0;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(hid_fix_event_gaomon_m6, struct hid_bpf_ctx *hid_ctx)
{
	__u8 *data = hid_bpf_get_data(hid_ctx, 0 /* offset */, VENDOR_REPORT_LENGTH /* size */);

	if (!data)
		return 0;

	/* Handle vendor reports only */
	if (hid_ctx->size != VENDOR_REPORT_LENGTH)
		return 0;
	if (data[0] != VENDOR_REPORT_ID)
		return 0;

	__u8 report_subtype = (data[1] >> 4) & 0x0f;

	if (report_subtype == VENDOR_REPORT_SUBTYPE_PEN ||
	    report_subtype == VENDOR_REPORT_SUBTYPE_PEN_OUT) {
		/* Invert Y tilt */
		data[11] = -data[11];
	} else if (report_subtype == VENDOR_REPORT_SUBTYPE_BUTTONS ||
		   report_subtype == VENDOR_REPORT_SUBTYPE_WHEELS) {
		struct pad_report {
			__u8 report_id;
			__u8 btn_stylus;
			__u8 x;
			__u8 y;
			__u8 buttons_low;
			__u8 buttons_high;
			__u8 wheel:4;
			__u8 wheel_misc:4;
		} __packed * pad_report;

		pad_report = (struct pad_report *)data;
		pad_report->report_id = CUSTOM_PAD_REPORT_ID;
		pad_report->btn_stylus = 0;
		pad_report->x = 0;
		pad_report->y = 0;

		switch (report_subtype) {
		case VENDOR_REPORT_SUBTYPE_WHEELS:
			__u8 raw = data[5] & 0x0f;

			if (raw > 0) {
				/*
				 * libinput normalize all as wacom which use left as zero,
				 * while this tablet use top as zero, counter-clockwise.
				 * After libinput fix this: (13 - raw) should be used
				 */
				pad_report->wheel = (15 - raw) % 12;
				pad_report->wheel_misc = 15;
			} else {
				pad_report->wheel = 0;
				pad_report->wheel_misc = 0;
			}
			pad_report->buttons_low = 0;
			pad_report->buttons_high = 0;
			break;

		case VENDOR_REPORT_SUBTYPE_BUTTONS:
			pad_report->buttons_low = data[4];
			pad_report->buttons_high = data[5] & 0x1f;
			pad_report->wheel = 0;
			pad_report->wheel_misc = 0;
			break;
		}

		return sizeof(struct pad_report);
	}

	return 0;
}

HID_BPF_OPS(gaomon_m6) = {
	.hid_device_event = (void *)hid_fix_event_gaomon_m6,
	.hid_rdesc_fixup = (void *)hid_fix_rdesc_gaomon_m6,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	switch (ctx->rdesc_size) {
	case VENDOR_DESCRIPTOR_LENGTH:
	case PEN_DESCRIPTOR_LENGTH:
	case PAD_DESCRIPTOR_LENGTH:
		ctx->retval = 0;
		break;
	default:
		ctx->retval = -EINVAL;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
