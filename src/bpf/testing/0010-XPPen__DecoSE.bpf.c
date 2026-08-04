// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Yangtse Su
 *
 * XP-Pen Deco SE (VID 0x28BD, PID 0x0949) is the same hardware family as
 * the XP-Pen Deco 01 V3 (0x0947): it exposes three HID interfaces, the
 * pad report descriptor (100 or 102 bytes, see below) and the pen report
 * descriptor (109 bytes) share the exact layout of the Deco 01 V3 ones,
 * and the pad buttons are reported as keyboard key sequences on report
 * ID 6.
 *
 * The same hardware is likely sold as the XP-Pen Deco mini7W V2
 * (Bluetooth 5.0 plus USB-C, 178x111 mm active area, eight side keys):
 * that model's specifications match this device exactly.
 *
 * The tablet is dual-mode. In the default mode (cold boot and Bluetooth)
 * the first interface carries a bogus absolute "Mouse" collection
 * (report 9, which is never sent) plus a keyboard collection (report 6)
 * carrying the pad button key sequences; the kernel exposes a phantom
 * mouse and a keyboard. The fixup replaces the descriptor with a tablet
 * pad descriptor (see below), and HID_BPF_DEVICE_EVENT converts the key
 * sequences back into a pad button bitmap so the buttons can be mapped
 * in the desktop environment (e.g. gnome-control-center), exactly like
 * the Deco 01 V3 implementation. After a USB/BT re-enumeration cycle the
 * device switches to a clean mode where the first interface already
 * reports the pad as tablet function keys (68-byte descriptor); probe()
 * rejects the 68-byte descriptor by size so this program only acts on the
 * default mode. In clean mode the pen may already carry the corrected
 * tilt range (as the Deco 01 V3 does); either way the pen fixup below
 * patches the +/-127 range only when it is actually present.
 *
 * Over Bluetooth the tablet exposes a single HID interface (211-byte
 * descriptor) that merges all three collections: the bogus absolute
 * "Mouse" (report 9), the keyboard carrying the pad button key sequences
 * (report 6) and the pen (report 7, with the same wrong +/-127 tilt
 * range). The merged descriptor is the default-mode pad descriptor
 * (102-byte variant) directly followed by the pen descriptor
 * (211 = 102 + 109). probe() accepts this size and the fixup replaces
 * the merged descriptor with the fixed pad descriptor followed by the
 * fixed pen descriptor, after checking that the layout really is
 * pad-then-pen.
 *
 * The pad report descriptor, see
 * https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/issues/54
 *
 * Recorded pad button reports (top to bottom, single press):
 *   Buttons released: 06 00 00 00 00 00 00 00
 *   Button 1:         06 00 05 00 00 00 00 00 -> b
 *   Button 2:         06 00 08 00 00 00 00 00 -> e
 *   Button 3:         06 04 00 00 00 00 00 00 -> LAlt
 *   Button 4:         06 00 2c 00 00 00 00 00 -> Space
 *   Button 5:         06 01 16 00 00 00 00 00 -> LControl + s
 *   Button 6:         06 01 1d 00 00 00 00 00 -> LControl + z
 *   Button 7:         06 01 57 00 00 00 00 00 -> LControl + Keypad Plus
 *   Button 8:         06 01 56 00 00 00 00 00 -> LControl + Keypad Dash
 *
 * When multiple buttons are pressed at the same time, the values used to
 * identify the buttons are identical, but they appear in different bytes
 * of the record. For example, when button 2 (0x08) and button 1 (0x05)
 * are pressed, this is the report:
 *
 *   Buttons 2 and 1:  06 00 08 05 00 00 00 00 -> e + b
 *
 * Buttons 1, 2, 4, 5 and 6 can be matched by finding their values in the
 * report.
 *
 * Button 3 is pressed when the 3rd bit is 1. For example, pressing
 * buttons 3 and 5 generates this report:
 *
 *   Buttons 3 and 5:  06 05 16 00 00 00 00 00 -> LControl + LAlt + s
 *                        -- --
 *                         |  |
 *                         |  `- Button 5 (0x16)
 *                         `- 0x05 = 0101. Button 3 is pressed
 *                                    ^
 *
 * pad_buttons contains the buttons matched by value in HID_BPF_DEVICE_EVENT.
 * Button 3 is not in that list because it has a dedicated bit in data[1].
 *
 * The pen has two side buttons: the one closer to the tip reports the
 * Barrel Switch (usage 0x44 -> BTN_STYLUS, i.e. right-click), the one
 * further from the tip reports the Eraser/Invert bits (usages 0x45/0x3c
 * -> BTN_TOOL_RUBBER, i.e. the eraser tool). This is firmware behavior
 * and is intentionally left as is.
 *
 * The pen report descriptor announces a wrong tilt range of +/-127 while
 * the device only ever sends values within +/-60, so libinput would scale
 * tilt down unnecessarily. Patch the logical range to +/-60.
 *
 * The third interface is a vendor-specific one (usage page 0xFF0A,
 * 36 bytes) that periodically reports battery status and also declares
 * a 13-byte output report (report ID 2) of unknown purpose; it is not
 * used by this program and the probe() function rejects it by size.
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_UGEE 0x28BD /* VID is shared with SinoWealth and Glorious and probably others */
#define PID_DECO_SE 0x0949

#define PEN_REPORT_DESCRIPTOR_LENGTH 109
/* The default-mode pad descriptor comes in two variants: 100 and
 * 102 bytes (the latter declares the Y axis of the bogus mouse).
 * The fixup replaces the whole descriptor, so both are accepted.
 */
#define PAD_REPORT_DESCRIPTOR_LENGTH 100
#define PAD_REPORT_DESCRIPTOR_LENGTH_V2 102
#define BT_REPORT_DESCRIPTOR_LENGTH 211
#define PAD_REPORT_LENGTH 8
#define PAD_REPORT_ID 6
#define PAD_NUM_BUTTONS 8

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_UGEE, PID_DECO_SE),
	HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_GENERIC, VID_UGEE, PID_DECO_SE),
);

/* Fixed pad descriptor: a tablet pad on report ID 6, one byte holding
 * the eight button states, followed by padding bytes and fake axes so
 * that the report length (8 bytes) matches what the firmware sends and
 * the kernel exposes a tablet pad that libinput/GNOME can configure.
 */
static const __u8 fixed_rdesc_pad[] = {
	UsagePage_GenericDesktop
	Usage_GD_Keypad
	CollectionApplication(
		// Byte 0 in report is the report ID
		ReportId(PAD_REPORT_ID)
		ReportCount(1)
		ReportSize(8)
		UsagePage_Digitizers
		Usage_Dig_TabletFunctionKeys
		CollectionPhysical(
			// Byte 1 is the button state
			UsagePage_Button
			UsageMinimum_i8(0x01)
			UsageMaximum_i8(PAD_NUM_BUTTONS)
			LogicalMinimum_i8(0x0)
			LogicalMaximum_i8(0x1)
			ReportCount(PAD_NUM_BUTTONS)
			ReportSize(1)
			Input(Var|Abs)
			// Byte 2 in report - just exists so we get to be a tablet pad
			UsagePage_Digitizers
			Usage_Dig_BarrelSwitch // BTN_STYLUS
			ReportCount(1)
			ReportSize(1)
			Input(Var|Abs)
			ReportCount(7) // padding
			Input(Const)
			// Bytes 3/4 in report - just exists so we get to be a tablet pad
			UsagePage_GenericDesktop
			Usage_GD_X
			Usage_GD_Y
			ReportCount(2)
			ReportSize(8)
			Input(Var|Abs)
			// Byte 5-7 are padding so we match the original report length
			ReportCount(3)
			ReportSize(8)
			Input(Const)
		)
	)
};

/* The pen descriptor with the tilt logical range already corrected to
 * +/-60. It is used as the pen part of the Bluetooth merged descriptor
 * (the BT descriptor carries the wrong +/-127 range).
 */
static const __u8 fixed_rdesc_pen[] = {
	0x05, 0x0d, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x07, 0x09, 0x20, 0xa1, 0x01,
	0x09, 0x42, 0x09, 0x44, 0x09, 0x45, 0x09, 0x3c, 0x15, 0x00, 0x25, 0x01,
	0x75, 0x01, 0x95, 0x04, 0x81, 0x02, 0x95, 0x01, 0x81, 0x03, 0x09, 0x32,
	0x95, 0x01, 0x81, 0x02, 0x95, 0x02, 0x81, 0x03, 0x75, 0x10, 0x95, 0x01,
	0x35, 0x00, 0xa4, 0x05, 0x01, 0x09, 0x30, 0x65, 0x13, 0x55, 0x0d, 0x46,
	0x5f, 0x1b, 0x26, 0x85, 0x45, 0x81, 0x02, 0x09, 0x31, 0x46, 0x16, 0x11,
	0x26, 0x65, 0x2b, 0x81, 0x02, 0xb4, 0x09, 0x30, 0x45, 0x00, 0x26, 0xff,
	0x3f, 0x81, 0x42, 0x09, 0x3d, 0x15, 0xc4, 0x25, 0x3c, 0x75, 0x08, 0x95,
	0x01, 0x81, 0x02, 0x09, 0x3e, 0x15, 0xc4, 0x25, 0x3c, 0x81, 0x02, 0xc0,
	0xc0,
};

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(xppen_decose_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);

	const __u8 wrong_logical_range[] = {0x15, 0x81, 0x25, 0x7f};
	const __u8 correct_logical_range[] = {0x15, 0xc4, 0x25, 0x3c};

	if (!data)
		return 0; /* EPERM check */

	switch (hctx->size) {
	case PAD_REPORT_DESCRIPTOR_LENGTH:
	case PAD_REPORT_DESCRIPTOR_LENGTH_V2:
		__builtin_memcpy(data, fixed_rdesc_pad, sizeof(fixed_rdesc_pad));
		return sizeof(fixed_rdesc_pad);
	case BT_REPORT_DESCRIPTOR_LENGTH:
		/* The merged descriptor is the 102-byte pad descriptor
		 * directly followed by the pen descriptor. Do not
		 * replace it unless the layout really is pad-then-pen:
		 * check the pen report ID (0x85 0x07 at offset
		 * 102 + 6) and the wrong tilt range (at offsets
		 * 102 + 89 and 102 + 101).
		 */
		if (__builtin_memcmp(&data[108], (const __u8[]){0x85, 0x07}, 2) != 0 ||
		    __builtin_memcmp(&data[191], wrong_logical_range,
				     sizeof(wrong_logical_range)) != 0 ||
		    __builtin_memcmp(&data[203], wrong_logical_range,
				     sizeof(wrong_logical_range)) != 0)
			break;
		__builtin_memcpy(data, fixed_rdesc_pad, sizeof(fixed_rdesc_pad));
		__builtin_memcpy(data + sizeof(fixed_rdesc_pad), fixed_rdesc_pen,
				 sizeof(fixed_rdesc_pen));
		return sizeof(fixed_rdesc_pad) + sizeof(fixed_rdesc_pen);
	case PEN_REPORT_DESCRIPTOR_LENGTH:
		if (__builtin_memcmp(&data[89], wrong_logical_range,
				     sizeof(wrong_logical_range)) == 0)
			__builtin_memcpy(&data[89], correct_logical_range,
					 sizeof(correct_logical_range));
		if (__builtin_memcmp(&data[101], wrong_logical_range,
				     sizeof(wrong_logical_range)) == 0)
			__builtin_memcpy(&data[101], correct_logical_range,
					 sizeof(correct_logical_range));
		break;
	}

	return 0;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(xppen_decose_device_event, struct hid_bpf_ctx *hctx)
{
	static const __u8 pad_buttons[] = { 0x05, 0x08, 0x00, 0x2c, 0x16, 0x1d, 0x57, 0x56 };
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, PAD_REPORT_LENGTH /* size */);

	if (!data)
		return 0; /* EPERM check */

	if (data[0] == PAD_REPORT_ID) {
		__u8 button_mask = 0;
		size_t d, b;

		/* data[1] stores the status of Button 3 in the 3rd bit */
		if (data[1] & BIT(2))
			button_mask |= BIT(2);

		/* The rest of the report stores the buttons as in pad_buttons */
		for (d = 2; d < 8; d++) {
			for (b = 0; b < sizeof(pad_buttons); b++) {
				if (data[d] != 0 && data[d] == pad_buttons[b])
					button_mask |= BIT(b);
			}
		}

		__u8 report[8] = {PAD_REPORT_ID, button_mask, 0x00};

		__builtin_memcpy(data, report, sizeof(report));
	}
	return 0;
}

HID_BPF_OPS(xppen_decose) = {
	.hid_rdesc_fixup = (void *)xppen_decose_rdesc_fixup,
	.hid_device_event = (void *)xppen_decose_device_event,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	switch (ctx->rdesc_size) {
	case PAD_REPORT_DESCRIPTOR_LENGTH:
	case PAD_REPORT_DESCRIPTOR_LENGTH_V2:
	case BT_REPORT_DESCRIPTOR_LENGTH:
	case PEN_REPORT_DESCRIPTOR_LENGTH:
		ctx->retval = 0;
		break;
	default:
		ctx->retval = -EINVAL;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
