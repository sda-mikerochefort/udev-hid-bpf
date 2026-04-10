// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Shi Lecun
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include "hid_usages.h"
#include <bpf/bpf_tracing.h>

#define VID_MICRODIA 0x0C45
#define PID_M60_WIRED 0x8032
#define PID_M60_DONGLE 0xFEFE
#define PID_M60_BLE 0xFEFE // Intentionally the same PID with dongle

// The device has three connection modes: wired, 2.4G dongle, and BLE.
HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_MICRODIA, PID_M60_WIRED),
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_MICRODIA, PID_M60_DONGLE),
	HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_GENERIC, VID_MICRODIA, PID_M60_BLE)
);

enum aula_connect_mode {
	AULA_CONNECT_MODE_INVALID = -1,
	AULA_CONNECT_MODE_WIRED = 0,
	AULA_CONNECT_MODE_DONGLE = 1,
	AULA_CONNECT_MODE_BLE = 2,
};

static inline enum aula_connect_mode connect_mode(struct hid_bpf_ctx *ctx)
{
	if (ctx->hid->bus == BUS_BLUETOOTH)
		return AULA_CONNECT_MODE_BLE;

	if (ctx->hid->product == PID_M60_WIRED)
		return AULA_CONNECT_MODE_WIRED;
	else if (ctx->hid->product == PID_M60_DONGLE)
		return AULA_CONNECT_MODE_DONGLE;

	return AULA_CONNECT_MODE_INVALID; // should never happen
}

/**
 * The device's report descriptor has a bug where the alt key and GUI key are
 * swapped, for both left and right keys. The report descriptor is different
 * in different connection modes, but the same bug exists in all modes.
 *
 * The broken report descriptor, in BLE mode, starts with:
 *
 * 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
 * 0x09, 0x06,                    // Usage (Keyboard)                    2
 * 0xa1, 0x01,                    // Collection (Application)            4
 * 0x85, 0x02,                    //  Report ID (2)                      6
 * 0x05, 0x07,                    //  Usage Page (Keyboard)              8
 * 0x19, 0xe0,                    //  Usage Minimum (224)                10
 * 0x29, 0xe7,                    //  Usage Maximum (231)                12
 * ... (rest of the report descriptor is correct and irrelevant)
 *
 * The broken report descriptor in wired and dongle modes starts with:
 *
 * 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
 * 0x09, 0x06,                    // Usage (Keyboard)
 * 0xa1, 0x01,                    // Collection (Application)
 * 0x05, 0x07,                    // Usage Page (Keyboard)
 * 0x19, 0xe0,                    // Usage Minimum (224)
 * 0x29, 0xe7,                    // Usage Maximum (231)
 * ... (rest of the report descriptor is correct and irrelevant)
 */

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(fix_aula_rdesc, struct hid_bpf_ctx *hctx)
{
	/**
	 * Fix report descriptor by replacing
	 *	19 E0 29 E7 (Usage Minimum 224, Usage Maximum 231)
	 * with seprate usages for each key:
	 */
	static const __u8 fixed_rdesc_part[] = {
		Usage_i8(HidUsage_KK_KeyboardLeftControl)
		Usage_i8(HidUsage_KK_KeyboardLeftShift)
		Usage_i8(HidUsage_KK_KeyboardLeftGUI) // swapped with Left Alt
		Usage_i8(HidUsage_KK_KeyboardLeftAlt) // swapped with Left Gui
		Usage_i8(HidUsage_KK_KeyboardRightControl)
		Usage_i8(HidUsage_KK_KeyboardRightShift)
		Usage_i8(HidUsage_KK_KeyboardRightGUI) // swapped with Right Alt
		Usage_i8(HidUsage_KK_KeyboardRightAlt) // swapped with Right Gui
	};

	const size_t old_n = hctx->size;
	const size_t broken_part_old_n = 4;
	const size_t fixed_part_n = sizeof(fixed_rdesc_part);
	const size_t new_n = old_n - broken_part_old_n + fixed_part_n;

	__u8 *rdesc = hid_bpf_get_data(hctx, 0, HID_MAX_DESCRIPTOR_SIZE);

	if (!rdesc)
		return 0; /* EPERM */

	enum aula_connect_mode mode = connect_mode(hctx);

	if (mode == AULA_CONNECT_MODE_INVALID)
		return 0;

	const size_t offset = (mode == AULA_CONNECT_MODE_BLE) ? 10 : 8;

	const size_t move_n = old_n - offset - broken_part_old_n;
	__u8 *move_src = rdesc + offset + broken_part_old_n;
	__u8 *move_dst = rdesc + offset + fixed_part_n;
	__u8 *rdesc_end = rdesc + HID_MAX_DESCRIPTOR_SIZE;

	for (int i = move_n - 1; i >= 0; i--) {
		if (move_dst + i < rdesc_end && move_src + i < rdesc_end)
			move_dst[i] = move_src[i];
		else // should never happen, make BPF verifier happy
			return 0;
	}

	__builtin_memcpy(rdesc + offset, fixed_rdesc_part, fixed_part_n);
	return new_n;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	static const __u8 pat[] = { 0x05, 0x01, 0x09, 0x06, 0xA1, 0x01 };

	if (ctx->rdesc_size < sizeof(pat) ||
		__builtin_memcmp(ctx->rdesc, pat, sizeof(pat)) != 0)
		ctx->retval = -EINVAL;
	else
		ctx->retval = 0;

	return 0;
}

HID_BPF_OPS(hid_rdesc_fixup_ops) = {
	.hid_rdesc_fixup = (void *)fix_aula_rdesc,
};

char _license[] SEC("license") = "GPL";

