// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Malte Homeyer */

/*
 * Iiyama ProLite TE9804MIS Interactive Touch Display Stylus Fix
 *
 * Problem: The device's pen interface constantly reports a static dummy value of 2048 for
 * Tip Pressure, even when the pen is only hovering (Tip Switch = 0) or completely out of range.
 * This causes libinput and drawing software to register permanent "ghost strokes".
 *
 * Fix: Since the physical IR frame does not support physical pressure, this BPF program hooks
 * into the probe phase (HID_BPF_RDESC_FIXUP) and rewrites the report descriptor.
 * It replaces Usage (Tip Pressure) [0x09, 0x30] with Usage (Undefined) [0x09, 0x00] in both
 * Pen reports (Report ID 16 and 17).
 * This completely disables the ABS_PRESSURE axis on the input node, resolving the ghost strokes
 * while keeping pen coordinates and Tip Switch clicks intact.
 *
 * Note: Other models in the Iiyama ProLite series (e.g., TE5504MIS, TE6504MIS, TE7504MIS,
 * TE8604MIS) likely share the same touch digitizer firmware and exhibit the same issue.
 * However, their USB Product IDs must be verified and added to HID_BPF_CONFIG after
 * successful testing.
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

/* VENDOR AND PRODUCT ID */
#define VID_IIYAMA 0x1ff7   // CVT Electronics ID (Manufacturer of the touch digitizer for Iiyama Display)
#define PID_IIYAMA_TE9804MIS_PEN 0x0f27   // Iiyama ProLite TE9804MIS (Product ID)

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_ANY, VID_IIYAMA, PID_IIYAMA_TE9804MIS_PEN)
);

/*
 * Modify the report descriptor during probe.
 * Replaces 'Usage (Tip Pressure)' (0x09, 0x30) with 'Usage (Undefined)' (0x09, 0x00)
 * in both Report 16 (index 102) and Report 17 (index 239) of the 274-byte descriptor.
 */
SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(hid_fix_rdesc_iiyama_pen, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, 4096);

	if (!data)
		return 0;

	if (hctx->size == 274) {
		/* Report 16 Tip Pressure Usage (at index 102/103) */
		if (data[102] == 0x09 && data[103] == 0x30)
			data[103] = 0x00; /* Set to Usage (Undefined) */
		/* Report 17 Tip Pressure Usage (at index 239/240) */
		if (data[239] == 0x09 && data[240] == 0x30)
			data[240] = 0x00; /* Set to Usage (Undefined) */
	}

	return 0;
}

HID_BPF_OPS(iiyama_pen_ops) = {
	.hid_rdesc_fixup = (void *)hid_fix_rdesc_iiyama_pen,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	/* Only apply to Pen interface (274 bytes) */
	if (ctx->rdesc_size != 274) {
		ctx->retval = -EINVAL;
		return 0;
	}
	ctx->retval = 0;
	return 0;
}

char _license[] SEC("license") = "GPL";
