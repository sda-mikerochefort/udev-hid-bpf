// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Santiago Valencia Leon
 *
 * Corsair K70 CORE RGB (1b1c:1bfd) report descriptor fixup
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_CORSAIR	0x1B1C
#define PID_K70_CORE	0x1BFD
#define RDESC_SIZE	125

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_CORSAIR, PID_K70_CORE)
);

/*
 * The Corsair K70 CORE RGB transmits Report ID 8 on interface 0. That
 * report's key array is declared with Logical Maximum 1 while its Usage
 * Maximum is 0x97 (151). hid_array_value_is_valid() in hid-core.c rejects
 * any array value above logical_maximum, so every non-modifier keycode is
 * silently dropped - Shift/Ctrl/Alt work and nothing else does. There is
 * no kernel log on that path, so the failure is completely silent.
 *
 * The same report declares Report Count 13, but the device puts 19 array
 * slots on the wire: 1 report ID + 1 modifier + 19 = 21 bytes, which is
 * exactly the report length observed from hidraw.
 *
 * Original descriptor, interface 0, byte offsets on the right:
 *
 * 0x05, 0x01,        // Usage Page (Generic Desktop)    0
 * 0x09, 0x06,        // Usage (Keyboard)                2
 * 0xa1, 0x01,        // Collection (Application)        4
 * 0x85, 0x08,        //  Report ID (8)                  6
 * 0x05, 0x07,        //  Usage Page (Keyboard)          8
 * 0x19, 0xe0,        //  Usage Minimum (224)            10
 * 0x29, 0xe7,        //  Usage Maximum (231)            12
 * 0x15, 0x00,        //  Logical Minimum (0)            14
 * 0x25, 0x01,        //  Logical Maximum (1)            16   modifiers: correct
 * 0x75, 0x01,        //  Report Size (1)                18
 * 0x95, 0x08,        //  Report Count (8)               20
 * 0x81, 0x02,        //  Input (Data,Var,Abs)           22
 * 0x19, 0x00,        //  Usage Minimum (0)              24
 * 0x29, 0x97,        //  Usage Maximum (151)            26
 * 0x15, 0x00,        //  Logical Minimum (0)            28
 * 0x25, 0x01,        //  Logical Maximum (1)            30   <- data[31] -> 0x97
 * 0x75, 0x08,        //  Report Size (8)                32
 * 0x95, 0x0d,        //  Report Count (13)              34   <- data[35] -> 0x13
 * 0x81, 0x00,        //  Input (Data,Arr,Abs)           36
 */

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(hid_rdesc_fixup_corsair_k70_core, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, HID_MAX_DESCRIPTOR_SIZE);

	if (!data)
		return 0; /* EPERM check */

	/* Logical Maximum 1 -> 151 so the key array is accepted at all */
	if (data[30] == 0x25 && data[31] == 0x01)
		data[31] = 0x97;

	/* Report Count 13 -> 19 to match what the device actually sends */
	if (data[34] == 0x95 && data[35] == 0x0d)
		data[35] = 0x13;

	return 0;
}

HID_BPF_OPS(corsair_k70_core) = {
	.hid_rdesc_fixup = (void *)hid_rdesc_fixup_corsair_k70_core,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	/* interface 0 only - the sole 125-byte descriptor on this device */
	ctx->retval = ctx->rdesc_size != RDESC_SIZE;
	if (ctx->retval)
		ctx->retval = -EINVAL;

	return 0;
}

char _license[] SEC("license") = "GPL";
