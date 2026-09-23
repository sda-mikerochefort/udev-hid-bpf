// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Ruzal Daminov */

/*
 * Goodix GXTP7863 Touchpad Telemetry Fix
 *
 * Problem: The touchpad sends periodic 1-Hz heartbeat reports on Report ID 8
 * with Vendor Usage Page 0xFF01. hid-input treats Usage Page 0xFF01 as
 * HID_UP_HPVENDOR2, misinterpreting changing telemetry bytes as phantom
 * KEY_BRIGHTNESSUP events.
 *
 * Fix: Remap the vendor telemetry collection to an ignored vendor usage page.
 * This prevents hid-input from creating a bogus keyboard input node while
 * keeping raw reports accessible via hidraw for firmware updates.
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define I2C_VENDOR_ID_GOODIX		0x27c6
#define I2C_DEVICE_ID_GOODIX_01E0	0x01e0
#define GOODIX_RDESC_SIZE		705

HID_BPF_CONFIG(
	HID_DEVICE(BUS_I2C, HID_GROUP_ANY, I2C_VENDOR_ID_GOODIX, I2C_DEVICE_ID_GOODIX_01E0)
);

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(hid_fix_rdesc_goodix_touchpad, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, HID_MAX_DESCRIPTOR_SIZE);

	if (!data)
		return 0;

	if (hctx->size == GOODIX_RDESC_SIZE) {
		/*
		 * Report 8: Change Usage Page from 0xFF01 (HID_UP_HPVENDOR2)
		 * to 0xFF09 (HID_UP_LOGIVENDOR2) at index 625.
		 */
		if (data[625] == 0x06 && data[626] == 0x01 && data[627] == 0xff &&
		    data[632] == 0x85 && data[633] == 0x08) {
			data[626] = 0x09;
		}
	}

	return 0;
}

HID_BPF_OPS(goodix_touchpad_ops) = {
	.hid_rdesc_fixup = (void *)hid_fix_rdesc_goodix_touchpad,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	if (ctx->rdesc_size != GOODIX_RDESC_SIZE) {
		ctx->retval = -EINVAL;
		return 0;
	}
	ctx->retval = 0;
	return 0;
}

char _license[] SEC("license") = "GPL";
