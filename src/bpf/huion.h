/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Helpers for Huion, UGEE and Gaomon tablets.
 *
 * These tablets start in a firmware mode that emulates a keyboard and
 * mouse for the pad. Reading USB string descriptor 200 switches them to
 * their native mode, where everything is reported through a vendor
 * report. String descriptor 201 holds a firmware ID (e.g.
 * HUION_T21j_221221) that tells apart products sharing a USB product ID.
 *
 * On kernels with hid_bpf_get_string_descriptor() the BPF program does
 * this itself in a sleepable hid_rdesc_fixup. On older kernels, the
 * huion-switcher udev helper reads the descriptors from userspace and
 * udev-hid-bpf passes the firmware ID in UDEV_PROP_HUION_FIRMWARE_ID.
 */

#ifndef __HUION_H
#define __HUION_H

#include "hid_bpf_helpers.h"

#define HUION_LANGID			0x0409
#define HUION_STRING_INDEX_MAGIC	200
#define HUION_STRING_INDEX_FIRMWARE_ID	201
#define HUION_FIRMWARE_ID_SIZE		64
#define HUION_USB_DT_STRING		0x03

/*
 * Read string descriptor @index and convert its UTF-16LE payload to ASCII
 * in @out (NUL-terminated, at most HUION_FIRMWARE_ID_SIZE - 1 characters).
 *
 * Returns the string length, or a negative error if the kfunc is not
 * available (-EOPNOTSUPP), the transport has no string descriptors, or the
 * descriptor is malformed.
 */
static __always_inline int
huion_read_string(struct hid_bpf_ctx *hctx, __u8 index,
		  char out[HUION_FIRMWARE_ID_SIZE])
{
#ifndef HID_BPF_TRACING
	__u8 desc[2 + 2 * (HUION_FIRMWARE_ID_SIZE - 1)] = {0};
	int ret, len, i;

	if (!bpf_ksym_exists(hid_bpf_get_string_descriptor))
		return -EOPNOTSUPP;

	ret = hid_bpf_get_string_descriptor(hctx, index, HUION_LANGID,
					    desc, sizeof(desc));
	if (ret < 0)
		return ret;
	if (ret < 2 || desc[1] != HUION_USB_DT_STRING)
		return -EIO;

	len = (ret - 2) / 2;
	for (i = 0; i < HUION_FIRMWARE_ID_SIZE - 1; i++) {
		__u8 lo, hi;

		if (i >= len)
			break;
		lo = desc[2 + 2 * i];
		hi = desc[3 + 2 * i];
		/* firmware IDs are plain ASCII */
		if (hi != 0 || lo < 0x20 || lo > 0x7e)
			return -EIO;
		out[i] = lo;
	}
	out[i] = '\0';

	return i;
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * Check whether the device's firmware ID starts with @expected
 * (@expected_len characters, without the NUL).
 *
 * The firmware ID is read from the device if the kernel supports it,
 * otherwise from @udev_prop (UDEV_PROP_HUION_FIRMWARE_ID, set by
 * huion-switcher). If the ID was read from the device, it is also
 * stored in @fw_id; @fw_id is left empty otherwise.
 *
 * Returns true on a match.
 */
static __always_inline bool
huion_firmware_id_matches(struct hid_bpf_ctx *hctx, const char *udev_prop,
			  const char *expected, size_t expected_len,
			  char fw_id[HUION_FIRMWARE_ID_SIZE])
{
	int ret;

	fw_id[0] = '\0';
	ret = huion_read_string(hctx, HUION_STRING_INDEX_FIRMWARE_ID, fw_id);
	if (ret >= 0)
		return ret >= (int)expected_len &&
		       __builtin_memcmp(fw_id, expected, expected_len) == 0;

	fw_id[0] = '\0';
	return __builtin_memcmp(udev_prop, expected, expected_len) == 0;
}

/*
 * Read the raw "magic bytes" (string descriptor 200, including its two
 * header bytes) into @buf. Reading them switches the tablet to its native
 * (vendor) mode. The payload holds tablet parameters (logical maxima,
 * pressure levels, resolution), little endian, model specific.
 *
 * Returns the number of bytes read or a negative error, -EOPNOTSUPP if the
 * kernel cannot read string descriptors.
 */
static __always_inline int
huion_read_magic(struct hid_bpf_ctx *hctx, __u8 *buf, size_t size)
{
#ifndef HID_BPF_TRACING
	if (!bpf_ksym_exists(hid_bpf_get_string_descriptor))
		return -EOPNOTSUPP;

	return hid_bpf_get_string_descriptor(hctx, HUION_STRING_INDEX_MAGIC,
					     HUION_LANGID, buf, size);
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * Switch the tablet to its native (vendor) mode by reading string
 * descriptor 200, ignoring the data.
 *
 * Returns 0 on success or a negative error, -EOPNOTSUPP if the kernel cannot
 * read string descriptors.
 */
static __always_inline int
huion_switch_to_vendor_mode(struct hid_bpf_ctx *hctx)
{
	__u8 magic[64] = {0};
	int ret;

	ret = huion_read_magic(hctx, magic, sizeof(magic));
	return ret < 0 ? ret : 0;
}

/*
 * Store @fw_id as the device's uniq (if the device has none) so that
 * userspace, e.g. libwacom, can tell apart devices sharing a product ID.
 * Only possible from hid_bpf_ops programs.
 */
static __always_inline void
huion_set_uniq(struct hid_bpf_ctx *hctx, const char fw_id[HUION_FIRMWARE_ID_SIZE])
{
#ifndef HID_BPF_TRACING
	if (!fw_id[0] || hctx->hid->uniq[0])
		return;

	/* the last byte of uniq is not writable, it stays NUL */
	__builtin_memcpy(hctx->hid->uniq, fw_id, HUION_FIRMWARE_ID_SIZE - 1);
#endif
}

/*
 * The common sequence for an hid_rdesc_fixup: returns true if the device
 * is the expected model (firmware ID prefix matches). If the firmware ID
 * was read from the device, the device's uniq is set, and if
 * @switch_mode is true the tablet is switched to vendor mode.
 */
static __always_inline bool
huion_probe_firmware(struct hid_bpf_ctx *hctx, const char *udev_prop,
		     const char *expected, size_t expected_len,
		     bool switch_mode)
{
	char fw_id[HUION_FIRMWARE_ID_SIZE];

	if (!huion_firmware_id_matches(hctx, udev_prop, expected,
				       expected_len, fw_id))
		return false;

	if (fw_id[0]) {
		huion_set_uniq(hctx, fw_id);
		if (switch_mode)
			huion_switch_to_vendor_mode(hctx);
	}

	return true;
}

#endif /* __HUION_H */
