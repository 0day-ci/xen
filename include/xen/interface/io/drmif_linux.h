/******************************************************************************
 * drmif_linux.h
 *
 *  Unified DRM-device I/O interface for Xen guest OSes
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016 EPAM Systems Inc.
 *
 * Authors: Oleksandr Andrushchenko <andr2000@gmail.com>
 *          Oleksandr Grytsov <al1img@gmail.com>
 */

#ifndef __XEN_PUBLIC_IO_XENSND_LINUX_H__
#define __XEN_PUBLIC_IO_XENSND_LINUX_H__

#include <xen/interface/io/ring.h>
#include <xen/interface/io/drmif.h>
#include <xen/interface/grant_table.h>

struct xendrm_dumb_create_req {
	uint64_t dumb_cookie;
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
	grant_ref_t gref_directory_start;
} __packed;

struct xendrm_dumb_destroy_req {
	uint64_t dumb_cookie;
} __packed;

struct xendrm_fb_create_req {
	uint64_t dumb_cookie;
	uint64_t fb_cookie;
	uint32_t width;
	uint32_t height;
	uint32_t pixel_format;
} __packed;

struct xendrm_fb_destroy_req {
	uint64_t fb_cookie;
} __packed;

struct xendrm_set_config_req {
	uint64_t fb_cookie;
	uint32_t x;
	uint32_t y;
	uint32_t width;
	uint32_t height;
	uint32_t bpp;
} __packed;

struct xendrm_page_flip_req {
	uint32_t crtc_idx;
	uint64_t fb_cookie;
} __packed;

struct xendrm_page_directory {
	grant_ref_t gref_dir_next_page;
	uint32_t num_grefs;
	grant_ref_t gref[0];
} __packed;

struct xendrm_req {
	union {
		struct xendrm_request raw;
		struct {
			uint16_t id;
			uint8_t operation;
			uint8_t reserved;
			union {
				struct xendrm_dumb_create_req dumb_create;
				struct xendrm_dumb_destroy_req dumb_destroy;
				struct xendrm_fb_create_req fb_create;
				struct xendrm_fb_destroy_req fb_destroy;
				struct xendrm_set_config_req set_config;
				struct xendrm_page_flip_req pg_flip;
			} op;
		} data __packed;
	} u;
};

struct xendrm_resp {
	union {
		struct xendrm_response raw;
		struct {
			uint16_t id;
			uint8_t operation;
			int8_t status;
		} data;
	} u;
};

struct xendrm_pg_flip_evt {
	uint32_t crtc_idx;
	uint64_t fb_cookie;
} __packed;

struct xendrm_evt {
	union {
		struct xendrm_event raw;
		struct {
			uint16_t id;
			uint8_t type;
			uint8_t reserved;
			union {
				struct xendrm_pg_flip_evt pg_flip;
			} op;
		} data __packed;
	} u;
};

DEFINE_RING_TYPES(xen_drmif, struct xendrm_req, struct xendrm_resp);

/* shared page for back to front events */

#define XENDRM_IN_RING_OFFS (sizeof(struct xendrm_event_page))
#define XENDRM_IN_RING_SIZE (PAGE_SIZE - XENDRM_IN_RING_OFFS)
#define XENDRM_IN_RING_LEN (XENDRM_IN_RING_SIZE / sizeof(struct xendrm_evt))
#define XENDRM_IN_RING(page) \
	((struct xendrm_evt *)((char *)(page) + XENDRM_IN_RING_OFFS))
#define XENDRM_IN_RING_REF(page, idx) \
	(XENDRM_IN_RING((page))[(idx) % XENDRM_IN_RING_LEN])

#endif /* __XEN_PUBLIC_IO_XENDRM_LINUX_H__ */
