/*
 *  Unified sound-device I/O interface for Xen guest OSes
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) 2016 EPAM Systems Inc.
 */

#ifndef __XEN_PUBLIC_IO_XENSND_LINUX_H__
#define __XEN_PUBLIC_IO_XENSND_LINUX_H__

#ifdef __KERNEL__
#include <xen/interface/io/ring.h>
#include <xen/interface/grant_table.h>
#else
#include <xen/io/ring.h>
#include <xen/grant_table.h>
#endif
#if 0
#include <xen/include/public/io/sndif.h>
#else
#warning "TODO: properly include base protocol header"
#include "sndif.h"
#endif

struct xensnd_open_req {
	uint32_t pcm_rate;
	uint8_t pcm_format;
	uint8_t pcm_channels;
	/* in Hz */
	uint16_t __reserved0;
	grant_ref_t gref_directory_start;
} __attribute__((packed));

struct xensnd_page_directory {
	grant_ref_t gref_dir_next_page;
	uint32_t num_grefs;
	grant_ref_t gref[0];
} __attribute__((packed));

struct xensnd_close_req {
} __attribute__((packed));

struct xensnd_write_req {
	uint32_t offset;
	uint32_t len;
} __attribute__((packed));

struct xensnd_read_req {
	uint32_t offset;
	uint32_t len;
} __attribute__((packed));

struct xensnd_get_vol_req {
} __attribute__((packed));

struct xensnd_set_vol_req {
} __attribute__((packed));

struct xensnd_mute_req {
} __attribute__((packed));

struct xensnd_unmute_req {
} __attribute__((packed));

struct xensnd_req {
	union {
		struct xensnd_request raw;
		struct {
			uint16_t id;
			uint8_t operation;
			uint8_t stream_idx;
			union {
				struct xensnd_open_req open;
				struct xensnd_close_req close;
				struct xensnd_write_req write;
				struct xensnd_read_req read;
				struct xensnd_get_vol_req get_vol;
				struct xensnd_set_vol_req set_vol;
				struct xensnd_mute_req mute;
				struct xensnd_unmute_req unmute;
			} op;
		} data;
	} u;
};

struct xensnd_resp {
	union {
		struct xensnd_response raw;
		struct {
			uint16_t id;
			uint8_t operation;
			uint8_t stream_idx;
			int8_t status;
		} data;
	} u;
};

DEFINE_RING_TYPES(xen_sndif, struct xensnd_req,
		struct xensnd_resp);

#endif /* __XEN_PUBLIC_IO_XENSND_LINUX_H__ */
