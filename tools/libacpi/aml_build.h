/*
 * tools/libacpi/aml_build.h
 *
 * Copyright (C) 2017, Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _AML_BUILD_H_
#define _AML_BUILD_H_

#include <stdint.h>
#include "libacpi.h"

/*
 * NB: All aml_prepend_* calls, which build AML code in one ACPI
 *     table, should be placed between a pair of calls to
 *     aml_build_begin() and aml_build_end(). Nested aml_build_begin()
 *     and aml_build_end() are not supported.
 *
 * NB: If a call to aml_prepend_*() fails, the AML builder buffer
 *     will be in an inconsistent state, and any following calls to
 *     aml_prepend_*() will result in undefined behavior.
 */

/**
 * Reset the AML builder and begin a new round of building.
 *
 * Parameters:
 *   ctxt: ACPI context used by the AML builder
 *
 * Returns:
 *   a pointer to the builder buffer where the AML code will be stored
 */
void *aml_build_begin(struct acpi_ctxt *ctxt);

/**
 * Mark the end of a round of AML building.
 *
 * Returns:
 *  the number of bytes in the builder buffer built in this round
 */
uint32_t aml_build_end(void);

/**
 * Prepend a blob, which can contain arbitrary content, to the builder buffer.
 *
 * On success, an object in the following form is stored at @buf.
 *   the first @length bytes in @blob
 *   the original content in @buf
 *
 * Parameters:
 *   buf:    pointer to the builder buffer
 *   blob:   pointer to the blob
 *   length: the number of bytes in the blob
 *
 * Return:
 *   0 on success, -1 on failure.
 */
int aml_prepend_blob(uint8_t *buf, const void *blob, uint32_t length);

/**
 * Prepend an AML device structure to the builder buffer. The existing
 * data in the builder buffer is included in the AML device.
 *
 * On success, an object decoded as below is stored at @buf.
 *   Device (@name)
 *   {
 *     the original content in @buf
 *   }
 *
 * Refer to ACPI spec 6.1, Sec 20.2.5.2 "Named Objects Encoding" -
 * "DefDevice".
 *
 * Parameters:
 *   buf:  pointer to the builder buffer
 *   name: the name of the device
 *
 * Return:
 *   0 on success, -1 on failure.
 */
int aml_prepend_device(uint8_t *buf, const char *name);

/**
 * Prepend an AML scope structure to the builder buffer. The existing
 * data in the builder buffer is included in the AML scope.
 *
 * On success, an object decoded as below is stored at @buf.
 *   Scope (@name)
 *   {
 *     the original content in @buf
 *   }
 *
 * Refer to ACPI spec 6.1, Sec 20.2.5.1 "Namespace Modifier Objects
 * Encoding" - "DefScope".
 *
 * Parameters:
 *   buf:  pointer to the builder buffer
 *   name: the name of the scope
 *
 * Return:
 *   0 on success, -1 on failure.
 */
int aml_prepend_scope(uint8_t *buf, const char *name);

#endif /* _AML_BUILD_H_ */
