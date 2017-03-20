/*
 * tools/libacpi/aml_build.c
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

#include LIBACPI_STDUTILS
#include "libacpi.h"
#include "aml_build.h"

#define AML_OP_SCOPE     0x10
#define AML_OP_EXT       0x5B
#define AML_OP_DEVICE    0x82

#define ACPI_NAMESEG_LEN 4

struct aml_build_alloctor {
    struct acpi_ctxt *ctxt;
    uint8_t *buf;
    uint32_t capacity;
    uint32_t used;
};
static struct aml_build_alloctor alloc;

static uint8_t *aml_buf_alloc(uint32_t size)
{
    uint8_t *buf = NULL;
    struct acpi_ctxt *ctxt = alloc.ctxt;
    uint32_t alloc_size, alloc_align = ctxt->min_alloc_byte_align;
    uint32_t length = alloc.used + size;

    /* Overflow ... */
    if ( length < alloc.used )
        return NULL;

    if ( length <= alloc.capacity )
    {
        buf = alloc.buf + alloc.used;
        alloc.used += size;
    }
    else
    {
        alloc_size = length - alloc.capacity;
        alloc_size = (alloc_size + alloc_align) & ~(alloc_align - 1);
        buf = ctxt->mem_ops.alloc(ctxt, alloc_size, alloc_align);

        if ( buf &&
             buf == alloc.buf + alloc.capacity /* cont to existing buf */ )
        {
            alloc.capacity += alloc_size;
            buf = alloc.buf + alloc.used;
            alloc.used += size;
        }
        else
            buf = NULL;
    }

    return buf;
}

static uint32_t get_package_length(uint8_t *pkg)
{
    uint32_t len;

    len = pkg - alloc.buf;
    len = alloc.used - len;

    return len;
}

/*
 * On success, an object in the following form is stored at @buf.
 *   @byte
 *   the original content in @buf
 */
static int build_prepend_byte(uint8_t *buf, uint8_t byte)
{
    uint32_t len;

    len = buf - alloc.buf;
    len = alloc.used - len;

    if ( !aml_buf_alloc(sizeof(uint8_t)) )
        return -1;

    if ( len )
        memmove(buf + 1, buf, len);
    buf[0] = byte;

    return 0;
}

/*
 * On success, an object in the following form is stored at @buf.
 *   AML encoding of four-character @name
 *   the original content in @buf
 *
 * Refer to  ACPI spec 6.1, Sec 20.2.2 "Name Objects Encoding".
 *
 * XXX: names of multiple segments (e.g. X.Y.Z) are not supported
 */
static int build_prepend_name(uint8_t *buf, const char *name)
{
    uint8_t *p = buf;
    const char *s = name;
    uint32_t len, name_len;

    while ( *s == '\\' || *s == '^' )
    {
        if ( build_prepend_byte(p, (uint8_t) *s) )
            return -1;
        ++p;
        ++s;
    }

    if ( !*s )
        return build_prepend_byte(p, 0x00);

    len = p - alloc.buf;
    len = alloc.used - len;
    name_len = strlen(s);
    ASSERT(name_len <= ACPI_NAMESEG_LEN);

    if ( !aml_buf_alloc(ACPI_NAMESEG_LEN) )
        return -1;
    if ( len )
        memmove(p + ACPI_NAMESEG_LEN, p, len);
    memcpy(p, s, name_len);
    memcpy(p + name_len, "____", ACPI_NAMESEG_LEN - name_len);

    return 0;
}

enum {
    PACKAGE_LENGTH_1BYTE_SHIFT = 6, /* Up to 63 - use extra 2 bits. */
    PACKAGE_LENGTH_2BYTE_SHIFT = 4,
    PACKAGE_LENGTH_3BYTE_SHIFT = 12,
    PACKAGE_LENGTH_4BYTE_SHIFT = 20,
};

/*
 * On success, an object in the following form is stored at @pkg.
 *   AML encoding of package length @length
 *   the original content in @pkg
 *
 * Refer to ACPI spec 6.1, Sec 20.2.4 "Package Length Encoding".
 */
static int build_prepend_package_length(uint8_t *pkg, uint32_t length)
{
    int rc = 0;
    uint8_t byte;
    unsigned length_bytes;

    if ( length + 1 < (1 << PACKAGE_LENGTH_1BYTE_SHIFT) )
        length_bytes = 1;
    else if ( length + 2 < (1 << PACKAGE_LENGTH_3BYTE_SHIFT) )
        length_bytes = 2;
    else if ( length + 3 < (1 << PACKAGE_LENGTH_4BYTE_SHIFT) )
        length_bytes = 3;
    else
        length_bytes = 4;

    length += length_bytes;

    switch ( length_bytes )
    {
    case 1:
        byte = length;
        return build_prepend_byte(pkg, byte);

    case 4:
        byte = length >> PACKAGE_LENGTH_4BYTE_SHIFT;
        if ( build_prepend_byte(pkg, byte) )
            break;
        length &= (1 << PACKAGE_LENGTH_4BYTE_SHIFT) - 1;
        /* fall through */
    case 3:
        byte = length >> PACKAGE_LENGTH_3BYTE_SHIFT;
        if ( build_prepend_byte(pkg, byte) )
            break;
        length &= (1 << PACKAGE_LENGTH_3BYTE_SHIFT) - 1;
        /* fall through */
    case 2:
        byte = length >> PACKAGE_LENGTH_2BYTE_SHIFT;
        if ( build_prepend_byte(pkg, byte) )
            break;
        length &= (1 << PACKAGE_LENGTH_2BYTE_SHIFT) - 1;
        /* fall through */
    }

    if ( !rc )
    {
        /*
         * Most significant two bits of byte zero indicate how many
         * following bytes are in PkgLength encoding.
         */
        byte = ((length_bytes - 1) << PACKAGE_LENGTH_1BYTE_SHIFT) | length;
        rc = build_prepend_byte(pkg, byte);
    }

    return rc;
}

/*
 * On success, an object in the following form is stored at @buf.
 *   @op
 *   AML encoding of package length of @buf
 *   original content in @buf
 *
 * Refer to comments of callers for ACPI spec sections.
 */
static int build_prepend_package(uint8_t *buf, uint8_t op)
{
    uint32_t length = get_package_length(buf);

    if ( !build_prepend_package_length(buf, length) )
        return build_prepend_byte(buf, op);
    else
        return -1;
}

/*
 * On success, an object in the following form is stored at @buf.
 *   AML_OP_EXT
 *   @op
 *   AML encoding of package length of @buf
 *   original content in @buf
 *
 * Refer to comments of callers for ACPI spec sections.
 */
static int build_prepend_ext_package(uint8_t *buf, uint8_t op)
{
    if ( !build_prepend_package(buf, op) )
        return build_prepend_byte(buf, AML_OP_EXT);
    else
        return -1;
}

void *aml_build_begin(struct acpi_ctxt *ctxt)
{
    uint32_t align = ctxt->min_alloc_byte_align;

    alloc.ctxt = ctxt;
    alloc.buf = ctxt->mem_ops.alloc(ctxt, align, align);
    alloc.capacity = align;
    alloc.used = 0;

    return alloc.buf;
}

uint32_t aml_build_end(void)
{
    return alloc.used;
}

/*
 * On success, an object in the following form is stored at @buf.
 *   the first @length bytes in @blob
 *   the original content in @buf
 */
int aml_prepend_blob(uint8_t *buf, const void *blob, uint32_t blob_length)
{
    uint32_t len;

    ASSERT(buf >= alloc.buf);
    len = buf - alloc.buf;
    ASSERT(alloc.used >= len);
    len = alloc.used - len;

    if ( !aml_buf_alloc(blob_length) )
        return -1;
    if ( len )
        memmove(buf + blob_length, buf, len);

    memcpy(buf, blob, blob_length);

    return 0;
}

/*
 * On success, an object decoded as below is stored at @buf.
 *   Device (@name)
 *   {
 *     the original content in @buf
 *   }
 *
 * Refer to ACPI spec 6.1, Sec 20.2.5.2 "Named Objects Encoding" -
 * "DefDevice".
 */
int aml_prepend_device(uint8_t *buf, const char *name)
{
    if ( !build_prepend_name(buf, name) )
        return build_prepend_ext_package(buf, AML_OP_DEVICE);
    else
        return -1;
}

/*
 * On success, an object decoded as below is stored at @buf.
 *   Scope (@name)
 *   {
 *     the original content in @buf
 *   }
 *
 * Refer to ACPI spec 6.1, Sec 20.2.5.1 "Namespace Modifier Objects
 * Encoding" - "DefScope".
 */
int aml_prepend_scope(uint8_t *buf, const char *name)
{
    if ( !build_prepend_name(buf, name) )
        return build_prepend_package(buf, AML_OP_SCOPE);
    else
        return -1;
}
