/*
 * smc.h
 *
 * SMC/HVC interface in accordance with SMC Calling Convention.
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
 * Copyright 2017 (C) EPAM Systems
 */

#ifndef __XEN_PUBLIC_ARCH_ARM_SMC_H__
#define __XEN_PUBLIC_ARCH_ARM_SMC_H__

typedef struct {
    uint32_t a[4];
} arm_smccc_uid;

#define ARM_SMCCC_UID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
    ((arm_smccc_uid) {{(a), ((b) << 16 | (c) ),                         \
                ((d0) << 24 | (d1) << 16 | (d2) << 8 | (d3) << 0),      \
                ((d4) << 24 | (d5) << 16 | (d6) << 8 | (d7) << 0)}})


/* Hypervisor Service UID. Randomly generated with 3rd party tool  */
#define XEN_SMCCC_UID ARM_SMCCC_UID(0xa71812dc, 0xc698, 0x4369, \
                                    0x9a, 0xcf, 0x79, 0xd1, \
                                    0x8d, 0xde, 0xe6, 0x67)

#endif	/* __XEN_PUBLIC_ARCH_ARM_SMC_H__ */
