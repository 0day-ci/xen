/*
  * Copyright (C) 2017 ARM Ltd.
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  */
#ifndef __ARCH_ARM_ARM32_INSN
#define __ARCH_ARM_ARM32_INSN

#include <xen/types.h>

#define __AARCH32_INSN_FUNCS(abbr, mask, val)   \
static always_inline bool_t aarch32_insn_is_##abbr(uint32_t code) \
{                                                                 \
    return (code & (mask)) == (val);                              \
}

/*
 * From ARM DDI 0406C.c Section A8.8.18 and A8.8.25. We can see that
 * unconditional blx and conditional b have the same value field and imm
 * length. And from ARM DDI 0406C.c Section A5.7 Table A5-23, we can see
 * that the blx is the only one unconditional instruction has the same
 * value with conditional branch instructions. So we define the b and blx
 * in the same macro to check them at the same time.
 */
__AARCH32_INSN_FUNCS(b_or_blx,  0x0F000000, 0x0A000000)
__AARCH32_INSN_FUNCS(bl,        0x0F000000, 0x0B000000)

int32_t aarch32_get_branch_offset(uint32_t insn);
uint32_t aarch32_set_branch_offset(uint32_t insn, int32_t offset);

/* Wrapper for common code */
static inline bool insn_is_branch_imm(uint32_t insn)
{
    return ( aarch32_insn_is_b_or_blx(insn) || aarch32_insn_is_bl(insn) );
}

static inline int32_t insn_get_branch_offset(uint32_t insn)
{
    return aarch32_get_branch_offset(insn);
}

static inline uint32_t insn_set_branch_offset(uint32_t insn, int32_t offset)
{
    return aarch32_set_branch_offset(insn, offset);
}

#endif /* !__ARCH_ARM_ARM32_INSN */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
