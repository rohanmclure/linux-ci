/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _ASM_POWERPC_KSTACK_H
#define _ASM_POWERPC_KSTACK_H

#ifdef CONFIG_HAVE_ARCH_KSTACK_OFFSET_STORE

#include <asm/paca.h>

#define read_kstack_offset()		local_paca->kstack_offset
#define write_kstack_offset(offset)	local_paca->kstack_offset = (offset)

#endif /* CONFIG_RANDOMIZE_KSTACK_OFFSET */

#endif
