/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file contains the table of syscall-handling functions.
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 * Largely rewritten by Cort Dougan (cort@cs.nmt.edu)
 * and Paul Mackerras.
 *
 * Adapted for iSeries by Mike Corrigan (mikejc@us.ibm.com)
 * PPC64 updates by Dave Engebretsen (engebret@us.ibm.com) 
 */

#include <asm/ppc_asm.h>

.section .rodata,"a"

#ifdef CONFIG_PPC64
	.p2align	3
#endif

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER

#define __powerpc_sys_ni_syscall sys_ni_syscall
#define __powerpc_compat_sys_pread64 compat_sys_pread64
#define __powerpc_compat_sys_pwrite64 compat_sys_pwrite64
#define __powerpc_compat_sys_readahead compat_sys_readahead
#define __powerpc_compat_sys_mmap2 compat_sys_mmap2
#define __powerpc_compat_sys_truncate64 compat_sys_truncate64
#define __powerpc_compat_sys_ftruncate64 compat_sys_ftruncate64
#define __powerpc_ppc32_fadvise64 ppc32_fadvise64
#define __powerpc_ppc_fadvise64_64 ppc_fadvise64_64
#define __powerpc_compat_sys_sync_file_range2 compat_sys_sync_file_range2
#define __powerpc_compat_sys_fallocate compat_sys_fallocate

#ifdef CONFIG_PPC64
#define __SYSCALL(nr, entry)	.8byte __powerpc_##entry
#define __powerpc_ppc64_personality ppc64_personality
#else
#define __SYSCALL(nr, entry)	.long __powerpc_##entry
#define __powerpc_ppc_select ppc_select
#define __powerpc_ppc_fadvise64_64 ppc_fadvise64_64
#endif

#else

#ifdef CONFIG_PPC64
#define __SYSCALL(nr, entry)	.8byte entry
#else
#define __SYSCALL(nr, entry)	.long entry
#endif

#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */

#define __SYSCALL_WITH_COMPAT(nr, native, compat)	__SYSCALL(nr, native)
.globl sys_call_table
sys_call_table:
#ifdef CONFIG_PPC64
#include <asm/syscall_table_64.h>
#else
#include <asm/syscall_table_32.h>
#endif

#ifdef CONFIG_COMPAT
#undef __SYSCALL_WITH_COMPAT
#define __SYSCALL_WITH_COMPAT(nr, native, compat)	__SYSCALL(nr, compat)
.globl compat_sys_call_table
compat_sys_call_table:
#define compat_sys_sigsuspend	sys_sigsuspend
#include <asm/syscall_table_32.h>
#endif
