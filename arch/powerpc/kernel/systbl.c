// SPDX-License-Identifier: GPL-2.0-only
/*
 * System call callback functions for SPUs
 */

#undef DEBUG

#include <linux/kallsyms.h>
#include <linux/export.h>
#include <linux/syscalls.h>

#include <asm/spu.h>
#include <asm/syscalls.h>
#include <asm/unistd.h>

#define __SYSCALL_WITH_COMPAT(nr, entry, compat) __SYSCALL(nr, entry)

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#define __SYSCALL(nr, entry) [nr] = __powerpc_##entry,
#else
#define __SYSCALL(nr, entry) [nr] = entry,
#endif

void *sys_call_table[] = {
#ifdef CONFIG_PPC64
#include <asm/syscall_table_64.h>
#else
#include <asm/syscall_table_32.h>
#endif
};

#ifdef CONFIG_COMPAT
#undef __SYSCALL_WITH_COMPAT
#define __SYSCALL_WITH_COMPAT(nr, native, compat) __SYSCALL(nr, compat)
void *compat_sys_call_table[] = {
// FIXME is the next line necessary?
#define compat_sys_sigsuspend	sys_sigsuspend
#include <asm/syscall_table_32.h>
};
#endif /* CONFIG_COMPAT */
