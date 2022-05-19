/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_POWERPC_SYSCALLS_H
#define __ASM_POWERPC_SYSCALLS_H
#ifdef __KERNEL__

#include <linux/syscalls.h>
#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/compat.h>

#include <asm/syscall.h>
#ifdef CONFIG_PPC64
#include <asm/ppc32.h>
#endif
#include <asm/unistd.h>
#include <asm/ucontext.h>

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
asmlinkage long sys_ni_syscall(void);
#else
asmlinkage long sys_ni_syscall(const struct pt_regs *regs);
#endif

struct rtas_args;

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER

/*
 * PowerPC architecture-specific syscalls
 */

asmlinkage long sys_rtas(struct rtas_args __user *uargs);

#ifdef CONFIG_PPC64
asmlinkage long sys_ppc64_personality(unsigned long personality);
#ifdef CONFIG_COMPAT
asmlinkage long compat_sys_ppc64_personality(unsigned long personality);
#endif
#endif /* CONFIG_PPC64 */

/* Parameters are reordered for powerpc to avoid padding */
asmlinkage long sys_ppc_fadvise64_64(int fd, int advice,
				     u32 offset_high, u32 offset_low,
				     u32 len_high, u32 len_low);
asmlinkage long sys_swapcontext(struct ucontext __user *old_ctx,
				struct ucontext __user *new_ctx, long ctx_size);
asmlinkage long sys_mmap(unsigned long addr, size_t len,
			 unsigned long prot, unsigned long flags,
			 unsigned long fd, off_t offset);
asmlinkage long sys_mmap2(unsigned long addr, size_t len,
			  unsigned long prot, unsigned long flags,
			  unsigned long fd, unsigned long pgoff);
asmlinkage long sys_switch_endian(void);

#ifdef CONFIG_PPC32
asmlinkage long sys_sigreturn(void);
asmlinkage long sys_debug_setcontext(struct ucontext __user *ctx, int ndbg,
				     struct sig_dbg_op __user *dbg);
#endif

asmlinkage long sys_rt_sigreturn(void);

asmlinkage long sys_subpage_prot(unsigned long addr,
				 unsigned long len, u32 __user *map);

#ifdef CONFIG_COMPAT
asmlinkage long compat_sys_swapcontext(struct ucontext32 __user *old_ctx,
				       struct ucontext32 __user *new_ctx,
				       int ctx_size);
asmlinkage long compat_sys_old_getrlimit(unsigned int resource,
					 struct compat_rlimit __user *rlim);
asmlinkage long compat_sys_sigreturn(void);
asmlinkage long compat_sys_rt_sigreturn(void);

/* Architecture-specific implementations in sys_ppc32.c */

asmlinkage long compat_sys_ppc_mmap2(unsigned long addr, size_t len,
				     unsigned long prot, unsigned long flags,
		       		     unsigned long fd, unsigned long pgoff);
asmlinkage long compat_sys_ppc_pread64(unsigned int fd,
				       char __user *ubuf, compat_size_t count,
		       		       u32 reg6, u32 pos1, u32 pos2);
asmlinkage long compat_sys_ppc_pwrite64(unsigned int fd,
					const char __user *ubuf, compat_size_t count,
					u32 reg6, u32 pos1, u32 pos2);
asmlinkage long compat_sys_ppc_readahead(int fd, u32 r4,
					 u32 offset1, u32 offset2, u32 count);
asmlinkage long compat_sys_ppc_truncate64(const char __user *path, u32 reg4,
					  unsigned long len1, unsigned long len2);
asmlinkage long compat_sys_ppc_fallocate(int fd, int mode, u32 offset1, u32 offset2,
					 u32 len1, u32 len2);
asmlinkage long compat_sys_ppc_ftruncate64(unsigned int fd, u32 reg4,
					   unsigned long len1, unsigned long len2);
asmlinkage long compat_sys_ppc32_fadvise64(int fd, u32 unused, u32 offset1, u32 offset2,
					   size_t len, int advice);
asmlinkage long compat_sys_ppc_sync_file_range2(int fd, unsigned int flags,
						unsigned int offset1, unsigned int offset2,
						unsigned int nbytes1, unsigned int nbytes2);
#endif /* CONFIG_COMPAT */

#else

/*
 * PowerPC architecture-specific syscalls
 */

asmlinkage long __powerpc_sys_rtas(const struct pt_regs *regs);

#ifdef CONFIG_PPC64
asmlinkage long __powerpc_sys_ppc64_personality(const struct pt_regs *regs);
#ifdef CONFIG_COMPAT
asmlinkage long __powerpc_compat_sys_ppc64_personality(const struct pt_regs *regs);
#endif
#endif /* CONFIG_PPC64 */

/* Parameters are reordered for powerpc to avoid padding */
asmlinkage long __powerpc_sys_ppc_fadvise64_64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_swapcontext(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mmap(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mmap2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_switch_endian(const struct pt_regs *regs);

#ifdef CONFIG_PPC32
asmlinkage long __powerpc_sys_sigreturn(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_debug_setcontext(const struct pt_regs *regs);
#endif

asmlinkage long __powerpc_sys_rt_sigreturn(const struct pt_regs *regs);

asmlinkage long __powerpc_sys_subpage_prot(const struct pt_regs *regs);

#ifdef CONFIG_COMPAT
asmlinkage long __powerpc_compat_sys_swapcontext(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_old_getrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_mmap(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_mmap2(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sigreturn(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigreturn(const struct pt_regs *regs);

asmlinkage long __powerpc_compat_sys_ppc_mmap2(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_pread64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_pwrite64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_readahead(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_truncate64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_fallocate(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_ftruncate64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc32_fadvise64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppc_sync_file_range2(const struct pt_regs *regs);
#endif

/* 
 * PowerPC symbols from linux/syscalls.h
 */

asmlinkage long __powerpc_sys_io_getevents(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_getevents_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_pgetevents(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_pgetevents_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_uring_setup(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_uring_enter(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_uring_register(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lsetxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsetxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lgetxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fgetxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_listxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_llistxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_flistxattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_removexattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lremovexattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fremovexattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getcwd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lookup_dcookie(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_eventfd2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_create1(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_ctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_pwait(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_pwait2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_dup(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_dup3(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fcntl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fcntl64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_init1(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_add_watch(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_rm_watch(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ioctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ioprio_set(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ioprio_get(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_flock(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mknodat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mkdirat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_unlinkat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_symlinkat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_linkat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_renameat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_umount(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mount(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pivot_root(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_statfs(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_statfs64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstatfs(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstatfs64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_truncate(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ftruncate(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_truncate64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ftruncate64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fallocate(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_faccessat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_faccessat2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_chdir(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchdir(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_chroot(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchmod(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchmodat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchownat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchown(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_openat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_openat2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_close(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_close_range(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_vhangup(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pipe2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_quotactl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_quotactl_fd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getdents64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_llseek(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lseek(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_read(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_write(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_readv(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_writev(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pread64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pwrite64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_preadv(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pwritev(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendfile64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pselect6(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pselect6_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ppoll(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ppoll_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_signalfd4(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_vmsplice(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_splice(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_tee(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_readlinkat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_newfstatat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_newfstat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstat64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstatat64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sync(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsync(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fdatasync(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sync_file_range2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sync_file_range(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_create(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_settime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_gettime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_gettime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_settime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimensat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimensat_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_acct(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_capget(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_capset(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_personality(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_exit(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_exit_group(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_waitid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_tid_address(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_unshare(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_futex(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_futex_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_get_robust_list(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_robust_list(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_futex_waitv(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_nanosleep(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_nanosleep_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getitimer(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setitimer(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_kexec_load(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_init_module(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_delete_module(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_create(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_gettime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_getoverrun(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_settime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_delete(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_settime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_gettime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_getres(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_nanosleep(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_gettime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_settime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_settime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_gettime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_getres_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_nanosleep_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_syslog(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ptrace(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setparam(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setscheduler(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getscheduler(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getparam(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setaffinity(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getaffinity(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_yield(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_get_priority_max(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_get_priority_min(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_rr_get_interval(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_rr_get_interval_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_restart_syscall(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_kill(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_tkill(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_tgkill(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigaltstack(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigsuspend(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigaction(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigprocmask(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigpending(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigtimedwait(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigtimedwait_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigqueueinfo(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setpriority(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpriority(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_reboot(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setregid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setreuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setresuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getresuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setresgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getresgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setfsuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setfsgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_times(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setpgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getsid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setsid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getgroups(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setgroups(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_newuname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sethostname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setdomainname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getrusage(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_umask(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_prctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getcpu(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_gettimeofday(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_settimeofday(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_adjtimex(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_adjtimex_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getppid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_geteuid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getgid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getegid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_gettid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sysinfo(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_open(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_unlink(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedsend(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedreceive(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_notify(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_getsetattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedreceive_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedsend_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgget(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_msgctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgrcv(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgsnd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_semget(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_semctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_semctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_semtimedop(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_semtimedop_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_semop(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmget(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_shmctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmdt(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_socket(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_socketpair(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_bind(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_listen(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_accept(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_connect(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getsockname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpeername(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendto(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvfrom(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setsockopt(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getsockopt(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_shutdown(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_readahead(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_brk(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_munmap(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mremap(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_add_key(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_request_key(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_keyctl(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clone(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clone3(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_execve(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fadvise64_64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_swapon(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_swapoff(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mprotect(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_msync(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mlock(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_munlock(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mlockall(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_munlockall(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mincore(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_madvise(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_madvise(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_mrelease(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_remap_file_pages(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mbind(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_get_mempolicy(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_mempolicy(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_migrate_pages(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_move_pages(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_tgsigqueueinfo(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_perf_event_open(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_accept4(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvmmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvmmsg_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_wait4(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_prlimit64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fanotify_init(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fanotify_mark(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_name_to_handle_at(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_open_by_handle_at(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_adjtime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_adjtime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_syncfs(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_setns(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pidfd_open(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendmmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_vm_readv(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_vm_writev(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_kcmp(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_finit_module(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_renameat2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_seccomp(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getrandom(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_memfd_create(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_bpf(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_execveat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_userfaultfd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_membarrier(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mlock2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_copy_file_range(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_preadv2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pwritev2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pkey_mprotect(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pkey_alloc(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pkey_free(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_statx(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rseq(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_open_tree(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_move_mount(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mount_setattr(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsopen(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsconfig(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsmount(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fspick(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pidfd_send_signal(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pidfd_getfd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_landlock_create_ruleset(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_landlock_add_rule(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_landlock_restrict_self(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_memfd_secret(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_mempolicy_home_node(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pciconfig_read(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pciconfig_write(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pciconfig_iobase(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_spu_run(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_spu_create(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_open(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_link(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_unlink(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mknod(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_chmod(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_chown(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mkdir(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rmdir(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lchown(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_access(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_rename(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_symlink(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_stat64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lstat64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pipe(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_dup2(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_create(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_init(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_eventfd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_signalfd(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendfile(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_newstat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_newlstat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fadvise64(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_alarm(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpgrp(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_pause(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_time(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_utime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimes(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_futimesat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_futimesat_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_utime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimes_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_creat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_getdents(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_select(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_poll(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_wait(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ustat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_vfork(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_recv(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_send(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_oldumount(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_uselib(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sysfs(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fork(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_stime(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_stime32(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigpending(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigprocmask(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigsuspend(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigaction(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_sgetmask(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ssetmask(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_signal(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_nice(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_kexec_file_load(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_waitpid(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_socketcall(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_stat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_lstat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstat(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_readlink(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_select(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_readdir(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_gethostname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_uname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_olduname(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_getrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_ipc(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_mmap_pgoff(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_mmap(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_setup(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_destroy(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_submit(const struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_cancel(const struct pt_regs *regs);

/* 
 * PowerPC symbols from linux/compat.h
 */

asmlinkage long __powerpc_compat_sys_open(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_execve(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_lseek(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ptrace(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_times(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ioctl(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_fcntl(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ustat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sigaction(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sigpending(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_setrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_old_getrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_getrusage(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_gettimeofday(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_settimeofday(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_old_readdir(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_truncate(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ftruncate(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_statfs(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_fstatfs(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_socketcall(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_setitimer(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_getitimer(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_newstat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_newlstat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_newfstat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_wait4(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sysinfo(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ipc(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sigreturn(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sigprocmask(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_getdents(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_select(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigreturn(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigaction(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigprocmask(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigpending(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigtimedwait_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigqueueinfo(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigsuspend(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sigaltstack(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sendfile(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_getrlimit(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_fcntl64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sched_setaffinity(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sched_getaffinity(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sendfile64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_io_setup(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_io_submit(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_lookup_dcookie(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_timer_create(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_statfs64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_fstatfs64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_mq_open(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_mq_notify(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_mq_getsetattr(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_kexec_load(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_keyctl(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_waitid(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_pselect6_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppoll_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_openat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_get_robust_list(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_set_robust_list(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_epoll_pwait(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_signalfd(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_signalfd4(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_preadv(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_pwritev(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_tgsigqueueinfo(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_fanotify_mark(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_recv(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_recvfrom(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sendmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_recvmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_recvmmsg_time32(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_open_by_handle_at(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_sendmmsg(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_execveat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_preadv2(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_pwritev2(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_io_pgetevents(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_semctl(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_shmctl(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_shmat(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_msgsnd(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_msgrcv(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_msgctl(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_pselect6_time64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_ppoll_time64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_recvmmsg_time64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_rt_sigtimedwait_time64(const struct pt_regs *regs);
asmlinkage long __powerpc_compat_sys_epoll_pwait2(const struct pt_regs *regs);

#ifdef CONFIG_COMPAT

#endif /* CONFIG_COMPAT */

#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */

#endif /* __KERNEL__ */
#endif /* __ASM_POWERPC_SYSCALLS_H */
