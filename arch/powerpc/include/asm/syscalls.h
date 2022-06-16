/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_POWERPC_SYSCALLS_H
#define __ASM_POWERPC_SYSCALLS_H
#ifdef __KERNEL__

#include <linux/syscalls.h>
#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/compat.h>

#ifdef CONFIG_PPC64
#include <asm/ppc32.h>
#endif
#include <asm/unistd.h>
#include <asm/ucontext.h>

struct rtas_args;

asmlinkage long ppc64_personality(unsigned long personality);
asmlinkage long sys_rtas(struct rtas_args __user *uargs);

long ppc_fadvise64_64(int fd, int advice, u32 offset_high, u32 offset_low,
		      u32 len_high, u32 len_low);

asmlinkage long sys_ni_syscall(void);

asmlinkage long sys_rtas(struct rtas_args __user *uargs);

#ifdef CONFIG_PPC64
asmlinkage long sys_ppc64_personality(unsigned long personality);
#ifdef CONFIG_COMPAT
asmlinkage long compat_sys_ppc64_personality(unsigned long personality);
#endif
#endif /* CONFIG_PPC64 */

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER

/*
 * PowerPC architecture-specific syscalls
 */

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
asmlinkage long compat_sys_mmap(unsigned long addr, size_t len,
				unsigned long prot, unsigned long flags,
			 	unsigned long fd, off_t offset);
asmlinkage long compat_sys_mmap2(unsigned long addr, size_t len,
				 unsigned long prot, unsigned long flags,
			  	 unsigned long fd, unsigned long pgoff);
asmlinkage long compat_sys_sigreturn(void);
asmlinkage long compat_sys_rt_sigreturn(void);
#endif

#else

/*
 * PowerPC architecture-specific syscalls
 */

/* 
 * PowerPC symbols from linux/syscalls.h
 */

asmlinkage long __powerpc_sys_io_getevents(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_getevents_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_pgetevents(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_pgetevents_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_uring_setup(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_uring_enter(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_uring_register(struct pt_regs *regs);

/* fs/xattr.c */
asmlinkage long __powerpc_sys_setxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lsetxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsetxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lgetxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fgetxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_listxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_llistxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_flistxattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_removexattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lremovexattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fremovexattr(struct pt_regs *regs);

/* fs/dcache.c */
asmlinkage long __powerpc_sys_getcwd(struct pt_regs *regs);

/* fs/cookies.c */
asmlinkage long __powerpc_sys_lookup_dcookie(struct pt_regs *regs);

/* fs/eventfd.c */
asmlinkage long __powerpc_sys_eventfd2(struct pt_regs *regs);

/* fs/eventpoll.c */
asmlinkage long __powerpc_sys_epoll_create1(struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_ctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_pwait(struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_pwait2(struct pt_regs *regs);

/* fs/fcntl.c */
asmlinkage long __powerpc_sys_dup(struct pt_regs *regs);
asmlinkage long __powerpc_sys_dup3(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fcntl(struct pt_regs *regs);
#if BITS_PER_LONG == 32
asmlinkage long __powerpc_sys_fcntl64(struct pt_regs *regs);
#endif

/* fs/inotify_user.c */
asmlinkage long __powerpc_sys_inotify_init1(struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_add_watch(struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_rm_watch(struct pt_regs *regs);

/* fs/ioctl.c */
asmlinkage long __powerpc_sys_ioctl(struct pt_regs *regs);

/* fs/ioprio.c */
asmlinkage long __powerpc_sys_ioprio_set(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ioprio_get(struct pt_regs *regs);

/* fs/locks.c */
asmlinkage long __powerpc_sys_flock(struct pt_regs *regs);

/* fs/namei.c */
asmlinkage long __powerpc_sys_mknodat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mkdirat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_unlinkat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_symlinkat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_linkat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_renameat(struct pt_regs *regs);

/* fs/namespace.c */
asmlinkage long __powerpc_sys_umount(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mount(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pivot_root(struct pt_regs *regs);

/* fs/nfsctl.c */

/* fs/open.c */
asmlinkage long __powerpc_sys_statfs(struct pt_regs *regs);
asmlinkage long __powerpc_sys_statfs64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstatfs(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstatfs64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_truncate(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ftruncate(struct pt_regs *regs);
#if BITS_PER_LONG == 32
asmlinkage long __powerpc_sys_truncate64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ftruncate64(struct pt_regs *regs);
#endif
asmlinkage long __powerpc_sys_fallocate(struct pt_regs *regs);
asmlinkage long __powerpc_sys_faccessat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_faccessat2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_chdir(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchdir(struct pt_regs *regs);
asmlinkage long __powerpc_sys_chroot(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchmod(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchmodat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchownat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchown(struct pt_regs *regs);
asmlinkage long __powerpc_sys_openat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_openat2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_close(struct pt_regs *regs);
asmlinkage long __powerpc_sys_close_range(struct pt_regs *regs);
asmlinkage long __powerpc_sys_vhangup(struct pt_regs *regs);

/* fs/pipe.c */
asmlinkage long __powerpc_sys_pipe2(struct pt_regs *regs);

/* fs/quota.c */
asmlinkage long __powerpc_sys_quotactl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_quotactl_fd(struct pt_regs *regs);

/* fs/readdir.c */
asmlinkage long __powerpc_sys_getdents64(struct pt_regs *regs);

/* fs/read_write.c */
asmlinkage long __powerpc_sys_llseek(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lseek(struct pt_regs *regs);
asmlinkage long __powerpc_sys_read(struct pt_regs *regs);
asmlinkage long __powerpc_sys_write(struct pt_regs *regs);
asmlinkage long __powerpc_sys_readv(struct pt_regs *regs);
asmlinkage long __powerpc_sys_writev(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pread64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pwrite64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_preadv(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pwritev(struct pt_regs *regs);

/* fs/sendfile.c */
asmlinkage long __powerpc_sys_sendfile64(struct pt_regs *regs);

/* fs/select.c */
asmlinkage long __powerpc_sys_pselect6(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pselect6_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ppoll(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ppoll_time32(struct pt_regs *regs);

/* fs/signalfd.c */
asmlinkage long __powerpc_sys_signalfd4(struct pt_regs *regs);

/* fs/splice.c */
asmlinkage long __powerpc_sys_vmsplice(struct pt_regs *regs);
asmlinkage long __powerpc_sys_splice(struct pt_regs *regs);
asmlinkage long __powerpc_sys_tee(struct pt_regs *regs);

/* fs/stat.c */
asmlinkage long __powerpc_sys_readlinkat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_newfstatat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_newfstat(struct pt_regs *regs);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
asmlinkage long __powerpc_sys_fstat64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstatat64(struct pt_regs *regs);
#endif

/* fs/sync.c */
asmlinkage long __powerpc_sys_sync(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsync(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fdatasync(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sync_file_range2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sync_file_range(struct pt_regs *regs);

/* fs/timerfd.c */
asmlinkage long __powerpc_sys_timerfd_create(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_settime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_gettime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_gettime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timerfd_settime32(struct pt_regs *regs);

/* fs/utimes.c */
asmlinkage long __powerpc_sys_utimensat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimensat_time32(struct pt_regs *regs);

/* kernel/acct.c */
asmlinkage long __powerpc_sys_acct(struct pt_regs *regs);

/* kernel/capability.c */
asmlinkage long __powerpc_sys_capget(struct pt_regs *regs);
asmlinkage long __powerpc_sys_capset(struct pt_regs *regs);

/* kernel/exec_domain.c */
asmlinkage long __powerpc_sys_personality(struct pt_regs *regs);

/* kernel/exit.c */
asmlinkage long __powerpc_sys_exit(struct pt_regs *regs);
asmlinkage long __powerpc_sys_exit_group(struct pt_regs *regs);
asmlinkage long __powerpc_sys_waitid(struct pt_regs *regs);

/* kernel/fork.c */
asmlinkage long __powerpc_sys_set_tid_address(struct pt_regs *regs);
asmlinkage long __powerpc_sys_unshare(struct pt_regs *regs);

/* kernel/futex/syscalls.c */
asmlinkage long __powerpc_sys_futex(struct pt_regs *regs);
asmlinkage long __powerpc_sys_futex_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_get_robust_list(struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_robust_list(struct pt_regs *regs);

asmlinkage long __powerpc_sys_futex_waitv(struct pt_regs *regs);

/* kernel/hrtimer.c */
asmlinkage long __powerpc_sys_nanosleep(struct pt_regs *regs);
asmlinkage long __powerpc_sys_nanosleep_time32(struct pt_regs *regs);

/* kernel/itimer.c */
asmlinkage long __powerpc_sys_getitimer(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setitimer(struct pt_regs *regs);

/* kernel/kexec.c */
asmlinkage long __powerpc_sys_kexec_load(struct pt_regs *regs);

/* kernel/module.c */
asmlinkage long __powerpc_sys_init_module(struct pt_regs *regs);
asmlinkage long __powerpc_sys_delete_module(struct pt_regs *regs);

/* kernel/posix-timers.c */
asmlinkage long __powerpc_sys_timer_create(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_gettime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_getoverrun(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_settime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_delete(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_settime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_gettime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_getres(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_nanosleep(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_gettime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_timer_settime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_settime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_gettime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_getres_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_nanosleep_time32(struct pt_regs *regs);

/* kernel/printk.c */
asmlinkage long __powerpc_sys_syslog(struct pt_regs *regs);

/* kernel/ptrace.c */
asmlinkage long __powerpc_sys_ptrace(struct pt_regs *regs);
/* kernel/sched/core.c */

asmlinkage long __powerpc_sys_sched_setparam(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setscheduler(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getscheduler(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getparam(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setaffinity(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getaffinity(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_yield(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_get_priority_max(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_get_priority_min(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_rr_get_interval(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_rr_get_interval_time32(struct pt_regs *regs);

/* kernel/signal.c */
asmlinkage long __powerpc_sys_restart_syscall(struct pt_regs *regs);
asmlinkage long __powerpc_sys_kill(struct pt_regs *regs);
asmlinkage long __powerpc_sys_tkill(struct pt_regs *regs);
asmlinkage long __powerpc_sys_tgkill(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigaltstack(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigsuspend(struct pt_regs *regs);
#ifndef CONFIG_ODD_RT_SIGACTION
asmlinkage long __powerpc_sys_rt_sigaction(struct pt_regs *regs);
#endif
asmlinkage long __powerpc_sys_rt_sigprocmask(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigpending(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigtimedwait(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigtimedwait_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rt_sigqueueinfo(struct pt_regs *regs);

/* kernel/sys.c */
asmlinkage long __powerpc_sys_setpriority(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpriority(struct pt_regs *regs);
asmlinkage long __powerpc_sys_reboot(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setregid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setreuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setresuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getresuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setresgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getresgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setfsuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setfsgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_times(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setpgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getsid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setsid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getgroups(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setgroups(struct pt_regs *regs);
asmlinkage long __powerpc_sys_newuname(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sethostname(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setdomainname(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getrlimit(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setrlimit(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getrusage(struct pt_regs *regs);
asmlinkage long __powerpc_sys_umask(struct pt_regs *regs);
asmlinkage long __powerpc_sys_prctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getcpu(struct pt_regs *regs);

/* kernel/time.c */
asmlinkage long __powerpc_sys_gettimeofday(struct pt_regs *regs);
asmlinkage long __powerpc_sys_settimeofday(struct pt_regs *regs);
asmlinkage long __powerpc_sys_adjtimex(struct pt_regs *regs);
asmlinkage long __powerpc_sys_adjtimex_time32(struct pt_regs *regs);

/* kernel/sys.c */
asmlinkage long __powerpc_sys_getpid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getppid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_geteuid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getgid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getegid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_gettid(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sysinfo(struct pt_regs *regs);

/* ipc/mqueue.c */
asmlinkage long __powerpc_sys_mq_open(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_unlink(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedsend(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedreceive(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_notify(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_getsetattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedreceive_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mq_timedsend_time32(struct pt_regs *regs);

/* ipc/msg.c */
asmlinkage long __powerpc_sys_msgget(struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_msgctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgrcv(struct pt_regs *regs);
asmlinkage long __powerpc_sys_msgsnd(struct pt_regs *regs);

/* ipc/sem.c */
asmlinkage long __powerpc_sys_semget(struct pt_regs *regs);
asmlinkage long __powerpc_sys_semctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_semctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_semtimedop(struct pt_regs *regs);
asmlinkage long __powerpc_sys_semtimedop_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_semop(struct pt_regs *regs);

/* ipc/shm.c */
asmlinkage long __powerpc_sys_shmget(struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_shmctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmctl(struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_shmdt(struct pt_regs *regs);

/* net/socket.c */
asmlinkage long __powerpc_sys_socket(struct pt_regs *regs);
asmlinkage long __powerpc_sys_socketpair(struct pt_regs *regs);
asmlinkage long __powerpc_sys_bind(struct pt_regs *regs);
asmlinkage long __powerpc_sys_listen(struct pt_regs *regs);
asmlinkage long __powerpc_sys_accept(struct pt_regs *regs);
asmlinkage long __powerpc_sys_connect(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getsockname(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpeername(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendto(struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvfrom(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setsockopt(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getsockopt(struct pt_regs *regs);
asmlinkage long __powerpc_sys_shutdown(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendmsg(struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvmsg(struct pt_regs *regs);

/* mm/filemap.c */
asmlinkage long __powerpc_sys_readahead(struct pt_regs *regs);

/* mm/nommu.c, also with MMU */
asmlinkage long __powerpc_sys_brk(struct pt_regs *regs);
asmlinkage long __powerpc_sys_munmap(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mremap(struct pt_regs *regs);

/* security/keys/keyctl.c */
asmlinkage long __powerpc_sys_add_key(struct pt_regs *regs);
asmlinkage long __powerpc_sys_request_key(struct pt_regs *regs);
asmlinkage long __powerpc_sys_keyctl(struct pt_regs *regs);

/* arch/example/kernel/__powerpc_sys_example.c */
#ifdef CONFIG_CLONE_BACKWARDS
asmlinkage long __powerpc_sys_clone(struct pt_regs *regs);
#else
#ifdef CONFIG_CLONE_BACKWARDS3
asmlinkage long __powerpc_sys_clone(struct pt_regs *regs);
#else
asmlinkage long __powerpc_sys_clone(struct pt_regs *regs);
#endif
#endif

asmlinkage long __powerpc_sys_clone3(struct pt_regs *regs);

asmlinkage long __powerpc_sys_execve(struct pt_regs *regs);

/* mm/fadvise.c */
asmlinkage long __powerpc_sys_fadvise64_64(struct pt_regs *regs);

/* mm/, CONFIG_MMU only */
asmlinkage long __powerpc_sys_swapon(struct pt_regs *regs);
asmlinkage long __powerpc_sys_swapoff(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mprotect(struct pt_regs *regs);
asmlinkage long __powerpc_sys_msync(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mlock(struct pt_regs *regs);
asmlinkage long __powerpc_sys_munlock(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mlockall(struct pt_regs *regs);
asmlinkage long __powerpc_sys_munlockall(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mincore(struct pt_regs *regs);
asmlinkage long __powerpc_sys_madvise(struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_madvise(struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_mrelease(struct pt_regs *regs);
asmlinkage long __powerpc_sys_remap_file_pages(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mbind(struct pt_regs *regs);
asmlinkage long __powerpc_sys_get_mempolicy(struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_mempolicy(struct pt_regs *regs);
asmlinkage long __powerpc_sys_migrate_pages(struct pt_regs *regs);
asmlinkage long __powerpc_sys_move_pages(struct pt_regs *regs);

asmlinkage long __powerpc_sys_rt_tgsigqueueinfo(struct pt_regs *regs);
asmlinkage long __powerpc_sys_perf_event_open(struct pt_regs *regs);
asmlinkage long __powerpc_sys_accept4(struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvmmsg(struct pt_regs *regs);
asmlinkage long __powerpc_sys_recvmmsg_time32(struct pt_regs *regs);

asmlinkage long __powerpc_sys_wait4(struct pt_regs *regs);
asmlinkage long __powerpc_sys_prlimit64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fanotify_init(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fanotify_mark(struct pt_regs *regs);
asmlinkage long __powerpc_sys_name_to_handle_at(struct pt_regs *regs);
asmlinkage long __powerpc_sys_open_by_handle_at(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_adjtime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_clock_adjtime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_syncfs(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setns(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pidfd_open(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sendmmsg(struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_vm_readv(struct pt_regs *regs);
asmlinkage long __powerpc_sys_process_vm_writev(struct pt_regs *regs);
asmlinkage long __powerpc_sys_kcmp(struct pt_regs *regs);
asmlinkage long __powerpc_sys_finit_module(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_setattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sched_getattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_renameat2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_seccomp(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getrandom(struct pt_regs *regs);
asmlinkage long __powerpc_sys_memfd_create(struct pt_regs *regs);
asmlinkage long __powerpc_sys_bpf(struct pt_regs *regs);
asmlinkage long __powerpc_sys_execveat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_userfaultfd(struct pt_regs *regs);
asmlinkage long __powerpc_sys_membarrier(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mlock2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_copy_file_range(struct pt_regs *regs);
asmlinkage long __powerpc_sys_preadv2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pwritev2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pkey_mprotect(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pkey_alloc(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pkey_free(struct pt_regs *regs);
asmlinkage long __powerpc_sys_statx(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rseq(struct pt_regs *regs);
asmlinkage long __powerpc_sys_open_tree(struct pt_regs *regs);
asmlinkage long __powerpc_sys_move_mount(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mount_setattr(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsopen(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsconfig(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fsmount(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fspick(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pidfd_send_signal(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pidfd_getfd(struct pt_regs *regs);
asmlinkage long __powerpc_sys_landlock_create_ruleset(struct pt_regs *regs);
asmlinkage long __powerpc_sys_landlock_add_rule(struct pt_regs *regs);
asmlinkage long __powerpc_sys_landlock_restrict_self(struct pt_regs *regs);
asmlinkage long __powerpc_sys_memfd_secret(struct pt_regs *regs);
asmlinkage long __powerpc_sys_set_mempolicy_home_node(struct pt_regs *regs);

/*
 * Architecture-specific system calls
 */

/* arch/x86/kernel/ioport.c */
asmlinkage long __powerpc_sys_ioperm(struct pt_regs *regs);

/* pciconfig: alpha, arm, arm64, ia64, sparc */
asmlinkage long __powerpc_sys_pciconfig_read(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pciconfig_write(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pciconfig_iobase(struct pt_regs *regs);

/* powerpc */
asmlinkage long __powerpc_sys_spu_run(struct pt_regs *regs);
asmlinkage long __powerpc_sys_spu_create(struct pt_regs *regs);


/*
 * Deprecated system calls which are still defined in
 * include/uapi/asm-generic/unistd.h and wanted by >= 1 arch
 */

/* __ARCH_WANT_SYSCALL_NO_AT */
asmlinkage long __powerpc_sys_open(struct pt_regs *regs);
asmlinkage long __powerpc_sys_link(struct pt_regs *regs);
asmlinkage long __powerpc_sys_unlink(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mknod(struct pt_regs *regs);
asmlinkage long __powerpc_sys_chmod(struct pt_regs *regs);
asmlinkage long __powerpc_sys_chown(struct pt_regs *regs);
asmlinkage long __powerpc_sys_mkdir(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rmdir(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lchown(struct pt_regs *regs);
asmlinkage long __powerpc_sys_access(struct pt_regs *regs);
asmlinkage long __powerpc_sys_rename(struct pt_regs *regs);
asmlinkage long __powerpc_sys_symlink(struct pt_regs *regs);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
asmlinkage long __powerpc_sys_stat64(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lstat64(struct pt_regs *regs);
#endif

/* __ARCH_WANT_SYSCALL_NO_FLAGS */
asmlinkage long __powerpc_sys_pipe(struct pt_regs *regs);
asmlinkage long __powerpc_sys_dup2(struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_create(struct pt_regs *regs);
asmlinkage long __powerpc_sys_inotify_init(struct pt_regs *regs);
asmlinkage long __powerpc_sys_eventfd(struct pt_regs *regs);
asmlinkage long __powerpc_sys_signalfd(struct pt_regs *regs);

/* __ARCH_WANT_SYSCALL_OFF_T */
asmlinkage long __powerpc_sys_sendfile(struct pt_regs *regs);
asmlinkage long __powerpc_sys_newstat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_newlstat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fadvise64(struct pt_regs *regs);

/* __ARCH_WANT_SYSCALL_DEPRECATED */
asmlinkage long __powerpc_sys_alarm(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getpgrp(struct pt_regs *regs);
asmlinkage long __powerpc_sys_pause(struct pt_regs *regs);
asmlinkage long __powerpc_sys_time(struct pt_regs *regs);
asmlinkage long __powerpc_sys_time32(struct pt_regs *regs);
#ifdef __ARCH_WANT_SYS_UTIME
asmlinkage long __powerpc_sys_utime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimes(struct pt_regs *regs);
asmlinkage long __powerpc_sys_futimesat(struct pt_regs *regs);
#endif
asmlinkage long __powerpc_sys_futimesat_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_utime32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_utimes_time32(struct pt_regs *regs);
asmlinkage long __powerpc_sys_creat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getdents(struct pt_regs *regs);
asmlinkage long __powerpc_sys_select(struct pt_regs *regs);
asmlinkage long __powerpc_sys_poll(struct pt_regs *regs);
asmlinkage long __powerpc_sys_epoll_wait(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ustat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_vfork(struct pt_regs *regs);
asmlinkage long __powerpc_sys_recv(struct pt_regs *regs);
asmlinkage long __powerpc_sys_send(struct pt_regs *regs);
asmlinkage long __powerpc_sys_oldumount(struct pt_regs *regs);
asmlinkage long __powerpc_sys_uselib(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sysfs(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fork(struct pt_regs *regs);

/* obsolete: kernel/time/time.c */
asmlinkage long __powerpc_sys_stime(struct pt_regs *regs);
asmlinkage long __powerpc_sys_stime32(struct pt_regs *regs);

/* obsolete: kernel/signal.c */
asmlinkage long __powerpc_sys_sigpending(struct pt_regs *regs);
asmlinkage long __powerpc_sys_sigprocmask(struct pt_regs *regs);
#ifdef CONFIG_OLD_SIGSUSPEND
asmlinkage long __powerpc_sys_sigsuspend(struct pt_regs *regs);
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
asmlinkage long __powerpc_sys_sigsuspend(struct pt_regs *regs);
#endif

#ifdef CONFIG_OLD_SIGACTION
asmlinkage long __powerpc_sys_sigaction(struct pt_regs *regs);
#endif
asmlinkage long __powerpc_sys_sgetmask(struct pt_regs *regs);
asmlinkage long __powerpc_sys_ssetmask(struct pt_regs *regs);
asmlinkage long __powerpc_sys_signal(struct pt_regs *regs);

/* obsolete: kernel/sched/core.c */
asmlinkage long __powerpc_sys_nice(struct pt_regs *regs);

/* obsolete: kernel/kexec_file.c */
asmlinkage long __powerpc_sys_kexec_file_load(struct pt_regs *regs);

/* obsolete: kernel/exit.c */
asmlinkage long __powerpc_sys_waitpid(struct pt_regs *regs);

/* obsolete: kernel/uid16.c */
#ifdef CONFIG_HAVE_UID16
asmlinkage long __powerpc_sys_chown16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lchown16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fchown16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setregid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setgid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setreuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setresuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getresuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setresgid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getresgid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setfsuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setfsgid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getgroups16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_setgroups16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_geteuid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getgid16(struct pt_regs *regs);
asmlinkage long __powerpc_sys_getegid16(struct pt_regs *regs);
#endif

/* obsolete: net/socket.c */
asmlinkage long __powerpc_sys_socketcall(struct pt_regs *regs);

/* obsolete: fs/stat.c */
asmlinkage long __powerpc_sys_stat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_lstat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_fstat(struct pt_regs *regs);
asmlinkage long __powerpc_sys_readlink(struct pt_regs *regs);

/* obsolete: fs/select.c */
asmlinkage long __powerpc_sys_old_select(struct pt_regs *regs);

/* obsolete: fs/readdir.c */
asmlinkage long __powerpc_sys_old_readdir(struct pt_regs *regs);

/* obsolete: kernel/sys.c */
asmlinkage long __powerpc_sys_gethostname(struct pt_regs *regs);
asmlinkage long __powerpc_sys_uname(struct pt_regs *regs);
asmlinkage long __powerpc_sys_olduname(struct pt_regs *regs);
#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
asmlinkage long __powerpc_sys_old_getrlimit(struct pt_regs *regs);
#endif

/* obsolete: ipc */
asmlinkage long __powerpc_sys_ipc(struct pt_regs *regs);

/* obsolete: mm/ */
asmlinkage long __powerpc_sys_mmap_pgoff(struct pt_regs *regs);
asmlinkage long __powerpc_sys_old_mmap(struct pt_regs *regs);


/*
 * Not a real system call, but a placeholder for syscalls which are
 * not implemented -- see kernel/__powerpc_sys_ni.c
 */
asmlinkage long __powerpc_sys_ni_syscall(struct pt_regs *regs);

asmlinkage long __powerpc_sys_io_setup(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_destroy(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_submit(struct pt_regs *regs);
asmlinkage long __powerpc_sys_io_cancel(struct pt_regs *regs);

#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */

#endif /* __KERNEL__ */
#endif /* __ASM_POWERPC_SYSCALLS_H */
