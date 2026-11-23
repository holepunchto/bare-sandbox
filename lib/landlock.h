#ifndef BARE_SANDBOX_LANDLOCK_H
#define BARE_SANDBOX_LANDLOCK_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/landlock.h>
#include <linux/netlink.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

// System calls from Linux 5.1 on share their numbers across architectures, so
// those the filter names are defined here for headers that predate them.
#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif

#ifndef __NR_setxattrat
#define __NR_setxattrat 463
#endif

#ifndef __NR_removexattrat
#define __NR_removexattrat 466
#endif

#ifndef __NR_file_setattr
#define __NR_file_setattr 469
#endif

// The last system call the filter was written against. Later ones are denied,
// as they might do what the filter denies.
#define BARE_SANDBOX_LAST_SYSCALL __NR_file_setattr

#ifdef __x86_64__
#define BARE_SANDBOX_AUDIT_ARCH AUDIT_ARCH_X86_64
#endif

#ifdef __aarch64__
#define BARE_SANDBOX_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

// The filter reads the low half of 64-bit syscall arguments.
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "Little endian required");

#define BARE_SANDBOX_NETWORK 1
#define BARE_SANDBOX_INGRESS 2

#define BARE_SANDBOX_FS_READ \
  (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

#define BARE_SANDBOX_FS_FILE \
  (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV)

typedef struct {
  int ruleset;
  int flags;
  pid_t supervisor;
  int pidfd;
} bare_sandbox_backend_t;

static inline uint64_t
bare_sandbox__handled_fs(void) {
  return LANDLOCK_ACCESS_FS_EXECUTE |
         LANDLOCK_ACCESS_FS_WRITE_FILE |
         LANDLOCK_ACCESS_FS_READ_FILE |
         LANDLOCK_ACCESS_FS_READ_DIR |
         LANDLOCK_ACCESS_FS_REMOVE_DIR |
         LANDLOCK_ACCESS_FS_REMOVE_FILE |
         LANDLOCK_ACCESS_FS_MAKE_CHAR |
         LANDLOCK_ACCESS_FS_MAKE_DIR |
         LANDLOCK_ACCESS_FS_MAKE_REG |
         LANDLOCK_ACCESS_FS_MAKE_SOCK |
         LANDLOCK_ACCESS_FS_MAKE_FIFO |
         LANDLOCK_ACCESS_FS_MAKE_BLOCK |
         LANDLOCK_ACCESS_FS_MAKE_SYM |
         LANDLOCK_ACCESS_FS_REFER |
         LANDLOCK_ACCESS_FS_TRUNCATE |
         LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

typedef struct {
  struct sock_filter code[256];
  unsigned short len;
} bare_sandbox_filter_t;

#define BARE_SANDBOX_ARG(i) (offsetof(struct seccomp_data, args) + (i) * sizeof(uint64_t))

#define BARE_SANDBOX_ALLOW SECCOMP_RET_ALLOW

#define BARE_SANDBOX_ERRNO(errno) (SECCOMP_RET_ERRNO | ((errno) & SECCOMP_RET_DATA))

static inline void
bare_sandbox__emit(bare_sandbox_filter_t *f, struct sock_filter code) {
  if (f->len == sizeof(f->code) / sizeof(f->code[0])) abort();

  f->code[f->len++] = code;
}

static inline void
bare_sandbox__load(bare_sandbox_filter_t *f, uint32_t offset) {
  bare_sandbox__emit(f, (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset));
}

static inline void
bare_sandbox__mask(bare_sandbox_filter_t *f, uint32_t mask) {
  bare_sandbox__emit(f, (struct sock_filter) BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask));
}

static inline void
bare_sandbox__return(bare_sandbox_filter_t *f, uint32_t action) {
  bare_sandbox__emit(f, (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, action));
}

// Returns `action` if the loaded value compares true against `k`.
static inline void
bare_sandbox__when(bare_sandbox_filter_t *f, uint16_t op, uint32_t k, uint32_t action) {
  bare_sandbox__emit(f, (struct sock_filter) BPF_JUMP(BPF_JMP | op | BPF_K, k, 0, 1));
  bare_sandbox__return(f, action);
}

// Returns `action` if the loaded value compares false against `k`.
static inline void
bare_sandbox__unless(bare_sandbox_filter_t *f, uint16_t op, uint32_t k, uint32_t action) {
  bare_sandbox__emit(f, (struct sock_filter) BPF_JUMP(BPF_JMP | op | BPF_K, k, 1, 0));
  bare_sandbox__return(f, action);
}

// Opens a block that runs if the loaded value equals `k`, and which must end
// in a return. Returns where the block starts, to be passed to `end()`.
static inline uint16_t
bare_sandbox__begin(bare_sandbox_filter_t *f, uint32_t k) {
  bare_sandbox__emit(f, (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, k, 0, 0));

  return f->len - 1;
}

static inline void
bare_sandbox__end(bare_sandbox_filter_t *f, uint16_t start) {
  f->code[start].jf = f->len - start - 1;
}

// Landlock governs the filesystem and TCP, and this filter covers what it
// doesn't:
//
// - Socket families, which also closes off Unix sockets as Landlock doesn't
//   govern connecting to them. Pairs may only be connected streams, as a
//   datagram socket could be addressed to any host socket.
// - io_uring, which can create sockets without a system call the filter sees.
// - User namespaces, which would give the workload capabilities within them.
// - Kernel keyrings, which hold secrets of the user.
// - System V IPC and POSIX message queues, which reach those of every process
//   of the user.
// - Injecting input into a terminal.
// - TCP Fast Open, which connects without the check Landlock applies.
// - Changing the resource limits of other processes.
// - System calls added after the filter was written.
// - Changing the mode, owner, timestamps, flags, or extended attributes of a
//   file, which Landlock doesn't govern, for a workload started by root, as
//   root owns the files of the system.
//
// Built in the forked workload, so it only writes to memory.
static inline void
bare_sandbox__build_filter(bare_sandbox_filter_t *f, int flags, bool root) {
  f->len = 0;

  bare_sandbox__load(f, offsetof(struct seccomp_data, arch));
  bare_sandbox__unless(f, BPF_JEQ, BARE_SANDBOX_AUDIT_ARCH, SECCOMP_RET_KILL_PROCESS);

  bare_sandbox__load(f, offsetof(struct seccomp_data, nr));

#ifdef __x86_64__
  bare_sandbox__when(f, BPF_JGE, __X32_SYSCALL_BIT, SECCOMP_RET_KILL_PROCESS);
#endif

  bare_sandbox__when(f, BPF_JGT, BARE_SANDBOX_LAST_SYSCALL, BARE_SANDBOX_ERRNO(ENOSYS));

  // `clone3()` passes its flags through a pointer the filter cannot read, so
  // callers fall back to `clone()`.
  static const struct {
    int nr;
    uint32_t action;
  } denied[] = {
    {__NR_io_uring_setup, BARE_SANDBOX_ERRNO(ENOSYS)},
    {__NR_io_uring_enter, BARE_SANDBOX_ERRNO(ENOSYS)},
    {__NR_io_uring_register, BARE_SANDBOX_ERRNO(ENOSYS)},
    {__NR_clone3, BARE_SANDBOX_ERRNO(ENOSYS)},
    {__NR_keyctl, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_add_key, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_request_key, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_shmget, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_shmat, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_shmctl, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_semget, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_semop, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_semtimedop, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_semctl, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_msgget, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_msgsnd, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_msgrcv, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_msgctl, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_mq_open, BARE_SANDBOX_ERRNO(EPERM)},
    {__NR_mq_unlink, BARE_SANDBOX_ERRNO(EPERM)},
  };

  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
    bare_sandbox__when(f, BPF_JEQ, denied[i].nr, denied[i].action);
  }

  static const int metadata[] = {
    __NR_fchmod,
    __NR_fchmodat,
    __NR_fchown,
    __NR_fchownat,
    __NR_utimensat,
    __NR_setxattr,
    __NR_lsetxattr,
    __NR_fsetxattr,
    __NR_removexattr,
    __NR_lremovexattr,
    __NR_fremovexattr,
#ifdef __NR_chmod
    __NR_chmod,
#endif
#ifdef __NR_chown
    __NR_chown,
#endif
#ifdef __NR_lchown
    __NR_lchown,
#endif
#ifdef __NR_utime
    __NR_utime,
#endif
#ifdef __NR_utimes
    __NR_utimes,
#endif
#ifdef __NR_futimesat
    __NR_futimesat,
#endif
    __NR_fchmodat2,
    __NR_setxattrat,
    __NR_removexattrat,
    __NR_file_setattr,
  };

  if (root) {
    for (size_t i = 0; i < sizeof(metadata) / sizeof(metadata[0]); i++) {
      bare_sandbox__when(f, BPF_JEQ, metadata[i], BARE_SANDBOX_ERRNO(EPERM));
    }
  }

  static const int namespacing[] = {__NR_unshare, __NR_clone};

  for (size_t i = 0; i < sizeof(namespacing) / sizeof(namespacing[0]); i++) {
    uint16_t block = bare_sandbox__begin(f, namespacing[i]);
    bare_sandbox__load(f, BARE_SANDBOX_ARG(0));
    bare_sandbox__when(f, BPF_JSET, CLONE_NEWUSER, BARE_SANDBOX_ERRNO(EPERM));
    bare_sandbox__return(f, BARE_SANDBOX_ALLOW);
    bare_sandbox__end(f, block);
  }

  uint16_t ioctl = bare_sandbox__begin(f, __NR_ioctl);
  bare_sandbox__load(f, BARE_SANDBOX_ARG(1));
  bare_sandbox__when(f, BPF_JEQ, TIOCSTI, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__when(f, BPF_JEQ, TIOCSCTTY, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__when(f, BPF_JEQ, TIOCLINUX, BARE_SANDBOX_ERRNO(EPERM));

  if (root) {
    bare_sandbox__when(f, BPF_JEQ, FS_IOC_SETFLAGS, BARE_SANDBOX_ERRNO(EPERM));
    bare_sandbox__when(f, BPF_JEQ, FS_IOC32_SETFLAGS, BARE_SANDBOX_ERRNO(EPERM));
    bare_sandbox__when(f, BPF_JEQ, FS_IOC_FSSETXATTR, BARE_SANDBOX_ERRNO(EPERM));
  }

  bare_sandbox__return(f, BARE_SANDBOX_ALLOW);
  bare_sandbox__end(f, ioctl);

  // Processes address themselves by 0.
  uint16_t prlimit = bare_sandbox__begin(f, __NR_prlimit64);
  bare_sandbox__load(f, BARE_SANDBOX_ARG(0));
  bare_sandbox__when(f, BPF_JEQ, 0, BARE_SANDBOX_ALLOW);
  bare_sandbox__return(f, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__end(f, prlimit);

  uint16_t socketpair = bare_sandbox__begin(f, __NR_socketpair);
  bare_sandbox__load(f, BARE_SANDBOX_ARG(0));
  bare_sandbox__unless(f, BPF_JEQ, AF_UNIX, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__load(f, BARE_SANDBOX_ARG(1));
  bare_sandbox__mask(f, ~(SOCK_NONBLOCK | SOCK_CLOEXEC));
  bare_sandbox__when(f, BPF_JEQ, SOCK_STREAM, BARE_SANDBOX_ALLOW);
  bare_sandbox__when(f, BPF_JEQ, SOCK_SEQPACKET, BARE_SANDBOX_ALLOW);
  bare_sandbox__return(f, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__end(f, socketpair);

  uint16_t socket = bare_sandbox__begin(f, __NR_socket);
  bare_sandbox__load(f, BARE_SANDBOX_ARG(0));

  // Only routing, which name resolution uses.
  uint16_t netlink = bare_sandbox__begin(f, AF_NETLINK);
  bare_sandbox__load(f, BARE_SANDBOX_ARG(2));
  bare_sandbox__when(f, BPF_JEQ, NETLINK_ROUTE, BARE_SANDBOX_ALLOW);
  bare_sandbox__return(f, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__end(f, netlink);

  static const int families[] = {AF_INET, AF_INET6};

  for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
    uint16_t block = bare_sandbox__begin(f, families[i]);

    if (flags & BARE_SANDBOX_NETWORK) {
      bare_sandbox__return(f, BARE_SANDBOX_ALLOW);
    } else if (flags & BARE_SANDBOX_INGRESS) {
      // Only TCP, which Landlock governs.
      bare_sandbox__load(f, BARE_SANDBOX_ARG(1));
      bare_sandbox__mask(f, ~(SOCK_NONBLOCK | SOCK_CLOEXEC));
      bare_sandbox__unless(f, BPF_JEQ, SOCK_STREAM, BARE_SANDBOX_ERRNO(EPERM));
      bare_sandbox__load(f, BARE_SANDBOX_ARG(2));
      bare_sandbox__when(f, BPF_JEQ, 0, BARE_SANDBOX_ALLOW);
      bare_sandbox__when(f, BPF_JEQ, IPPROTO_TCP, BARE_SANDBOX_ALLOW);
      bare_sandbox__return(f, BARE_SANDBOX_ERRNO(EPERM));
    } else {
      bare_sandbox__return(f, BARE_SANDBOX_ERRNO(EPERM));
    }

    bare_sandbox__end(f, block);
  }

  bare_sandbox__return(f, BARE_SANDBOX_ERRNO(EPERM));
  bare_sandbox__end(f, socket);

  if ((flags & BARE_SANDBOX_NETWORK) == 0) {
    static const struct {
      int nr;
      int flags;
    } sending[] = {{__NR_sendto, 3}, {__NR_sendmsg, 2}, {__NR_sendmmsg, 3}};

    for (size_t i = 0; i < sizeof(sending) / sizeof(sending[0]); i++) {
      uint16_t block = bare_sandbox__begin(f, sending[i].nr);
      bare_sandbox__load(f, BARE_SANDBOX_ARG(sending[i].flags));
      bare_sandbox__when(f, BPF_JSET, MSG_FASTOPEN, BARE_SANDBOX_ERRNO(EPERM));
      bare_sandbox__return(f, BARE_SANDBOX_ALLOW);
      bare_sandbox__end(f, block);
    }
  }

  bare_sandbox__return(f, BARE_SANDBOX_ALLOW);
}

// The path has already been resolved, so a symlink in it means that it changed
// since, and following it could grant something else.
static inline int
bare_sandbox__add_rule(int ruleset, const char *path, uint64_t access) {
  struct open_how how = {.flags = O_PATH | O_CLOEXEC, .resolve = RESOLVE_NO_SYMLINKS};

  int fd = syscall(__NR_openat2, AT_FDCWD, path, &how, sizeof(how));
  if (fd == -1) return errno;

  struct stat st;

  if (fstat(fd, &st) == -1) {
    int err = errno;
    close(fd);
    return err;
  }

  if (!S_ISDIR(st.st_mode)) access &= BARE_SANDBOX_FS_FILE;

  struct landlock_path_beneath_attr rule = {
    .allowed_access = access,
    .parent_fd = fd,
  };

  int err = syscall(__NR_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) == -1 ? errno : 0;

  close(fd);

  return err;
}

// The profile is a set of network flags followed by pairs of access, either
// `r` or `w`, and path.
static inline int
bare_sandbox__prepare(char **profile, const uint32_t stdio[3], bare_sandbox_backend_t *backend, char **error) {
  int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);

  if (abi < 6) {
    *error = strdup("Landlock ABI 6 or later is required");
    return ENOTSUP;
  }

  int flags = atoi(profile[0]);

  uint64_t handled = bare_sandbox__handled_fs();

  struct landlock_ruleset_attr attr = {
    .handled_access_fs = handled,
    .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
  };

  if ((flags & BARE_SANDBOX_NETWORK) == 0) attr.handled_access_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
  if ((flags & BARE_SANDBOX_INGRESS) == 0) attr.handled_access_net |= LANDLOCK_ACCESS_NET_BIND_TCP;

  int ruleset = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if (ruleset == -1) return errno;

  for (size_t i = 1; profile[i] && profile[i + 1]; i += 2) {
    const char *path = profile[i + 1];

    int err = bare_sandbox__add_rule(ruleset, path, profile[i][0] == 'w' ? handled : BARE_SANDBOX_FS_READ);

    if (err != 0) {
      close(ruleset);

      size_t size = strlen(path) + 64;
      *error = malloc(size);
      if (*error) snprintf(*error, size, "Cannot grant %s: %s", path, strerror(err));

      return err;
    }
  }

  backend->ruleset = ruleset;
  backend->flags = flags;

  return 0;
}

static inline void
bare_sandbox__release(bare_sandbox_backend_t *backend) {
  close(backend->ruleset);
}

static inline void
bare_sandbox__cloexec(void) {
  syscall(__NR_close_range, 3, ~0U, CLOSE_RANGE_CLOEXEC);
}

// Calls `fn` with each process ID listed in a `children` file of procfs.
// Async-signal-safe, so the supervisor can use it too.
static inline void
bare_sandbox__for_each_child(const char *path, void (*fn)(pid_t pid, void *data), void *data) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd == -1) return;

  char buf[4096];
  ssize_t len;
  pid_t pid = 0;

  while ((len = read(fd, buf, sizeof(buf))) > 0) {
    for (ssize_t i = 0; i < len; i++) {
      if (buf[i] >= '0' && buf[i] <= '9') {
        pid = pid * 10 + (buf[i] - '0');
      } else if (pid != 0) {
        fn(pid, data);
        pid = 0;
      }
    }
  }

  if (pid != 0) fn(pid, data);

  close(fd);
}

static inline void
bare_sandbox__kill_child(pid_t pid, void *data) {
  kill(pid, SIGKILL);
}

// Runs in the forked child of the parent, which must therefore stick to
// async-signal-safe calls. As a subreaper, every process of the run that
// loses its parent is reparented to the supervisor, even if it left the
// session or process group, so whatever is left can be killed when the
// workload exits, when the parent dies, or when asked to by SIGTERM. The
// supervisor then exits like the workload did.
static _Noreturn void
bare_sandbox__supervise(pid_t workload, int report_fd) {
  pid_t parent = getppid();

  // Blocked before reporting, as the parent only signals the supervisor once
  // it has the report.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  sigaddset(&set, SIGTERM);
  sigprocmask(SIG_BLOCK, &set, NULL);

  bare_sandbox__report(report_fd, workload);

  // Hold on to nothing of the parent's, so that its descriptors close when it
  // closes them.
  syscall(__NR_close_range, 0, ~0U, 0);

  prctl(PR_SET_PDEATHSIG, SIGTERM);

  bool exited = false;
  int status = 0;

  // Wait for the workload to exit, or to be asked to stop, which includes the
  // parent having died before the death signal was set up.
  while (getppid() == parent) {
    int wstatus;
    pid_t pid;

    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
      if (pid == workload) {
        status = wstatus;
        exited = true;
      }
    }

    if (exited || sigwaitinfo(&set, NULL) == SIGTERM) break;
  }

  for (;;) {
    if (!exited) kill(workload, SIGKILL);

    // The supervisor has a single thread, and every orphan of the run is
    // reparented to it.
    bare_sandbox__for_each_child("/proc/thread-self/children", bare_sandbox__kill_child, NULL);

    int wstatus;
    pid_t pid = waitpid(-1, &wstatus, 0);

    if (pid == -1) {
      if (errno == EINTR) continue;
      break;
    }

    if (pid == workload) {
      status = wstatus;
      exited = true;
    }
  }

  bare_sandbox__exit_like(status);
}

// Forks the workload from a supervisor that keeps the run together. Only the
// workload returns.
static inline int
bare_sandbox__contain(bare_sandbox_backend_t *backend, int report_fd) {
  if (prctl(PR_SET_CHILD_SUBREAPER, 1) == -1) return errno;

  pid_t workload = fork();
  if (workload == -1) return errno;

  if (workload > 0) bare_sandbox__supervise(workload, report_fd);

  return 0;
}

// A workload started by root would otherwise keep every capability, which
// Landlock doesn't restrict, such as loading kernel modules.
static inline int
bare_sandbox__drop_capabilities(void) {
  if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED) == -1) return errno;

  for (int cap = 0; prctl(PR_CAPBSET_READ, cap) >= 0; cap++) {
    if (prctl(PR_CAPBSET_DROP, cap) == -1) return errno;
  }

  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == -1) return errno;

  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct data[2] = {{0}};

  if (syscall(__NR_capset, &header, data) == -1) return errno;

  return 0;
}

static inline int
bare_sandbox__enter(bare_sandbox_backend_t *backend) {
  bool root = geteuid() == 0;

  bare_sandbox_filter_t filter;
  bare_sandbox__build_filter(&filter, backend->flags, root);

  struct sock_fprog program = {.len = filter.len, .filter = filter.code};

  if (root) {
    int err = bare_sandbox__drop_capabilities();
    if (err != 0) return err;
  }

  if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) return errno;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) return errno;
  if (syscall(__NR_landlock_restrict_self, backend->ruleset, 0) == -1) return errno;
  if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == -1) return errno;

  return 0;
}

static inline int
bare_sandbox__watch(bare_sandbox_backend_t *backend, pid_t supervisor) {
  backend->supervisor = supervisor;
  backend->pidfd = syscall(__NR_pidfd_open, supervisor, 0);

  return backend->pidfd;
}

static inline void
bare_sandbox__unwatch(bare_sandbox_backend_t *backend) {
  close(backend->pidfd);
}

typedef struct {
  pid_t *pids;
  int *fds;
  size_t len;
  size_t cap;
  bool failed;
} bare_sandbox_pids_t;

static inline bool
bare_sandbox__push(bare_sandbox_pids_t *list, pid_t pid, int fd) {
  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 16;

    pid_t *pids = realloc(list->pids, cap * sizeof(pid_t));
    if (pids) list->pids = pids;

    int *fds = realloc(list->fds, cap * sizeof(int));
    if (fds) list->fds = fds;

    if (pids == NULL || fds == NULL) {
      list->failed = true;
      return false;
    }

    list->cap = cap;
  }

  list->pids[list->len] = pid;
  list->fds[list->len] = fd;
  list->len++;

  return true;
}

static inline void
bare_sandbox__push_pid(pid_t pid, void *data) {
  bare_sandbox__push(data, pid, -1);
}

static inline void
bare_sandbox__free_pids(bare_sandbox_pids_t *list) {
  free(list->pids);
  free(list->fds);
}

// Lists the children of every thread of `pid`.
static inline void
bare_sandbox__list_children(pid_t pid, bare_sandbox_pids_t *result) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/task", pid);

  DIR *dir = opendir(path);
  if (dir == NULL) return;

  struct dirent *entry;

  while ((entry = readdir(dir))) {
    if (entry->d_name[0] == '.') continue;

    char children[96];
    snprintf(children, sizeof(children), "/proc/%d/task/%s/children", pid, entry->d_name);

    bare_sandbox__for_each_child(children, bare_sandbox__push_pid, result);
  }

  closedir(dir);
}

static inline bool
bare_sandbox__listed(bare_sandbox_pids_t *list, pid_t pid) {
  for (size_t i = 0; i < list->len; i++) {
    if (list->pids[i] == pid) return true;
  }

  return false;
}

static inline bool
bare_sandbox__running(int pidfd) {
  struct pollfd pfd = {.fd = pidfd, .events = POLLIN};

  return poll(&pfd, 1, 0) == 0;
}

// Signals every descendant of the supervisor, found through the children of
// each of their threads. A child is only signalled through a descriptor that
// was opened while its parent listed it, and only if the parent still lists it
// and is still running afterwards, as its process ID could otherwise have been
// reused by a process outside the run.
static inline int
bare_sandbox__signal_run(bare_sandbox_backend_t *backend, int signum) {
  bare_sandbox_pids_t run = {0};

  bare_sandbox__push(&run, backend->supervisor, backend->pidfd);

  int sent = 0;

  for (size_t i = 0; i < run.len; i++) {
    pid_t parent = run.pids[i];

    bare_sandbox_pids_t before = {0}, after = {0};

    bare_sandbox__list_children(parent, &before);

    for (size_t j = 0; j < before.len; j++) {
      before.fds[j] = syscall(__NR_pidfd_open, before.pids[j], 0);
    }

    bare_sandbox__list_children(parent, &after);

    bool running = bare_sandbox__running(run.fds[i]);

    for (size_t j = 0; j < before.len; j++) {
      int fd = before.fds[j];

      if (fd == -1) continue;

      bool member = running && bare_sandbox__listed(&after, before.pids[j]);

      if (!member || !bare_sandbox__push(&run, before.pids[j], fd)) close(fd);
    }

    if (before.failed || after.failed) run.failed = true;

    bare_sandbox__free_pids(&before);
    bare_sandbox__free_pids(&after);

    if (i > 0 && syscall(__NR_pidfd_send_signal, run.fds[i], signum, NULL, 0) == 0) sent++;
  }

  for (size_t i = 1; i < run.len; i++) {
    close(run.fds[i]);
  }

  bare_sandbox__free_pids(&run);

  // Processes that didn't fit weren't signalled.
  return run.failed ? -1 : sent;
}

// The supervisor does the work, and a descriptor rather than a process ID
// keeps the signal from reaching another process after it has exited.
static inline void
bare_sandbox__kill_run(bare_sandbox_backend_t *backend) {
  syscall(__NR_pidfd_send_signal, backend->pidfd, SIGTERM, NULL, 0);
}

#endif // BARE_SANDBOX_LANDLOCK_H
