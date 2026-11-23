#ifndef BARE_SANDBOX_SEATBELT_H
#define BARE_SANDBOX_SEATBELT_H

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct sandbox_params;
struct sandbox_profile;

// Private libsandbox API, as used by Chromium. Compiling the profile in the
// parent leaves the child with only `sandbox_apply()` between `fork()` and
// `execve()`, which installs the compiled profile without interpreting it.
extern struct sandbox_params *
sandbox_create_params(void);

extern int
sandbox_set_param(struct sandbox_params *params, const char *key, const char *value);

extern void
sandbox_free_params(struct sandbox_params *params);

extern struct sandbox_profile *
sandbox_compile_string(const char *profile, struct sandbox_params *params, char **error);

extern void
sandbox_free_profile(struct sandbox_profile *profile);

extern int
sandbox_apply(struct sandbox_profile *profile);

extern int
sandbox_check(pid_t pid, const char *operation, int type, ...);

#define BARE_SANDBOX_FILTER_GLOBAL_NAME 2
#define BARE_SANDBOX_CHECK_NO_REPORT    0x40000000

#define BARE_SANDBOX_RUN_PREFIX "dev.holepunch.bare-sandbox.run."
#define BARE_SANDBOX_RUN_PROBE  BARE_SANDBOX_RUN_PREFIX "probe"

// A run is every process that inherits the profile of the workload. macOS has
// no unprivileged way to track a process tree that leaves its process group,
// so each profile allows looking up a random Mach service name that nothing
// else allows. No service by that name exists, so the grant gives nothing
// away, but `sandbox_check()` can find every process holding it. Every profile
// denies the rest of the prefix, which tells these apart from processes
// without a sandbox, as those allow every name.
typedef struct {
  struct sandbox_profile *profile;
  char marker[sizeof(BARE_SANDBOX_RUN_PREFIX) + 32];
  pid_t supervisor;
  int kq;
} bare_sandbox_backend_t;

// The profile is its source followed by pairs of parameter names and values.
// The source also refers to a parameter for the run marker, and one for each
// standard stream that names its terminal when the workload inherits one, as
// Seatbelt checks terminal control through inherited descriptors.
static inline int
bare_sandbox__prepare(char **profile, const uint32_t stdio[3], bare_sandbox_backend_t *backend, char **error) {
  uint8_t bytes[16];
  arc4random_buf(bytes, sizeof(bytes));

  size_t n = strlcpy(backend->marker, BARE_SANDBOX_RUN_PREFIX, sizeof(backend->marker));

  for (size_t i = 0; i < sizeof(bytes); i++, n += 2) {
    snprintf(&backend->marker[n], sizeof(backend->marker) - n, "%02x", bytes[i]);
  }

  struct sandbox_params *params = sandbox_create_params();
  if (params == NULL) return ENOMEM;

  for (size_t i = 1; profile[i] && profile[i + 1]; i += 2) {
    sandbox_set_param(params, profile[i], profile[i + 1]);
  }

  sandbox_set_param(params, "RUN", backend->marker);

  static const char *names[] = {"TERMINAL_0", "TERMINAL_1", "TERMINAL_2"};

  char terminals[3][MAXPATHLEN];

  for (int fd = 0; fd < 3; fd++) {
    if (stdio[fd] != bare_sandbox_stdio_inherit || ttyname_r(fd, terminals[fd], MAXPATHLEN) != 0) {
      strlcpy(terminals[fd], "/dev/null/none", MAXPATHLEN);
    }

    sandbox_set_param(params, names[fd], terminals[fd]);
  }

  backend->profile = sandbox_compile_string(profile[0], params, error);

  sandbox_free_params(params);

  return backend->profile == NULL ? EINVAL : 0;
}

static inline void
bare_sandbox__release(bare_sandbox_backend_t *backend) {
  sandbox_free_profile(backend->profile);
}

// Calls `fn` with every open descriptor, along with `data`. macOS has no
// `close_range()`, so the open descriptors are listed instead, which is a
// single system call. Should the list fill the buffer, it may be incomplete,
// and every possible descriptor is visited instead. Async-signal-safe, so the
// supervisor can use it too.
static inline void
bare_sandbox__for_each_fd(void (*fn)(int fd, int data), int data) {
  struct proc_fdinfo fds[1024];

  int size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, sizeof(fds));
  int len = size > 0 ? size / PROC_PIDLISTFD_SIZE : 0;

  if (len > 0 && len < 1024) {
    for (int i = 0; i < len; i++)
      fn(fds[i].proc_fd, data);
  } else {
    int max_fd = getdtablesize();

    for (int fd = 0; fd < max_fd; fd++)
      fn(fd, data);
  }
}

static inline void
bare_sandbox__set_cloexec(int fd, int data) {
  if (fd >= 3) fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static inline void
bare_sandbox__cloexec(void) {
  bare_sandbox__for_each_fd(bare_sandbox__set_cloexec, 0);
}

static inline bool
bare_sandbox__in_run(bare_sandbox_backend_t *backend, pid_t pid) {
  int type = BARE_SANDBOX_FILTER_GLOBAL_NAME | BARE_SANDBOX_CHECK_NO_REPORT;

  return sandbox_check(pid, "mach-lookup", type, BARE_SANDBOX_RUN_PROBE) == 1 &&
         sandbox_check(pid, "mach-lookup", type, backend->marker) == 0;
}

static inline int
bare_sandbox__max_processes(void) {
  int max;
  size_t len = sizeof(max);

  return sysctlbyname("kern.maxproc", &max, &len, NULL, 0) == 0 ? max : -1;
}

// Lists the processes of the run that are still running into `pids`, which
// has room for `max` processes. Only processes of the same user can be
// signalled, so only those are listed. Async-signal-safe, so the supervisor
// can use it too.
static inline int
bare_sandbox__list_run(bare_sandbox_backend_t *backend, pid_t *pids, int max) {
  int size = proc_listpids(PROC_UID_ONLY, getuid(), pids, max * sizeof(pid_t));
  if (size <= 0) return -1;

  int len = size / sizeof(pid_t), found = 0;

  for (int i = 0; i < len; i++) {
    if (pids[i] > 0 && bare_sandbox__in_run(backend, pids[i])) pids[found++] = pids[i];
  }

  return found;
}

// Kills every process of the run, and repeats until none is left, as a
// process may start another before it is killed.
static inline void
bare_sandbox__end_run(bare_sandbox_backend_t *backend, pid_t *pids, int max) {
  int len;

  while ((len = bare_sandbox__list_run(backend, pids, max)) > 0) {
    for (int i = 0; i < len; i++)
      kill(pids[i], SIGKILL);
  }
}

static inline void
bare_sandbox__close_unless(int fd, int keep) {
  if (fd != keep) close(fd);
}

// Runs in the forked child of the parent, which must therefore stick to
// async-signal-safe calls. Waits for the workload to exit, for the parent to
// die, or to be asked to stop by SIGTERM, then ends the run and exits like the
// workload did.
static _Noreturn void
bare_sandbox__supervise(bare_sandbox_backend_t *backend, pid_t workload, int report_fd) {
  pid_t parent = getppid();

  int max = bare_sandbox__max_processes();

  pid_t pids[max > 0 ? max : 1];

  // The queue still sees an ignored signal. It's set up before reporting, as
  // the parent only signals the supervisor once it has the report.
  struct sigaction action = {.sa_handler = SIG_IGN};
  sigaction(SIGTERM, &action, NULL);

  int kq = kqueue();

  struct kevent changes[3];
  EV_SET(&changes[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
  EV_SET(&changes[1], workload, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
  EV_SET(&changes[2], parent, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);

  // Watching a process that has already exited fails, so the run then ends
  // right away, as it does if there is no queue at all.
  bool watching = true;

  for (int i = 0; i < 3; i++) {
    if (kevent(kq, &changes[i], 1, NULL, 0, NULL) == -1) watching = false;
  }

  bare_sandbox__report(report_fd, workload);

  // Hold on to nothing of the parent's, so that its descriptors close when it
  // closes them.
  bare_sandbox__for_each_fd(bare_sandbox__close_unless, kq);

  if (watching && getppid() == parent) {
    struct kevent event;

    while (kevent(kq, NULL, 0, &event, 1, NULL) == -1 && errno == EINTR) {
    }
  }

  // The workload may not have entered the sandbox yet, which would keep it out
  // of the run.
  kill(workload, SIGKILL);

  if (max > 0) bare_sandbox__end_run(backend, pids, max);

  int status;

  while (waitpid(workload, &status, 0) == -1 && errno == EINTR) {
  }

  bare_sandbox__exit_like(status);
}

// Forks the workload from a supervisor that ends the run, whose processes are
// those that inherit the profile of the workload. Only the workload returns.
static inline int
bare_sandbox__contain(bare_sandbox_backend_t *backend, int report_fd) {
  pid_t workload = fork();
  if (workload == -1) return errno;

  if (workload > 0) bare_sandbox__supervise(backend, workload, report_fd);

  return 0;
}

static inline int
bare_sandbox__enter(bare_sandbox_backend_t *backend) {
  return sandbox_apply(backend->profile) == 0 ? 0 : EPERM;
}

static inline int
bare_sandbox__watch(bare_sandbox_backend_t *backend, pid_t pid) {
  backend->supervisor = pid;

  int kq = kqueue();
  if (kq == -1) return -1;

  struct kevent event;
  EV_SET(&event, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);

  if (kevent(kq, &event, 1, NULL, 0, NULL) == -1) {
    // The child has already exited, so wake the poll to reap it.
    EV_SET(&event, 0, EVFILT_USER, EV_ADD | EV_ONESHOT, NOTE_TRIGGER, 0, NULL);

    kevent(kq, &event, 1, NULL, 0, NULL);
  }

  backend->kq = kq;

  return kq;
}

static inline void
bare_sandbox__unwatch(bare_sandbox_backend_t *backend) {
  close(backend->kq);
}

static inline int
bare_sandbox__signal_run(bare_sandbox_backend_t *backend, int signum) {
  int max = bare_sandbox__max_processes();
  if (max <= 0) return -1;

  pid_t *pids = malloc(max * sizeof(pid_t));
  if (pids == NULL) return -1;

  int len = bare_sandbox__list_run(backend, pids, max);

  int sent = 0;

  for (int i = 0; i < len; i++) {
    if (kill(pids[i], signum) == 0) sent++;
  }

  free(pids);

  return len < 0 ? -1 : sent;
}

// The supervisor is a child that hasn't been reaped yet, so its process ID
// cannot have been reused.
static inline void
bare_sandbox__kill_run(bare_sandbox_backend_t *backend) {
  kill(backend->supervisor, SIGTERM);
}

#endif // BARE_SANDBOX_SEATBELT_H
