#ifndef BARE_SANDBOX_POSIX_H
#define BARE_SANDBOX_POSIX_H

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uv.h>

#include "sandbox.h"

// Writes a message to the report pipe of the parent, which waits for either a
// positive process ID of the workload, when it isn't the direct child, or a
// negated `errno` if starting it failed. End of file means that it started.
static void
bare_sandbox__report(int fd, int message) {
  ssize_t res;

  do {
    res = write(fd, &message, sizeof(message));
  } while (res == -1 && errno == EINTR);
}

// Exits like a process that ended with `status`, without dumping core. Only
// makes async-signal-safe calls, for the supervisor.
static _Noreturn void
bare_sandbox__exit_like(int status) {
  if (WIFSIGNALED(status)) {
    int signum = WTERMSIG(status);

    struct rlimit none = {0, 0};
    setrlimit(RLIMIT_CORE, &none);

    struct sigaction action = {.sa_handler = SIG_DFL};
    sigaction(signum, &action, NULL);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    sigprocmask(SIG_UNBLOCK, &set, NULL);

    kill(getpid(), signum);

    _exit(128 + signum);
  }

  _exit(WEXITSTATUS(status));
}

#ifdef __APPLE__
#include "seatbelt.h"
#endif

#ifdef __linux__
#include "landlock.h"
#endif

struct bare_sandbox_process_s {
  uv_poll_t poll;

  pid_t pid;
  bare_sandbox_backend_t backend;
};

static void
bare_sandbox__on_poll(uv_poll_t *handle, int status, int events) {
  int err;

  bare_sandbox_process_t *process = (bare_sandbox_process_t *) handle;

  // The watched descriptor only becomes readable once the supervisor has
  // exited.
  pid_t pid;
  int wstatus;

  do {
    pid = waitpid(process->pid, &wstatus, 0);
  } while (pid == -1 && errno == EINTR);

  assert(pid == process->pid);

  err = uv_poll_stop(handle);
  assert(err == 0);

  bare_sandbox__on_exit(process, WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 0, WIFSIGNALED(wstatus) ? WTERMSIG(wstatus) : 0);
}

static void
bare_sandbox__close_fd(int fd) {
  close(fd);
}

static int
bare_sandbox__dup_above_stdio(int fd) {
  int dup = fcntl(fd, F_DUPFD_CLOEXEC, 3);

  close(fd);

  return dup;
}

static int
bare_sandbox__pipe(int fds[2]) {
  if (uv_pipe(fds, 0, 0) < 0) return -1;

  fds[0] = bare_sandbox__dup_above_stdio(fds[0]);
  fds[1] = bare_sandbox__dup_above_stdio(fds[1]);

  if (fds[0] == -1 || fds[1] == -1) {
    if (fds[0] != -1) close(fds[0]);
    if (fds[1] != -1) close(fds[1]);

    return -1;
  }

  return 0;
}

static _Noreturn void
bare_sandbox__report_and_exit(int fd, int error) {
  bare_sandbox__report(fd, -error);

  _exit(127);
}

static void
bare_sandbox__child(int report_fd, int child_fds[3], const char *cwd, bare_sandbox_backend_t *backend, char **argv, char **envp) {
  if (setsid() == -1) bare_sandbox__report_and_exit(report_fd, errno);

  for (int fd = 0; fd < 3; fd++) {
    if (child_fds[fd] == -1) {
      if (fcntl(fd, F_SETFD, 0) == -1 && errno != EBADF) bare_sandbox__report_and_exit(report_fd, errno);
    } else {
      if (dup2(child_fds[fd], fd) == -1) bare_sandbox__report_and_exit(report_fd, errno);
    }
  }

  // Nothing the parent opened may reach the workload, as the sandbox only
  // governs what the workload opens itself. The report pipe is already
  // close-on-exec, which is how the parent learns that `execve()` succeeded.
  bare_sandbox__cloexec();

  struct sigaction action = {.sa_handler = SIG_DFL};

  for (int signum = 1; signum < NSIG; signum++) {
    if (signum == SIGKILL || signum == SIGSTOP) continue;

    sigaction(signum, &action, NULL);
  }

  sigset_t set;
  sigemptyset(&set);

  if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) bare_sandbox__report_and_exit(report_fd, errno);

  int err = bare_sandbox__contain(backend, report_fd);
  if (err != 0) bare_sandbox__report_and_exit(report_fd, err);

  err = bare_sandbox__enter(backend);
  if (err != 0) bare_sandbox__report_and_exit(report_fd, err);

  if (chdir(cwd) == -1) bare_sandbox__report_and_exit(report_fd, errno);

  execve(argv[0], argv, envp);

  bare_sandbox__report_and_exit(report_fd, errno);
}

static int
bare_sandbox__await_report(int fd, pid_t *workload) {
  for (;;) {
    int message;
    ssize_t res;

    do {
      res = read(fd, &message, sizeof(message));
    } while (res == -1 && errno == EINTR);

    if (res <= 0) return 0;

    if (message > 0) *workload = message;
    else return -message;
  }
}

// Returns 0 or a negative libuv error code, along with an optional message.
static int
bare_sandbox__spawn(uv_loop_t *loop, bare_sandbox_process_t *process, char **args, char **env, const char *cwd, char **profile, const uint32_t stdio[3], int parent_fds[3], int *pid, char **error) {
  int err;

  bare_sandbox_backend_t backend;

  err = bare_sandbox__prepare(profile, stdio, &backend, error);
  if (err != 0) return uv_translate_sys_error(err);

  int child_fds[3] = {-1, -1, -1};
  int report_fds[2] = {-1, -1};

  for (int fd = 0; fd < 3; fd++) {
    switch (stdio[fd]) {
    case bare_sandbox_stdio_ignore:
      child_fds[fd] = open("/dev/null", (fd == 0 ? O_RDONLY : O_WRONLY) | O_CLOEXEC);
      if (child_fds[fd] == -1) goto fail;

      child_fds[fd] = bare_sandbox__dup_above_stdio(child_fds[fd]);
      if (child_fds[fd] == -1) goto fail;
      break;

    case bare_sandbox_stdio_pipe: {
      int fds[2];
      if (bare_sandbox__pipe(fds) == -1) goto fail;

      parent_fds[fd] = fd == 0 ? fds[1] : fds[0];
      child_fds[fd] = fd == 0 ? fds[0] : fds[1];
      break;
    }
    }
  }

  if (bare_sandbox__pipe(report_fds) == -1) goto fail;

  sigset_t all, previous;
  sigfillset(&all);

  // Keep the parent's signal handlers from running in the child before it
  // resets them.
  err = pthread_sigmask(SIG_SETMASK, &all, &previous);
  assert(err == 0);

  pid_t child = fork();

  if (child == 0) {
    close(report_fds[0]);

    bare_sandbox__child(report_fds[1], child_fds, cwd, &backend, args, env);
  }

  int fork_error = errno;

  err = pthread_sigmask(SIG_SETMASK, &previous, NULL);
  assert(err == 0);

  if (child == -1) {
    errno = fork_error;
    goto fail;
  }

  close(report_fds[1]);
  report_fds[1] = -1;

  pid_t workload = child;

  int child_error = bare_sandbox__await_report(report_fds[0], &workload);

  if (child_error != 0) {
    int status;

    do {
      err = waitpid(child, &status, 0);
    } while (err == -1 && errno == EINTR);

    errno = child_error;
    goto fail;
  }

  process->pid = child;
  process->backend = backend;

  int fd = bare_sandbox__watch(&process->backend, child);

  if (fd == -1) {
    int watch_error = errno;

    // The supervisor ends the run when asked to, and as a child that hasn't
    // been reaped, its process ID cannot have been reused.
    kill(child, SIGTERM);

    int status;

    do {
      err = waitpid(child, &status, 0);
    } while (err == -1 && errno == EINTR);

    errno = watch_error;
    goto fail;
  }

  err = uv_poll_init(loop, &process->poll, fd);
  assert(err == 0);

  err = uv_poll_start(&process->poll, UV_READABLE, bare_sandbox__on_poll);
  assert(err == 0);

  *pid = workload;

  err = 0;

  goto done;

fail:
  err = uv_translate_sys_error(errno);

  for (int fd = 0; fd < 3; fd++) {
    if (parent_fds[fd] != -1) close(parent_fds[fd]);

    parent_fds[fd] = -1;
  }

done:
  for (int fd = 0; fd < 3; fd++) {
    if (child_fds[fd] != -1) close(child_fds[fd]);
  }

  if (report_fds[0] != -1) close(report_fds[0]);
  if (report_fds[1] != -1) close(report_fds[1]);

  bare_sandbox__release(&backend);

  return err;
}

static int
bare_sandbox__kill(bare_sandbox_process_t *process, int signum) {
  return bare_sandbox__signal_run(&process->backend, signum);
}

static void
bare_sandbox__terminate(bare_sandbox_process_t *process) {
  bare_sandbox__kill_run(&process->backend);
}

static uv_handle_t *
bare_sandbox__handle(bare_sandbox_process_t *process) {
  return (uv_handle_t *) &process->poll;
}

static void
bare_sandbox__dispose(bare_sandbox_process_t *process) {
  bare_sandbox__unwatch(&process->backend);
}

#endif // BARE_SANDBOX_POSIX_H
