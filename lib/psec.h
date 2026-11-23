#ifndef BARE_SANDBOX_PSEC_H
#define BARE_SANDBOX_PSEC_H

#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <windows.h>


#include "sandbox.h"

// The process security environment API of `processmodel.dll`, available from
// Windows 11 24H2 with the August 2026 update. A security environment created
// from a "PSEC" FlatBuffer is attached to an otherwise ordinary
// `CreateProcessW()` call, which then starts the process in a BaseContainer.
typedef HRESULT(WINAPI *bare_sandbox_create_environment_t)(LPCVOID specification, DWORD size, DWORD flags, HANDLE *environment);

typedef void(WINAPI *bare_sandbox_close_environment_t)(HANDLE environment);

#define BARE_SANDBOX_PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT (35 | PROC_THREAD_ATTRIBUTE_INPUT)

static uv_once_t bare_sandbox__environment_guard = UV_ONCE_INIT;

static bare_sandbox_create_environment_t bare_sandbox__create_environment;
static bare_sandbox_close_environment_t bare_sandbox__close_environment;

static void
bare_sandbox__load_environment(void) {
  HMODULE module = LoadLibraryExW(L"processmodel.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (module == NULL) return;

  bare_sandbox_create_environment_t create = (bare_sandbox_create_environment_t) GetProcAddress(module, "CreateProcessSecurityEnvironment");
  bare_sandbox_close_environment_t close = (bare_sandbox_close_environment_t) GetProcAddress(module, "CloseProcessSecurityEnvironment");

  if (create == NULL || close == NULL) return;

  bare_sandbox__create_environment = create;
  bare_sandbox__close_environment = close;
}

struct bare_sandbox_process_s {
  uv_async_t async;

  HANDLE process;
  HANDLE job;
  HANDLE wait;
  HANDLE environment;

  int signal;
};

static WCHAR *
bare_sandbox__utf16(const char *str) {
  // The length includes the terminating null character.
  ssize_t len = uv_wtf8_length_as_utf16(str);
  if (len < 0) return NULL;

  WCHAR *result = malloc(len * sizeof(WCHAR));
  if (result == NULL) return NULL;

  uv_wtf8_to_utf16(str, (uint16_t *) result, len);

  return result;
}

// Quotes each argument such that `CommandLineToArgvW()` and the C runtime
// split the command line back into the same arguments. Backslashes are only
// special before a double quote, where each must be doubled.
static char *
bare_sandbox__command_line(char **args) {
  size_t size = 1;

  for (char **arg = args; *arg; arg++)
    size += strlen(*arg) * 2 + 3;

  char *line = malloc(size), *out = line;
  if (line == NULL) return NULL;

  for (char **arg = args; *arg; arg++) {
    if (arg != args) *out++ = ' ';

    const char *in = *arg;

    if (*in != '\0' && strpbrk(in, " \t\n\v\"") == NULL) {
      size_t len = strlen(in);
      memcpy(out, in, len);
      out += len;
      continue;
    }

    *out++ = '"';

    size_t backslashes = 0;

    for (; *in; in++) {
      if (*in == '\\') {
        backslashes++;
        continue;
      }

      size_t escapes = *in == '"' ? backslashes * 2 + 1 : backslashes;

      while (escapes--)
        *out++ = '\\';

      *out++ = *in;

      backslashes = 0;
    }

    for (size_t i = 0; i < backslashes * 2; i++)
      *out++ = '\\';

    *out++ = '"';
  }

  *out = '\0';

  return line;
}

static WCHAR *
bare_sandbox__environment_block(char **env) {
  size_t len = 1;

  for (char **pair = env; *pair; pair++) {
    ssize_t pair_len = uv_wtf8_length_as_utf16(*pair);
    if (pair_len < 0) return NULL;

    len += pair_len;
  }

  WCHAR *block = malloc(len * sizeof(WCHAR)), *out = block;
  if (block == NULL) return NULL;

  for (char **pair = env; *pair; pair++) {
    size_t pair_len = uv_wtf8_length_as_utf16(*pair);

    uv_wtf8_to_utf16(*pair, (uint16_t *) out, pair_len);

    out += pair_len;
  }

  *out = L'\0';

  return block;
}

// Returns the value of a hexadecimal digit, or -1 if it isn't one.
static int
bare_sandbox__nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bare_sandbox__decode_hex(const char *hex, uint8_t **result, size_t *len) {
  size_t hex_len = strlen(hex);
  if (hex_len % 2 != 0) return UV_EINVAL;

  *len = hex_len / 2;

  uint8_t *bytes = malloc(*len);
  if (bytes == NULL) return UV_ENOMEM;

  for (size_t i = 0; i < *len; i++) {
    int high = bare_sandbox__nibble(hex[i * 2]);
    int low = bare_sandbox__nibble(hex[i * 2 + 1]);

    if (high < 0 || low < 0) {
      free(bytes);
      return UV_EINVAL;
    }

    bytes[i] = (uint8_t) (high << 4 | low);
  }

  *result = bytes;

  return 0;
}

static void
bare_sandbox__close_fd(int fd) {
  uv_fs_t req;
  uv_fs_close(NULL, &req, fd, NULL);
  uv_fs_req_cleanup(&req);
}

static void
bare_sandbox__on_async(uv_async_t *handle) {
  bare_sandbox_process_t *process = (bare_sandbox_process_t *) handle;

  UnregisterWaitEx(process->wait, INVALID_HANDLE_VALUE);

  DWORD code = 0;
  GetExitCodeProcess(process->process, &code);

  TerminateJobObject(process->job, 1);

  bare_sandbox__on_exit(process, code, process->signal);
}

static void CALLBACK
bare_sandbox__on_wait(void *data, BOOLEAN timed_out) {
  bare_sandbox_process_t *process = (bare_sandbox_process_t *) data;

  uv_async_send(&process->async);
}

static int
bare_sandbox__win32_error(void) {
  return uv_translate_sys_error(GetLastError());
}

// Opens the handle the workload gets for the standard stream `fd`, if any,
// along with the descriptor the parent keeps of a pipe.
static int
bare_sandbox__open_stdio(int fd, uint32_t type, HANDLE *child, int *parent) {
  static const DWORD std_handles[3] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};

  SECURITY_ATTRIBUTES inherit = {.nLength = sizeof(inherit), .bInheritHandle = TRUE};

  HANDLE process = GetCurrentProcess();

  switch (type) {
  case bare_sandbox_stdio_pipe: {
    uv_file fds[2];

    int err = fd == 0 ? uv_pipe(fds, 0, UV_NONBLOCK_PIPE) : uv_pipe(fds, UV_NONBLOCK_PIPE, 0);
    if (err < 0) return err;

    *parent = fd == 0 ? fds[1] : fds[0];

    int end = fd == 0 ? fds[0] : fds[1];

    if (!DuplicateHandle(process, uv_get_osfhandle(end), process, child, 0, TRUE, DUPLICATE_SAME_ACCESS)) err = bare_sandbox__win32_error();

    bare_sandbox__close_fd(end);

    return err;
  }

  case bare_sandbox_stdio_ignore:
    *child = CreateFileW(L"NUL", fd == 0 ? GENERIC_READ : GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, NULL);

    if (*child == INVALID_HANDLE_VALUE) {
      *child = NULL;
      return bare_sandbox__win32_error();
    }

    return 0;

  case bare_sandbox_stdio_inherit: {
    HANDLE handle = GetStdHandle(std_handles[fd]);

    if (handle == NULL || handle == INVALID_HANDLE_VALUE) return 0;

    // Only the access the stream needs, as writing to the input of a console
    // would inject input into it, and reading its output would reveal what it
    // shows.
    if (!DuplicateHandle(process, handle, process, child, fd == 0 ? GENERIC_READ : GENERIC_WRITE, TRUE, 0)) return bare_sandbox__win32_error();

    return 0;
  }
  }

  return 0;
}

// A job keeps the run together, as processes started by the workload join it
// too, and closing the job kills whatever is left of the run.
static HANDLE
bare_sandbox__create_job(void) {
  HANDLE job = CreateJobObjectW(NULL, NULL);
  if (job == NULL) return NULL;

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    CloseHandle(job);
    return NULL;
  }

  return job;
}

// Returns 0 or a negative libuv error code, along with an optional message.
static int
bare_sandbox__spawn(uv_loop_t *loop, bare_sandbox_process_t *process, char **args, char **env, const char *cwd, char **profile, const uint32_t stdio[3], int parent_fds[3], int *pid, char **error) {
  uv_once(&bare_sandbox__environment_guard, bare_sandbox__load_environment);

  if (bare_sandbox__create_environment == NULL) {
    *error = _strdup("Process security environments are not available");
    return UV_ENOTSUP;
  }

  int err = 0;

  HANDLE handles[3] = {NULL, NULL, NULL};
  HANDLE inheritable[3];
  DWORD inheritable_len = 0;
  HANDLE environment = NULL;
  HANDLE job = NULL;
  LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
  WCHAR *application = NULL, *command_line = NULL, *block = NULL, *directory = NULL;

  for (int fd = 0; fd < 3; fd++) {
    err = bare_sandbox__open_stdio(fd, stdio[fd], &handles[fd], &parent_fds[fd]);
    if (err < 0) goto done;

    if (handles[fd]) inheritable[inheritable_len++] = handles[fd];
  }

  uint8_t *specification;
  size_t specification_len;

  err = bare_sandbox__decode_hex(profile[0], &specification, &specification_len);
  if (err < 0) goto done;

  HRESULT hr = bare_sandbox__create_environment(specification, (DWORD) specification_len, 0, &environment);

  free(specification);

  if (FAILED(hr)) {
    environment = NULL;

    *error = malloc(96);
    if (*error) snprintf(*error, 96, "Cannot create a process security environment (0x%08lx)", (unsigned long) hr);

    err = UV_EINVAL;
    goto done;
  }

  job = bare_sandbox__create_job();

  if (job == NULL) {
    err = bare_sandbox__win32_error();
    goto done;
  }

  // Only the standard streams are inherited, whatever else of the parent's is
  // marked inheritable.
  DWORD attribute_count = inheritable_len ? 2 : 1;
  SIZE_T attributes_size = 0;

  InitializeProcThreadAttributeList(NULL, attribute_count, 0, &attributes_size);

  attributes = malloc(attributes_size);

  if (attributes == NULL) {
    err = UV_ENOMEM;
    goto done;
  }

  if (!InitializeProcThreadAttributeList(attributes, attribute_count, 0, &attributes_size)) {
    free(attributes);
    attributes = NULL;

    err = bare_sandbox__win32_error();
    goto done;
  }

  if (
    !UpdateProcThreadAttribute(attributes, 0, BARE_SANDBOX_PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT, &environment, sizeof(environment), NULL, NULL) ||
    (inheritable_len && !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritable, inheritable_len * sizeof(HANDLE), NULL, NULL))
  ) {
    err = bare_sandbox__win32_error();
    goto done;
  }

  STARTUPINFOEXW startup = {0};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = handles[0];
  startup.StartupInfo.hStdOutput = handles[1];
  startup.StartupInfo.hStdError = handles[2];
  startup.lpAttributeList = attributes;

  char *line = bare_sandbox__command_line(args);

  if (line) {
    command_line = bare_sandbox__utf16(line);
    free(line);
  }

  application = bare_sandbox__utf16(args[0]);
  block = bare_sandbox__environment_block(env);
  directory = bare_sandbox__utf16(cwd);

  if (command_line == NULL || application == NULL || block == NULL || directory == NULL) {
    err = UV_ENOMEM;
    goto done;
  }

  // A console of its own, as one shared with the parent would let the workload
  // inject input into it. The process starts suspended so that it joins the
  // job before it runs, as the security environment ignores a job given as an
  // attribute.
  DWORD flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;

  PROCESS_INFORMATION info;

  if (!CreateProcessW(application, command_line, NULL, NULL, inheritable_len > 0, flags, block, directory, &startup.StartupInfo, &info)) {
    err = bare_sandbox__win32_error();
    goto done;
  }

  if (!AssignProcessToJobObject(job, info.hProcess)) {
    err = bare_sandbox__win32_error();

    TerminateProcess(info.hProcess, 1);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    goto done;
  }

  ResumeThread(info.hThread);
  CloseHandle(info.hThread);

  process->process = info.hProcess;
  process->job = job;
  process->environment = environment;
  process->signal = 0;

  job = NULL;
  environment = NULL;

  err = uv_async_init(loop, &process->async, bare_sandbox__on_async);
  assert(err == 0);

  if (!RegisterWaitForSingleObject(&process->wait, process->process, bare_sandbox__on_wait, process, INFINITE, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD)) {
    abort();
  }

  *pid = GetProcessId(process->process);

done:
  for (int fd = 0; fd < 3; fd++) {
    if (handles[fd]) CloseHandle(handles[fd]);

    if (err < 0 && parent_fds[fd] != -1) {
      bare_sandbox__close_fd(parent_fds[fd]);
      parent_fds[fd] = -1;
    }
  }

  if (attributes) {
    DeleteProcThreadAttributeList(attributes);
    free(attributes);
  }

  if (job) CloseHandle(job);
  if (environment) bare_sandbox__close_environment(environment);

  free(application);
  free(command_line);
  free(block);
  free(directory);

  return err;
}

// Windows has no signals, so those that terminate end the whole run, which is
// then reported as terminated by that signal.
static int
bare_sandbox__kill(bare_sandbox_process_t *process, int signum) {
  if (signum == 0) return WaitForSingleObject(process->process, 0) == WAIT_TIMEOUT;

  if (signum != SIGTERM && signum != SIGKILL && signum != SIGINT) return -1;

  if (!TerminateJobObject(process->job, 1)) return -1;

  if (process->signal == 0) process->signal = signum;

  return 1;
}

static void
bare_sandbox__terminate(bare_sandbox_process_t *process) {
  TerminateJobObject(process->job, 1);
}

static uv_handle_t *
bare_sandbox__handle(bare_sandbox_process_t *process) {
  return (uv_handle_t *) &process->async;
}

static void
bare_sandbox__dispose(bare_sandbox_process_t *process) {
  CloseHandle(process->process);
  CloseHandle(process->job);

  bare_sandbox__close_environment(process->environment);
}

#endif // BARE_SANDBOX_PSEC_H
