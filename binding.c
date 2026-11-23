#include <assert.h>
#include <bare.h>
#include <js.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <utf.h>
#include <uv.h>

#ifdef _WIN32
#include "lib/psec.h"
#else
#include "lib/posix.h"
#endif

typedef struct {
  bare_sandbox_process_t process;

  js_env_t *env;
  js_ref_t *handle;
  js_ref_t *ctx;
  js_ref_t *on_exit;

  bool exited;
  bool exiting;

  js_deferred_teardown_t *teardown;
} bare_sandbox_t;

static int
bare_sandbox__expect_type(js_env_t *env, js_value_t *value, js_value_type_t expected, const char *message) {
  int err;

  js_value_type_t type;
  err = js_typeof(env, value, &type);
  if (err < 0) return err;

  if (type != expected) {
    js_throw_type_error(env, NULL, message);

    return -1;
  }

  return 0;
}

static int
bare_sandbox__expect_array(js_env_t *env, js_value_t *value, const char *message) {
  int err;

  bool is_array;
  err = js_is_array(env, value, &is_array);
  if (err < 0) return err;

  if (!is_array) {
    js_throw_type_error(env, NULL, message);

    return -1;
  }

  return 0;
}

static int
bare_sandbox__get_string(js_env_t *env, js_value_t *value, char **result) {
  int err;

  err = bare_sandbox__expect_type(env, value, js_string, "Expected a string");
  if (err < 0) return err;

  size_t len;
  err = js_get_value_string_utf8(env, value, NULL, 0, &len);
  if (err < 0) return err;

  utf8_t *str = malloc(len + 1);

  if (str == NULL) {
    js_throw_error(env, uv_err_name(UV_ENOMEM), uv_strerror(UV_ENOMEM));
    return -1;
  }

  err = js_get_value_string_utf8(env, value, str, len + 1, NULL);
  if (err < 0) {
    free(str);
    return err;
  }

  *result = (char *) str;

  return 0;
}

static void
bare_sandbox__free_strings(char **strings) {
  if (strings == NULL) return;

  for (char **string = strings; *string; string++)
    free(*string);

  free(strings);
}

static int
bare_sandbox__get_strings(js_env_t *env, js_value_t *array, char ***result) {
  int err;

  err = bare_sandbox__expect_array(env, array, "Expected an array of strings");
  if (err < 0) return err;

  uint32_t len;
  err = js_get_array_length(env, array, &len);
  if (err < 0) return err;

  js_value_t **values = calloc(len, sizeof(js_value_t *));
  char **strings = calloc((size_t) len + 1, sizeof(char *));

  if (values == NULL || strings == NULL) {
    free(values);
    free(strings);

    js_throw_error(env, uv_err_name(UV_ENOMEM), uv_strerror(UV_ENOMEM));
    return -1;
  }

  err = js_get_array_elements(env, array, values, len, 0, NULL);

  for (uint32_t i = 0; err == 0 && i < len; i++) {
    err = bare_sandbox__get_string(env, values[i], &strings[i]);
  }

  free(values);

  if (err < 0) {
    bare_sandbox__free_strings(strings);
    return err;
  }

  *result = strings;

  return 0;
}

static int
bare_sandbox__get_stdio(js_env_t *env, js_value_t *array, uint32_t stdio[3]) {
  int err;

  err = bare_sandbox__expect_array(env, array, "Expected an array of stdio types");
  if (err < 0) return err;

  uint32_t len;
  err = js_get_array_length(env, array, &len);
  if (err < 0) return err;

  if (len != 3) {
    js_throw_range_error(env, NULL, "Expected exactly three stdio types");
    return -1;
  }

  js_value_t *values[3];
  err = js_get_array_elements(env, array, values, 3, 0, NULL);
  if (err < 0) return err;

  for (int fd = 0; fd < 3; fd++) {
    err = bare_sandbox__expect_type(env, values[fd], js_number, "Expected a stdio type");
    if (err < 0) return err;

    err = js_get_value_uint32(env, values[fd], &stdio[fd]);
    if (err < 0) return err;

    if (stdio[fd] > bare_sandbox_stdio_pipe) {
      js_throw_range_error(env, NULL, "Unknown stdio type");
      return -1;
    }
  }

  return 0;
}

static int
bare_sandbox__get_sandbox(js_env_t *env, js_value_t *value, bare_sandbox_t **result) {
  int err;

  bool is_arraybuffer;
  err = js_is_arraybuffer(env, value, &is_arraybuffer);
  if (err < 0) return err;

  if (!is_arraybuffer) {
    js_throw_type_error(env, NULL, "Expected a sandbox handle");
    return -1;
  }

  size_t len;
  err = js_get_arraybuffer_info(env, value, (void **) result, &len);
  if (err < 0) return err;

  if (len != sizeof(bare_sandbox_t)) {
    js_throw_type_error(env, NULL, "Expected a sandbox handle");
    return -1;
  }

  return 0;
}

static int
bare_sandbox__get_args(js_env_t *env, js_callback_info_t *info, size_t expected, js_value_t **argv) {
  int err;

  size_t argc = expected;
  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  if (err < 0) return err;

  if (argc != expected) {
    js_throw_type_error(env, NULL, "Unexpected number of arguments");
    return -1;
  }

  return 0;
}

static void
bare_sandbox__on_close(uv_handle_t *handle) {
  int err;

  bare_sandbox_t *sandbox = (bare_sandbox_t *) handle;

  js_env_t *env = sandbox->env;
  js_ref_t *ref = sandbox->handle;
  js_deferred_teardown_t *teardown = sandbox->teardown;

  bare_sandbox__dispose(&sandbox->process);

  err = js_delete_reference(env, sandbox->on_exit);
  assert(err == 0);

  err = js_delete_reference(env, sandbox->ctx);
  assert(err == 0);

  // The handle holds the sandbox itself, so it goes last.
  err = js_delete_reference(env, ref);
  assert(err == 0);

  err = js_finish_deferred_teardown_callback(teardown);
  assert(err == 0);
}

static void
bare_sandbox__on_exit(bare_sandbox_process_t *process, int64_t exit_status, int term_signal) {
  int err;

  bare_sandbox_t *sandbox = (bare_sandbox_t *) process;

  sandbox->exited = true;

  if (sandbox->exiting) goto close;

  js_env_t *env = sandbox->env;

  js_handle_scope_t *scope;
  err = js_open_handle_scope(env, &scope);
  assert(err == 0);

  js_value_t *ctx;
  err = js_get_reference_value(env, sandbox->ctx, &ctx);
  assert(err == 0);

  js_value_t *on_exit;
  err = js_get_reference_value(env, sandbox->on_exit, &on_exit);
  assert(err == 0);

  js_value_t *argv[2];

  err = js_create_int64(env, exit_status, &argv[0]);
  assert(err == 0);

  err = js_create_int32(env, term_signal, &argv[1]);
  assert(err == 0);

  js_call_function(env, ctx, on_exit, 2, argv, NULL);

  err = js_close_handle_scope(env, scope);
  assert(err == 0);

close:
  uv_close(bare_sandbox__handle(process), bare_sandbox__on_close);
}

static void
bare_sandbox__on_teardown(js_deferred_teardown_t *handle, void *data) {
  bare_sandbox_t *sandbox = (bare_sandbox_t *) data;

  sandbox->exiting = true;

  if (sandbox->exited) return;

  bare_sandbox__terminate(&sandbox->process);
}

static js_value_t *
bare_sandbox__create_result(js_env_t *env, js_value_t *handle, int pid, const int parent_fds[3]) {
  int err;

  js_value_t *elements[5] = {handle};

  err = js_create_int32(env, pid, &elements[1]);
  if (err < 0) return NULL;

  for (int fd = 0; fd < 3; fd++) {
    err = js_create_int32(env, parent_fds[fd], &elements[2 + fd]);
    if (err < 0) return NULL;
  }

  js_value_t *result;
  err = js_create_array_with_elements(env, elements, 5, &result);
  if (err < 0) return NULL;

  return result;
}

static js_value_t *
bare_sandbox_spawn(js_env_t *env, js_callback_info_t *info) {
  int err;

  js_value_t *argv[7];
  err = bare_sandbox__get_args(env, info, 7, argv);
  if (err < 0) return NULL;

  err = bare_sandbox__expect_type(env, argv[0], js_object, "Expected a context object");
  if (err < 0) return NULL;

  err = bare_sandbox__expect_type(env, argv[1], js_function, "Expected an exit callback");
  if (err < 0) return NULL;

  uv_loop_t *loop;
  err = js_get_env_loop(env, &loop);
  if (err < 0) return NULL;

  js_value_t *result = NULL;

  char **args = NULL, **pairs = NULL, **profile = NULL, *cwd = NULL;
  uint32_t stdio[3];

  if (
    bare_sandbox__get_strings(env, argv[2], &args) < 0 ||
    bare_sandbox__get_strings(env, argv[3], &pairs) < 0 ||
    bare_sandbox__get_string(env, argv[4], &cwd) < 0 ||
    bare_sandbox__get_strings(env, argv[5], &profile) < 0 ||
    bare_sandbox__get_stdio(env, argv[6], stdio) < 0
  ) {
    goto done;
  }

  if (args[0] == NULL || profile[0] == NULL) {
    js_throw_range_error(env, NULL, "Expected a file and a profile");
    goto done;
  }

  js_value_t *handle;

  bare_sandbox_t *sandbox;
  err = js_create_arraybuffer(env, sizeof(bare_sandbox_t), (void **) &sandbox, &handle);
  if (err < 0) goto done;

  sandbox->env = env;
  sandbox->handle = NULL;
  sandbox->ctx = NULL;
  sandbox->on_exit = NULL;
  sandbox->exited = false;
  sandbox->exiting = false;

  // Everything that may fail on the JavaScript side happens before the
  // workload starts, so that a failure never leaves one behind.
  // Libuv uses the sandbox until the handle is closed, whatever becomes of the
  // handle in JavaScript.
  err = js_create_reference(env, handle, 1, &sandbox->handle);
  if (err < 0) goto done;

  err = js_create_reference(env, argv[0], 1, &sandbox->ctx);
  if (err < 0) goto unreference;

  err = js_create_reference(env, argv[1], 1, &sandbox->on_exit);
  if (err < 0) goto unreference;

  err = js_add_deferred_teardown_callback(env, bare_sandbox__on_teardown, (void *) sandbox, &sandbox->teardown);
  if (err < 0) goto unreference;

  int parent_fds[3] = {-1, -1, -1};
  int pid;
  char *error = NULL;

  err = bare_sandbox__spawn(loop, &sandbox->process, args, pairs, cwd, profile, stdio, parent_fds, &pid, &error);

  if (err < 0) {
    js_throw_error(env, uv_err_name(err), error ? error : uv_strerror(err));

    free(error);

    err = js_finish_deferred_teardown_callback(sandbox->teardown);
    assert(err == 0);

    goto unreference;
  }

  result = bare_sandbox__create_result(env, handle, pid, parent_fds);

  if (result == NULL) {
    // The workload is already running, so it's ended, and closing the handle
    // once it has exited releases the references and finishes the teardown.
    sandbox->exiting = true;

    bare_sandbox__terminate(&sandbox->process);

    for (int fd = 0; fd < 3; fd++) {
      if (parent_fds[fd] != -1) bare_sandbox__close_fd(parent_fds[fd]);
    }
  }

  goto done;

unreference:
  if (sandbox->on_exit) js_delete_reference(env, sandbox->on_exit);
  if (sandbox->ctx) js_delete_reference(env, sandbox->ctx);
  if (sandbox->handle) js_delete_reference(env, sandbox->handle);

done:
  bare_sandbox__free_strings(profile);
  bare_sandbox__free_strings(pairs);
  bare_sandbox__free_strings(args);

  free(cwd);

  return result;
}

static js_value_t *
bare_sandbox_kill(js_env_t *env, js_callback_info_t *info) {
  int err;

  js_value_t *argv[2];
  err = bare_sandbox__get_args(env, info, 2, argv);
  if (err < 0) return NULL;

  bare_sandbox_t *sandbox;
  err = bare_sandbox__get_sandbox(env, argv[0], &sandbox);
  if (err < 0) return NULL;

  err = bare_sandbox__expect_type(env, argv[1], js_number, "Expected a signal number");
  if (err < 0) return NULL;

  int32_t signum;
  err = js_get_value_int32(env, argv[1], &signum);
  if (err < 0) return NULL;

  bool sent = !sandbox->exited && bare_sandbox__kill(&sandbox->process, signum) > 0;

  js_value_t *result;
  err = js_get_boolean(env, sent, &result);
  if (err < 0) return NULL;

  return result;
}

static js_value_t *
bare_sandbox_ref(js_env_t *env, js_callback_info_t *info) {
  int err;

  js_value_t *argv[1];
  err = bare_sandbox__get_args(env, info, 1, argv);
  if (err < 0) return NULL;

  bare_sandbox_t *sandbox;
  err = bare_sandbox__get_sandbox(env, argv[0], &sandbox);
  if (err < 0) return NULL;

  if (!sandbox->exited) uv_ref(bare_sandbox__handle(&sandbox->process));

  return NULL;
}

static js_value_t *
bare_sandbox_unref(js_env_t *env, js_callback_info_t *info) {
  int err;

  js_value_t *argv[1];
  err = bare_sandbox__get_args(env, info, 1, argv);
  if (err < 0) return NULL;

  bare_sandbox_t *sandbox;
  err = bare_sandbox__get_sandbox(env, argv[0], &sandbox);
  if (err < 0) return NULL;

  if (!sandbox->exited) uv_unref(bare_sandbox__handle(&sandbox->process));

  return NULL;
}

static js_value_t *
bare_sandbox_exports(js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    if (err < 0) return NULL; \
    err = js_set_named_property(env, exports, name, val); \
    if (err < 0) return NULL; \
  }

  V("spawn", bare_sandbox_spawn)
  V("kill", bare_sandbox_kill)
  V("ref", bare_sandbox_ref)
  V("unref", bare_sandbox_unref)
#undef V

  return exports;
}

BARE_MODULE(bare_sandbox, bare_sandbox_exports)
