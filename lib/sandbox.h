#ifndef BARE_SANDBOX_H
#define BARE_SANDBOX_H

#include <stdint.h>

enum {
  bare_sandbox_stdio_inherit = 0,
  bare_sandbox_stdio_ignore = 1,
  bare_sandbox_stdio_pipe = 2,
};

typedef struct bare_sandbox_process_s bare_sandbox_process_t;

// Called once the workload has exited and the rest of its run is gone.
static void
bare_sandbox__on_exit(bare_sandbox_process_t *process, int64_t exit_status, int term_signal);

#endif // BARE_SANDBOX_H
