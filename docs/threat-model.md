# Threat model

## What this is

`bare-sandbox` starts a process that can reach only what a policy grants. It builds no walls of its own. It turns the policy into rules for the sandbox of the operating system, so every promise it makes rests on the kernel keeping it.

This document says what `bare-sandbox` promises, what it does not promise, and which of the two your bug report falls under.

## Terms

- **The caller** is the program that calls `spawn()`, along with everything else running in its process.
- **The policy** is the `filesystem` and `network` options passed to `spawn()`.
- **The workload** is the process that `spawn()` starts.
- **The run** is the workload and every process it starts, directly or not.
- **The baseline** is what every run may do whatever the policy says, such as reading and running the programs and libraries of the system.

## What counts

- **Counts:** `index.js`, `binding.c`, and everything in `lib/`.
- **Does not count:** the tests and their fixtures, and the sandboxes of the operating systems themselves.

## The promise

Everything in the run can reach only what the policy and the baseline grant, through anything the operating system offers. Whatever the policy doesn't grant is denied, and a policy that a backend cannot enforce as written is rejected with `UNSUPPORTED_POLICY` before anything starts.

The run ends with the workload. Once the workload exits, every process it started that is still running is killed, including processes that left its session or process group. The run also ends when the caller exits or dies, however it dies.

The run starts with nothing of the caller's. It gets no environment variables but the defaults and those passed in `env`, and no open files but its standard streams.

There are three things this does **not** mean:

- The run is not walled off from the user it runs as. It may do anything the policy grants with every right that user has, and whatever it writes is owned by that user.
- Runs are not walled off from each other. Two runs reach each other through anything both are granted.
- Nothing limits how much the run uses. CPU, memory, disk space within a write grant, and the number of processes are up to the operating system.

## The backends

Each backend enforces the same policy with a different mechanism. Where a mechanism cannot express a policy exactly, the policy is rejected rather than enforced more loosely. [`index.d.ts`](../index.d.ts) lists every such case, and this section only adds what matters for security.

### macOS

The workload runs under a Seatbelt profile, compiled in the caller and applied between `fork()` and `execve()`. Every process the workload starts inherits it. The profile denies everything by default, including every Mach service but the system logger, so the run cannot ask other processes on the system to act for it.

Seatbelt matches paths, so a rename above a path could move it out from under its rule. Directories above a denied or read-only path may therefore not be renamed or removed.

Seatbelt cannot track a process tree, so each profile carries a random marker, and the run is every process of the user that carries it. A supervisor outside the sandbox kills every such process when the workload exits, when asked to, or when the caller dies, and keeps at it until none is left. The run may not start setuid programs, as those would run as another user, which the supervisor could neither find nor kill.

### Linux

The workload runs under a Landlock ruleset, which governs the filesystem and TCP, and a seccomp filter, which covers much of what Landlock doesn't:

- Every socket family but IP and routing netlink, which also closes off Unix sockets.
- `io_uring`, which can do work without a system call the filter sees.
- User namespaces, which would give the run capabilities within them.
- Kernel keyrings, which hold secrets of the user.
- System V IPC and POSIX message queues, which reach those of every process of the user.
- Injecting input into a terminal.
- TCP Fast Open, which connects without the check Landlock applies.
- Changing the resource limits of other processes.
- Changing the metadata of files, but only for a run started by root.
- Every system call added after the filter was written, which it may know nothing about.

Landlock ABI 6 or later is required, as earlier versions don't keep the run from signalling processes outside it. A run started by root also drops every capability, and every run sets `no_new_privs`, so setuid programs gain nothing.

A supervisor sits between the caller and the workload. As a subreaper, it inherits every process of the run that loses its parent, even one that left its session, and kills what is left of the run when the workload exits, when asked to, or when the caller dies.

### Windows

The workload runs in a BaseContainer, created through the process security environment API. Every process it starts stays in the container. The run also belongs to a job, which kills whatever is left of it once the caller closes the job or dies.

The run has no GUI at all. It may make no Win32k system calls, so it can reach no window, desktop, or window station, and the job forbids global atoms, the clipboard, and changes to system and display settings. It gets a console of its own. Handles to an inherited console are narrowed to what each stream needs, so the run cannot inject input into the console of the caller.

Rules match paths, so a policy that a rename could undo is rejected.

## What is a wall and what is not

A **No** row cannot be the basis of a bug report.

| Thing               | Is it a wall? | Why                                                                            |
| ------------------- | ------------- | ------------------------------------------------------------------------------ |
| Run -> system       | Yes           | The kernel enforces the policy, and this is the whole point                    |
| Run -> caller       | Yes           | Except for the streams and exit status, and scheduling on Linux                |
| Run -> outliving it | Yes           | The run ends with the workload or the caller, whichever goes first             |
| Run -> run          | No            | Runs share whatever both are granted, and run as the same user                 |
| Run -> the user     | No            | The run acts as the user within whatever the policy grants                     |
| `spawn()`           | No            | It grants whatever the policy asks for, so whoever calls it can start anything |

The `spawn()` row matters when the caller runs code it does not trust. A policy may grant every file and every host, so loading `bare-sandbox` grants the power to start processes, much like `bare-subprocess` does.

## What we trust

- The kernel and its sandbox: Seatbelt on macOS, Landlock and seccomp on Linux, and BaseContainer on Windows
- The private Seatbelt API, `sandbox_compile_string()` and `sandbox_apply()`, which Chromium uses as well
- The process security environment API of `processmodel.dll`
- The caller and all code in its process
- The policy, which the caller writes
- `libjs`, `libuv`, and Bare

## Who we are defending against

The attacker we care about is the run. We assume it is native code that does whatever it likes, starts as many processes as it wants, and calls anything the operating system offers, in any order and all at once.

We are **not** defending against:

- Code in the process of the caller. It can call `spawn()` and start anything it likes.
- A policy that grants too much. The policy is the caller's to get right.
- Other users, root, or anything else on the system that is not part of the run.
- Bugs in the kernel or its sandbox. Those go upstream.

## What is actually left to worry about

**1. Turning the policy into rules.** Every backend turns the policy into rules for a mechanism that thinks differently. On macOS, the deepest grant decides each path, then denials, then the protected directories above them, all in one profile where the last match wins. On Linux, grants add up along a path and cannot be taken back. On Windows, the rules are a FlatBuffer that `bare-sandbox` encodes itself. A mistake in any of these is a policy enforced differently than it reads.

**2. What a backend leaves open.** The baseline grants more than the policy names, and each mechanism has gaps the backend must fill. The seccomp filter on Linux is a list of what to deny among the system calls it was written against, so anything it leaves off is allowed.

**3. Keeping the run together.** On macOS, a process is found by its marker and then signalled by its process ID, so if it exits and its ID is reused in between, the signal reaches an unrelated process of the same user. macOS has no process descriptors to rule this out, but it hands out process IDs in order, so every other ID would have to be used up within that moment.

**4. Starting the workload.** Between `fork()` and `execve()`, the child holds whatever the caller had. Every descriptor but the standard streams is closed and every signal handler is reset before the sandbox applies, so a mistake here hands the caller's state to the run.

## What callers must do

`bare-sandbox` promises that the run reaches only what the policy grants. It does not promise that the policy is safe. That part is yours.

**1. Grant as little as you can.** Every grant is reachable by every process of the run for as long as it runs.

**2. Treat what the run writes as hostile.** A write grant lets the run plant anything there: scripts that something outside the sandbox later runs, configuration it later reads, symlinks or hard links that point elsewhere, and FIFOs that block whoever opens them. If the caller or the user acts on what is in a write grant after the run, the run may as well have done it outside the sandbox. Never grant write access to a place that something outside the sandbox runs or reads without checking, such as a shell profile or the hooks of a Git repository.

**3. Treat what the run prints as hostile.** Output may carry escape sequences, and an inherited terminal hands the run the terminal itself. Some terminals answer certain escape sequences by typing a reply, which arrives as input to whatever reads the terminal next. Pipe the output and clean it up if you show it.

**4. Keep secrets out of the run.** Arguments and environment variables are part of the run, and so is everything in a read grant.

**5. Mind the network.** Ingress cannot be scoped by peer, so a listener on every address is reachable from other hosts. Loopback reaches every service on this host, many of which trust local callers. A proxy only filters destinations if it is configured to.

**6. Set your own limits.** If the run must not exhaust CPU, memory, disk, or processes, limit it through the operating system.

## Things that still work inside the sandbox

All of these work whatever the policy says, and none of them are bugs.

- Reading and running the programs, libraries, and configuration of the system
- Writing to `/dev/null` and reading from the random devices, or their equivalents
- Using the standard streams, including a terminal or console they lead to
- Timing and cache side channels against anything else on the system
- On macOS, learning whether any path but a denied one exists, and its metadata, and reading system information through `sysctl`, including the list of processes
- On macOS, creating System V IPC objects, which outlive the run and count against limits of the whole system, though the run cannot use them
- On Linux, learning whether any path exists, and its metadata, and watching any file or directory with `inotify`, which reveals the names of files created in it
- On Linux, reading `/proc`, including the list of processes and their command lines
- On Linux with egress, receiving UDP datagrams from any host, as Landlock doesn't govern UDP
- On Linux, changing the mode, owner, timestamps, and extended attributes of any file the user owns, unless the run was started by root
- On Linux, lowering the scheduling priority of other processes of the same user, and changing which CPUs they run on
- On Windows, listing the names in every directory above a grant
- On Windows, reading the registry, including the keys of the user, as the policy has no rules for it
- On Windows, starting `file` itself, which needn't be granted

## What to report

**Please report:**

- Any way for the run to reach something the policy and the baseline don't grant
- Any policy that is accepted but enforced differently than it reads
- Any way for a process of the run to outlive the workload or the caller
- Any way for the run to reach the caller other than through the standard streams and the exit status
- Memory bugs in `binding.c` or `lib/` that the policy, the arguments, or the run can reach

**Not a bug:**

- Anything that needs code in the process of the caller
- Harm from what the policy grants
- Anything crossing a **No** row
- Anything in the "still works inside the sandbox" list
- Bugs in the kernel or its sandbox, which go upstream
