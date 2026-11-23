import EventEmitter, { EventMap } from 'bare-events'
import Pipe from 'bare-pipe'
import errors from './lib/errors'

export { errors }

export type IO = 'inherit' | 'pipe' | 'ignore'

/**
 * Every path must be absolute. On macOS and Linux, a path also may not contain `..` after a part
 * that doesn't exist, as `..` is applied after following symlinks.
 *
 * On Linux, grants add up along a path and cannot be taken back, so a policy that needs that is
 * rejected with `UNSUPPORTED_POLICY`: a read grant within a write grant, a denial that overlaps a
 * grant, and a grant on a path that doesn't exist. Landlock also doesn't govern changing the mode,
 * owner, timestamps, or extended attributes of a file, so the workload may change those of any file
 * the user owns, granted or not, unless it was started by root, which may change none.
 *
 * On Windows, rules match paths, so a denial or read grant within a write grant would not hold once
 * the workload renames a directory above it. A grant within a denial would win over the denial, and
 * a grant on a volume root doesn't extend below it. All of these are rejected with
 * `UNSUPPORTED_POLICY`, as is a rule on a path that doesn't exist. The workload may list the names
 * in every directory above a grant, but not read what they name.
 */
export interface FilesystemPolicy {
  /**
   * Paths the workload may read and execute, including everything below them. On macOS, a path may
   * name a file or directory that doesn't exist yet.
   */
  read?: string[]
  /**
   * Paths the workload may read, write, and execute, including everything below them. On macOS,
   * the workload may also bind and connect Unix sockets there, and a path may name a file or
   * directory that doesn't exist yet. On Linux, the workload may not create Unix sockets at all,
   * except connected stream pairs.
   */
  write?: string[]
  /**
   * Paths the workload may not access at all. On macOS, a denial outranks every grant and also
   * hides whether the path exists. On Linux and Windows, a denial may not lie within a write grant,
   * and on Linux it may not overlap any grant, so there it mostly documents what is denied anyway.
   */
  deny?: string[]
}

/**
 * On macOS, `egress` requires `loopback`, as Seatbelt cannot leave every address of this host out.
 *
 * On Linux, `egress` and `loopback` must be granted together, and `proxy` is rejected, as neither
 * can be told apart from the other by Landlock. Landlock also only governs TCP, so with `egress`
 * the workload may receive UDP datagrams from any host, even without `ingress`.
 *
 * On Windows, `proxy` is rejected, and `loopback` requires `ingress`, as Windows grants loopback in
 * both directions. Accepting connections from this host also requires both.
 */
export interface NetworkPolicy {
  /**
   * Whether the workload may connect to other hosts. Defaults to `false`.
   */
  egress?: boolean
  /**
   * Whether the workload may accept connections. The grant cannot be scoped by peer, so a listener
   * on all addresses is also reachable from other hosts. Defaults to `false`.
   */
  ingress?: boolean
  /**
   * Whether the workload may connect to services on this host, on any of its addresses. Defaults
   * to `false`, even when `egress` is `true`.
   */
  loopback?: boolean
  /**
   * The URL of an HTTP proxy on loopback, such as `http://127.0.0.1:8080`. The workload may then
   * connect to the proxy port on this host and nowhere else, and the standard proxy environment
   * variables point at it. Using the proxy is up to the workload, and filtering destinations is up
   * to the proxy. Cannot be combined with `egress`.
   */
  proxy?: string
}

export interface SpawnOptions {
  /**
   * The working directory of the workload, which the policy must grant. Defaults to the root of
   * the filesystem, or of the current drive on Windows.
   */
  cwd?: string
  /**
   * Environment variables for the workload, layered over a default of `PATH` and `TERM`, or on
   * Windows the system locations, `PATH`, `PATHEXT`, and `LOCALAPPDATA`. The environment of the
   * parent is never inherited.
   */
  env?: Record<string, string>
  /**
   * How to set up standard input, output, and error. Defaults to `'pipe'`. The workload may use
   * whatever it inherits, but not inject input into an inherited terminal or console.
   */
  stdio?: [stdin?: IO, stdout?: IO, stderr?: IO] | IO
  filesystem?: FilesystemPolicy
  network?: NetworkPolicy
}

export interface SandboxEvents extends EventMap {
  /**
   * Emitted when the workload exits, carrying its exit code or the signal that terminated it. Every
   * process it started that is still running is killed at that point, including processes that
   * left its session or process group. They are also killed if the caller exits or dies first.
   */
  exit: [code: number | null, signalCode: string | null]
}

export interface Sandbox<M extends SandboxEvents = SandboxEvents> extends EventEmitter<M> {
  /** The exit code of the workload, or `null` if it has not exited or was terminated by a signal. */
  readonly exitCode: number | null
  /** `true` if `sandbox.kill()` has sent a signal, otherwise `false`. */
  readonly killed: boolean
  /** The process ID of the workload. */
  readonly pid: number
  /** The name of the signal the workload was terminated with, or `null`. */
  readonly signalCode: string | null
  /** The arguments the workload was spawned with. */
  readonly spawnargs: string[]
  /** The file that was spawned. */
  readonly spawnfile: string
  /** The pipes for standard input, output, and error, or `null` for slots that aren't piped. */
  readonly stdio: [stdin: Pipe | null, stdout: Pipe | null, stderr: Pipe | null]
  readonly stdin: Pipe | null
  readonly stdout: Pipe | null
  readonly stderr: Pipe | null

  /**
   * Send a signal to the workload and every process it started that is still running.
   * @param signum - The signal to send, as a number or a name. Defaults to `'SIGTERM'`.
   * @returns `true` if the signal was sent, or `false` if the workload has already exited.
   * @throws {UNKNOWN_SIGNAL} thrown if `signum` is a name that isn't a known signal.
   */
  kill(signum?: number | string): boolean

  /** Reference the workload and its pipes against the event loop. */
  ref(): void
  /** Unreference the workload and its pipes against the event loop. */
  unref(): void
}

export class Sandbox {}

/**
 * Spawn `file` in a sandbox that denies everything the policy doesn't grant. The workload may read
 * and execute system locations, but nothing else on the filesystem or network unless granted.
 *
 * On macOS, the sandbox is enforced by Seatbelt, and the workload may not run setuid programs. On
 * Linux, it is enforced by Landlock ABI 6 or later and seccomp, which also keep the workload from
 * creating user namespaces, and setuid programs gain no privileges. A workload started by root
 * keeps no capabilities, and may not change the mode, owner, timestamps, flags, or extended
 * attributes of any file.
 *
 * On Windows, the sandbox is a BaseContainer created through the process security environment API
 * of Windows 11 24H2 or later with the August 2026 update. The workload has no GUI at all, so it
 * can't create windows, use the clipboard, or inject input, and programs that load user32 fail to
 * start. Only signals that terminate are supported, and they end the whole run. `file` itself
 * needn't be granted, but whatever the workload starts must be.
 * @param file - The executable to spawn. A name without a directory is looked up in the `PATH` of
 * the workload, and a relative path is resolved against its `cwd`.
 * @param args - Arguments to pass to `file`.
 * @param opts - The environment, stdio, and policy of the workload.
 * @throws {ENOTSUP} thrown on Linux if Landlock ABI 6 or later is unavailable, and on Windows if
 * process security environments are unavailable.
 * @throws {UNSUPPORTED_POLICY} thrown if the policy cannot be enforced as written.
 * @throws {INVALID_PATH} thrown if a path in the policy is relative or cannot be resolved, such as
 * a dangling symlink.
 * @throws {EPERM} thrown on macOS if the policy doesn't allow executing `file`.
 * @throws {EACCES} thrown on Linux if the policy doesn't allow executing `file`.
 * @throws {UNSUPPORTED_EXECUTABLE} thrown on Windows if `file` is a batch file, as cmd.exe would
 * parse its arguments by rules of its own. Spawn `cmd.exe` with `/c` instead.
 * @throws {EXECUTABLE_NOT_FOUND} thrown if `file` doesn't exist, or isn't found in the `PATH`.
 */
export function spawn(file: string, args?: string[] | null, opts?: SpawnOptions): Sandbox

export function spawn(file: string, opts?: SpawnOptions): Sandbox
