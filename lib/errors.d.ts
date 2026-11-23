declare class SandboxError extends Error {
  readonly code: string

  static UNSUPPORTED_POLICY(msg: string): SandboxError
  static INVALID_PATH(msg: string): SandboxError
  static UNSUPPORTED_EXECUTABLE(msg: string): SandboxError
  static EXECUTABLE_NOT_FOUND(msg: string): SandboxError
  static UNKNOWN_SIGNAL(msg: string): SandboxError
}

export = SandboxError
