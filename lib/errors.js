module.exports = class SandboxError extends Error {
  constructor(msg, code, fn = SandboxError) {
    super(`${code}: ${msg}`)
    this.code = code

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, fn)
    }
  }

  get name() {
    return 'SandboxError'
  }

  static UNSUPPORTED_POLICY(msg) {
    return new SandboxError(msg, 'UNSUPPORTED_POLICY', SandboxError.UNSUPPORTED_POLICY)
  }

  static INVALID_PATH(msg) {
    return new SandboxError(msg, 'INVALID_PATH', SandboxError.INVALID_PATH)
  }

  static UNSUPPORTED_EXECUTABLE(msg) {
    return new SandboxError(msg, 'UNSUPPORTED_EXECUTABLE', SandboxError.UNSUPPORTED_EXECUTABLE)
  }

  static EXECUTABLE_NOT_FOUND(msg) {
    return new SandboxError(msg, 'EXECUTABLE_NOT_FOUND', SandboxError.EXECUTABLE_NOT_FOUND)
  }

  static UNKNOWN_SIGNAL(msg) {
    return new SandboxError(msg, 'UNKNOWN_SIGNAL', SandboxError.UNKNOWN_SIGNAL)
  }
}
