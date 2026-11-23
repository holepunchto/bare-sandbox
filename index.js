const EventEmitter = require('bare-events')
const Pipe = require('bare-pipe')
const fs = require('bare-fs')
const os = require('bare-os')
const path = require('bare-path')
const backend = require('#backend')
const binding = require('./binding')
const errors = require('./lib/errors')

const stdioTypes = { inherit: 0, ignore: 1, pipe: 2 }

const proxyKeys = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'FTP_PROXY']

class Sandbox extends EventEmitter {
  constructor(file, args, opts) {
    super()

    const policy = normalize(opts)
    const env = environment(policy, opts.env)
    const cwd = path.resolve(typeof opts.cwd === 'string' ? opts.cwd : '/')

    const resolved = resolveFile(file, env, cwd)

    backend.validateFile(resolved)

    const [handle, pid, ...fds] = binding.spawn(
      this,
      this._onexit,
      [resolved, ...args],
      Object.entries(env).map(([key, value]) => key + '=' + value),
      cwd,
      backend.profile(policy),
      normalizeStdio(opts.stdio)
    )

    this.spawnfile = file
    this.spawnargs = args
    this.pid = pid
    this.exitCode = null
    this.signalCode = null
    this.killed = false
    this.stdio = fds.map((fd) => (fd === -1 ? null : new Pipe().open(fd)))

    this._handle = handle
  }

  get stdin() {
    return this.stdio[0]
  }

  get stdout() {
    return this.stdio[1]
  }

  get stderr() {
    return this.stdio[2]
  }

  kill(signum = 'SIGTERM') {
    if (typeof signum === 'string') {
      if (!Object.hasOwn(os.constants.signals, signum)) {
        throw errors.UNKNOWN_SIGNAL('Unknown signal: ' + signum)
      }

      signum = os.constants.signals[signum]
    }

    const sent = binding.kill(this._handle, signum)

    if (sent) this.killed = true

    return sent
  }

  ref() {
    for (const pipe of this.stdio) if (pipe) pipe.ref()

    binding.ref(this._handle)
  }

  unref() {
    for (const pipe of this.stdio) if (pipe) pipe.unref()

    binding.unref(this._handle)
  }

  _onexit(code, signal) {
    if (signal) {
      const { signals } = os.constants

      this.signalCode = Object.keys(signals).find((name) => signals[name] === signal)
    } else {
      this.exitCode = code
    }

    this.emit('exit', this.exitCode, this.signalCode)
  }
}

exports.Sandbox = Sandbox

exports.errors = errors

exports.spawn = function spawn(file, args, opts) {
  if (Array.isArray(args)) {
    args = [...args]
  } else if (args === null || args === undefined) {
    args = []
  } else {
    opts = args
    args = []
  }

  if (!opts) opts = {}

  validate(file, args, opts)

  return new Sandbox(file, args, opts)
}

// Strings reach native code, where a null character would end them early, so
// they are checked here rather than passed on with a different meaning.
function validate(file, args, opts) {
  validateString(file, 'file')

  for (const arg of args) validateString(arg, 'Each argument')

  if (opts.cwd !== undefined) validateString(opts.cwd, 'cwd')

  if (opts.env !== undefined) {
    for (const [key, value] of Object.entries(opts.env)) {
      validateString(key, 'Each environment variable name')
      validateString(value, 'Each environment variable value')

      if (key === '' || key.includes('=')) {
        throw new TypeError('Invalid environment variable name: ' + key)
      }
    }
  }

  const { filesystem = {}, network = {} } = opts

  for (const kind of ['read', 'write', 'deny']) {
    if (filesystem[kind] === undefined) continue

    if (!Array.isArray(filesystem[kind])) {
      throw new TypeError(`filesystem.${kind} must be an array`)
    }

    for (const path of filesystem[kind]) validateString(path, `Each path of filesystem.${kind}`)
  }

  for (const kind of ['egress', 'ingress', 'loopback']) {
    if (network[kind] !== undefined && typeof network[kind] !== 'boolean') {
      throw new TypeError(`network.${kind} must be a boolean`)
    }
  }

  if (network.proxy !== undefined) validateString(network.proxy, 'network.proxy')
}

function validateString(value, name) {
  if (typeof value !== 'string') {
    throw new TypeError(`${name} must be a string, got ${typeof value}`)
  }

  if (value.includes('\0')) {
    throw new TypeError(`${name} must not contain null characters`)
  }
}

function normalize(opts) {
  const { filesystem = {}, network = {} } = opts

  const policy = {
    filesystem: {
      read: (filesystem.read || []).map(resolvePath),
      write: (filesystem.write || []).map(resolvePath),
      deny: (filesystem.deny || []).map(resolvePath)
    },
    network: {
      egress: network.egress === true,
      ingress: network.ingress === true,
      loopback: network.loopback === true,
      proxy: null
    }
  }

  if (network.proxy) {
    if (policy.network.egress) {
      throw errors.UNSUPPORTED_POLICY('A proxy cannot be combined with egress')
    }

    policy.network.proxy = parseProxy(network.proxy)
  }

  return policy
}

function normalizeStdio(stdio = 'pipe') {
  if (typeof stdio === 'string') stdio = [stdio, stdio, stdio]

  return [0, 1, 2].map((fd) => {
    const type = stdio[fd] || 'pipe'

    if (!Object.hasOwn(stdioTypes, type)) {
      throw new TypeError('Invalid stdio type: ' + type)
    }

    return stdioTypes[type]
  })
}

function environment(policy, overrides = {}) {
  const { proxy } = policy.network

  if (proxy) {
    overrides = { ...overrides }

    for (const key of Object.keys(overrides)) {
      if (key.toUpperCase() === 'NO_PROXY') delete overrides[key]
    }

    for (const key of proxyKeys) overrides[key] = overrides[key.toLowerCase()] = proxy.url
  }

  return backend.environment(overrides)
}

function parseProxy(proxy) {
  let url

  try {
    url = new URL(proxy)
  } catch {
    throw errors.UNSUPPORTED_POLICY('Invalid proxy URL: ' + proxy)
  }

  if (url.protocol !== 'http:') {
    throw errors.UNSUPPORTED_POLICY('The proxy must use http: ' + proxy)
  }

  if (!['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
    throw errors.UNSUPPORTED_POLICY('The proxy must be on loopback: ' + proxy)
  }

  // The port of an HTTP URL is left out when it's the default.
  const port = url.port === '' ? 80 : parseInt(url.port, 10)

  if (port === 0) {
    throw errors.UNSUPPORTED_POLICY('The proxy must name a port other than 0: ' + proxy)
  }

  return { url: proxy, port }
}

// Resolves symlinks so that rules apply to the paths the kernel checks.
// Components that don't exist yet are kept, so a grant can name a path that the
// workload will create. `..` is applied by the kernel after following
// symlinks, so the path is deliberately not normalized up front, and may not
// follow a component that doesn't exist, as there is no symlink to follow.
function resolvePath(target) {
  if (!path.isAbsolute(target)) {
    throw errors.INVALID_PATH(`Cannot resolve ${target}: not an absolute path`)
  }

  let current = target

  const missing = []

  while (true) {
    try {
      return path.join(fs.realpathSync(current), ...missing)
    } catch (err) {
      if (err.code !== 'ENOENT') {
        throw errors.INVALID_PATH(`Cannot resolve ${target}: ${err.code}`)
      }
    }

    if (exists(current)) {
      throw errors.INVALID_PATH(`Cannot resolve ${target}: dangling symlink`)
    }

    const parent = path.dirname(current)
    const name = path.basename(current)

    if (parent === current || name === '..') {
      throw errors.INVALID_PATH(`Cannot resolve ${target}`)
    }

    missing.unshift(name)
    current = parent
  }
}

function exists(target) {
  try {
    fs.lstatSync(target)
    return true
  } catch {
    return false
  }
}

// A file with a directory is relative to the working directory of the
// workload, and one without is looked up in its `PATH`.
function resolveFile(file, env, cwd) {
  if (file.includes('/') || file.includes(path.sep)) {
    const resolved = path.resolve(cwd, file)

    if (!fs.existsSync(resolved)) throw errors.EXECUTABLE_NOT_FOUND('Cannot find ' + resolved)

    return resolved
  }

  const extensions = path.extname(file) === '' ? backend.extensions(env) : ['']

  for (const dir of (env.PATH || '').split(path.delimiter)) {
    if (dir === '') continue

    for (const extension of extensions) {
      const candidate = path.resolve(cwd, dir, file + extension)

      if (executable(candidate)) return candidate
    }
  }

  throw errors.EXECUTABLE_NOT_FOUND('Cannot find ' + file + ' in PATH')
}

function executable(file) {
  try {
    fs.accessSync(file, fs.constants.X_OK)
    return fs.statSync(file).isFile()
  } catch {
    return false
  }
}
