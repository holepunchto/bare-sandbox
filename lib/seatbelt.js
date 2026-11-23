const fs = require('bare-fs')
const errors = require('./errors')
const posix = require('./posix')
const { ancestors } = require('./paths')

// Adapted from the Seatbelt backend of https://github.com/microsoft/mxc.
const baseline = `\
(version 1)
(deny default)
(allow process-fork)
(allow signal (target same-sandbox))
(allow sysctl-read)
(allow file-read-metadata)
(allow mach-lookup (global-name "com.apple.system.logger"))
(allow file-read-data (literal "/"))
(allow file-read* process-exec
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/usr/bin")
  (subpath "/usr/sbin")
  (subpath "/usr/lib")
  (subpath "/usr/libexec")
  (subpath "/usr/share")
  (subpath "/System")
  (subpath "/Library")
  (subpath "/private/var/db/timezone")
  (subpath "/private/var/db/dyld")
  (subpath "/private/var/select")
  (subpath "/private/etc")
  (subpath "/dev/fd"))
(allow file-read* file-write*
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom"))
(allow file-read* file-write* file-ioctl (literal "/dev/tty"))
; Hardware identifiers are readable unless these are denied explicitly.
(deny iokit-get-properties)
(deny nvram-get)
`

exports.environment = posix.environment
exports.extensions = posix.extensions
exports.validateFile = posix.validateFile

exports.profile = function profile(policy) {
  const params = []

  const param = (path, filter = 'subpath') => {
    const name = 'PATH_' + params.length / 2
    params.push(name, path)
    return `(${filter} (param "${name}"))`
  }

  let source = baseline

  const developer = developerDirectory()

  if (developer) source += `(allow file-read* process-exec ${param(developer)})\n`

  // Seatbelt is last match wins among filtered rules, so emitting shallow to
  // deep lets the deepest grant decide each path. Naming the socket operations
  // also governs AF_UNIX sockets, which Seatbelt matches by path.
  for (const [path, write] of plan(policy.filesystem)) {
    if (write) {
      source += `(allow file-read* file-write* process-exec network-bind network-outbound ${param(path)})\n`
    } else {
      source += `(allow file-read* process-exec ${param(path)})\n`
      source += `(deny file-write* network-bind network-outbound ${param(path)})\n`
    }
  }

  const { egress, ingress, loopback, proxy } = policy.network

  // Seatbelt names remote hosts only as `localhost` or `*`, and `localhost`
  // misses addresses of this host such as IPv4-mapped ones, so egress cannot
  // leave this host out.
  if (egress && !loopback) {
    throw errors.UNSUPPORTED_POLICY('Egress cannot be granted without loopback on macOS')
  }

  if (egress || ingress) source += '(allow network-bind (local ip))\n'

  // Outbound grants name IP explicitly, as an unfiltered grant would also let
  // the workload connect to every Unix socket on the host.
  if (egress) {
    source += '(allow network-outbound (remote ip))\n'
    source += '(allow network-outbound (literal "/private/var/run/mDNSResponder"))\n'
    source += '(allow system-socket)\n'
  } else if (loopback) {
    source += '(allow network-outbound (remote ip "localhost:*"))\n'
  } else if (proxy) {
    source += `(allow network-outbound (remote ip "localhost:${proxy.port}"))\n`
  }

  if (ingress) source += '(allow network-inbound (local ip))\n'

  // Seatbelt checks terminal control through inherited descriptors, so the
  // terminals the workload inherits are granted, as named by the binding.
  for (let fd = 0; fd < 3; fd++) {
    source += `(allow file-ioctl (literal (param "TERMINAL_${fd}")))\n`
  }

  // Denies go last so that they outrank every grant. Metadata is named
  // explicitly as the baseline grants it without a filter, which would
  // otherwise outrank the wildcard.
  for (const path of policy.filesystem.deny) {
    source += `(deny file-read* file-read-metadata file-write* process-exec network-bind network-outbound ${param(path)})\n`
  }

  // Seatbelt matches paths, so renaming a directory above a denied or
  // read-only path would move it out from under its rule. Those directories may
  // therefore not be renamed or removed, though what they contain still may.
  const protectedDirs = new Set()

  for (const path of [...policy.filesystem.deny, ...policy.filesystem.read]) {
    for (const dir of ancestors(path)) protectedDirs.add(dir)
  }

  for (const dir of protectedDirs) {
    source += `(deny file-write* ${param(dir, 'literal')})\n`
  }

  // A setuid program would run as another user, which the run can neither
  // signal nor find.
  source += '(deny process-exec (file-mode #o4000))\n'

  // Marks the run, as named by the binding, so that its processes can be found.
  source += `(deny mach-lookup (global-name-prefix "dev.holepunch.bare-sandbox.run."))\n`
  source += '(allow mach-lookup (global-name (param "RUN")))\n'

  return [source, ...params]
}

function plan(filesystem) {
  const entries = new Map()

  for (const path of filesystem.write) entries.set(path, true)
  for (const path of filesystem.read) entries.set(path, false)

  return [...entries].sort(([a], [b]) => depth(a) - depth(b))
}

function depth(path) {
  return path.split('/').filter(Boolean).length
}

// Many tools in /usr/bin are shims that dispatch into the developer directory
// selected by xcode-select, which falls back to Xcode when nothing is selected.
// Only a link owned by root is trusted, and `DEVELOPER_DIR` is ignored, so the
// caller's environment cannot redirect the grant.
function developerDirectory() {
  const link = '/private/var/db/xcode_select_link'

  let path

  try {
    if (fs.lstatSync(link).uid !== 0) return null

    path = fs.realpathSync(link)
  } catch {
    path = '/Applications/Xcode.app'

    if (!fs.existsSync(path)) return null
  }

  const match = path.match(/^(.+\.app)\/Contents\/Developer$/)

  return match ? match[1] : path
}
