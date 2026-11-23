const fs = require('bare-fs')
const errors = require('./errors')
const posix = require('./posix')
const { inside, assertExisting } = require('./paths')

const baseline = {
  read: ['/bin', '/sbin', '/lib', '/lib32', '/lib64', '/libx32', '/usr', '/etc', '/proc'],
  write: ['/dev/null', '/dev/zero', '/dev/full', '/dev/random', '/dev/urandom', '/dev/tty']
}

const NETWORK = 1
const INGRESS = 2

exports.environment = posix.environment
exports.extensions = posix.extensions
exports.validateFile = posix.validateFile

// Landlock only grants, and grants add up along a path, so a policy is
// rejected wherever a narrower rule would have to take back a broader one.
exports.profile = function profile(policy) {
  const { filesystem, network } = policy

  if (network.proxy) {
    throw errors.UNSUPPORTED_POLICY('A proxy cannot be enforced on Linux')
  }

  if (network.egress !== network.loopback) {
    throw errors.UNSUPPORTED_POLICY('Egress and loopback must be granted together on Linux')
  }

  assertExisting([...filesystem.read, ...filesystem.write])

  for (const path of filesystem.read) {
    if (filesystem.write.some((parent) => inside(path, parent))) {
      throw errors.UNSUPPORTED_POLICY(
        'Cannot grant read-only access within a write grant on Linux: ' + path
      )
    }
  }

  const read = resolve([...baseline.read, '/etc/resolv.conf']).concat(filesystem.read)
  const write = resolve(baseline.write).concat(filesystem.write)

  for (const path of filesystem.deny) {
    for (const grant of [...read, ...write]) {
      if (inside(path, grant) || inside(grant, path)) {
        throw errors.UNSUPPORTED_POLICY(
          'Cannot deny a path that overlaps a grant on Linux: ' + path
        )
      }
    }
  }

  let flags = 0

  if (network.egress) flags |= NETWORK
  if (network.ingress) flags |= INGRESS

  const profile = [String(flags)]

  for (const path of read) profile.push('r', path)
  for (const path of write) profile.push('w', path)

  return profile
}

// Resolves the paths that exist, as the grants are opened without following
// symlinks. The resolver configuration, for example, is commonly a link into
// /run, which isn't part of the baseline.
function resolve(paths) {
  const result = []

  for (const path of paths) {
    try {
      result.push(fs.realpathSync(path))
    } catch {}
  }

  return result
}
