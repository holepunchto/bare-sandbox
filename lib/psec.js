const os = require('bare-os')
const path = require('bare-path')
const errors = require('./errors')
const { inside, assertExisting, ancestors } = require('./paths')

// Mirrors `ProcessSecurityEnvironment.fbs` from the Windows SDK, as vendored
// by https://github.com/microsoft/mxc.
const VERSION = { major: 1, minor: 1 }

// The workload gets no GUI at all, as with the default of MXC. Win32k system
// calls are disallowed, and every `JOB_OBJECT_UILIMIT_*` restriction applies
// too, as atoms are reached through other system calls.
const UI_RESTRICTIONS = 0x2ffn

const ALLOW = 1

exports.environment = function environment(overrides = {}) {
  const root = os.getEnv('SystemRoot') || 'C:\\Windows'
  const system = path.join(root, 'System32')

  const env = {
    SystemRoot: root,
    windir: root,
    ComSpec: path.join(system, 'cmd.exe'),
    PATH: [
      system,
      root,
      path.join(system, 'Wbem'),
      path.join(system, 'WindowsPowerShell', 'v1.0')
    ].join(';'),
    PATHEXT: '.COM;.EXE;.BAT;.CMD'
  }

  // The security environment refuses to start a process without it.
  const local = os.getEnv('LOCALAPPDATA')

  if (local) env.LOCALAPPDATA = local

  // Variable names are case insensitive on Windows, so an override replaces a
  // default under the spelling of the default.
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.keys(env).find((name) => name.toUpperCase() === key.toUpperCase())

    env[existing || key] = value
  }

  return env
}

// Windows runs batch files through cmd.exe, which parses their arguments by
// rules of its own that no quoting for other programs can satisfy.
exports.validateFile = function validateFile(file) {
  const extension = path.extname(file).toLowerCase()

  if (extension === '.bat' || extension === '.cmd') {
    throw errors.UNSUPPORTED_EXECUTABLE('Cannot spawn a batch file on Windows: ' + file)
  }
}

exports.extensions = function extensions(env) {
  return env.PATHEXT.split(';')
}

// BaseContainer lets a grant beneath a denied directory win, a grant on a
// volume root doesn't extend to its children, and rules match paths that a
// write grant would let the workload rename, so all of these are rejected
// rather than enforced differently than on other platforms.
exports.profile = function profile(policy) {
  const { filesystem, network } = policy

  if (network.proxy) {
    throw errors.UNSUPPORTED_POLICY('A proxy cannot be enforced on Windows')
  }

  // Windows grants loopback in both directions, so the workload could then
  // also accept connections from this host.
  if (network.loopback && !network.ingress) {
    throw errors.UNSUPPORTED_POLICY('Loopback cannot be granted without ingress on Windows')
  }

  const grants = [...filesystem.read, ...filesystem.write]

  assertExisting([...grants, ...filesystem.deny])

  // Rules match paths, so a workload that may rename a directory above a
  // denied or read-only path could move it out from under its rule.
  for (const path of [...filesystem.deny, ...filesystem.read]) {
    if (filesystem.write.some((grant) => inside(path, grant))) {
      throw errors.UNSUPPORTED_POLICY(
        'Cannot restrict a path within a write grant on Windows: ' + path
      )
    }
  }

  for (const grant of grants) {
    if (path.dirname(grant) === grant) {
      throw errors.UNSUPPORTED_POLICY('Cannot grant a volume root on Windows: ' + grant)
    }

    for (const denial of filesystem.deny) {
      if (inside(grant, denial) && path.relative(denial, grant) !== '') {
        throw errors.UNSUPPORTED_POLICY('Cannot grant a path within a denial on Windows: ' + grant)
      }
    }
  }

  // Programs commonly look up every directory above the paths they use, which
  // BaseContainer denies unless the directory may be enumerated. Enumeration
  // replaces a grant on the same directory, so granted directories are left
  // out.
  const enumerable = new Set()

  for (const grant of grants) {
    for (const dir of ancestors(grant)) {
      if (!grants.some((other) => inside(dir, other))) enumerable.add(dir)
    }
  }

  const capabilities = []

  if (network.egress) capabilities.push('internetClient')
  if (network.ingress) capabilities.push('privateNetworkClientServer')

  const spec = table([
    struct(VERSION.major, VERSION.minor),
    capabilities.length ? string(capabilities.join(',')) : null,
    bool(true),
    u64(UI_RESTRICTIONS),
    strings(filesystem.write),
    strings(filesystem.read),
    strings(filesystem.deny),
    table([
      null,
      table([byte(network.egress ? ALLOW : 0)]),
      null,
      table([byte(network.ingress ? ALLOW : 0), byte(network.loopback ? ALLOW : 0)])
    ]),
    strings([...enumerable])
  ])

  return [Buffer.from(encode(spec, 'PSEC')).toString('hex')]
}

function table(fields) {
  return { type: 'table', fields }
}

function string(value) {
  return { type: 'string', value }
}

function strings(values) {
  return values.length ? { type: 'vector', items: values.map(string) } : null
}

function bool(value) {
  return byte(value ? 1 : 0)
}

function byte(value) {
  return { type: 'scalar', size: 1, write: (view, at) => view.setUint8(at, value) }
}

function u64(value) {
  return { type: 'scalar', size: 8, write: (view, at) => view.setBigUint64(at, value, true) }
}

function struct(major, minor) {
  return {
    type: 'scalar',
    size: 4,
    align: 2,
    write: (view, at) => {
      view.setUint16(at, major, true)
      view.setUint16(at + 2, minor, true)
    }
  }
}

// A minimal FlatBuffers encoder. Every object is laid out after the field
// that refers to it, so all offsets point forward as the format requires, and
// each vtable directly precedes its table.
function encode(root, identifier) {
  let bytes = new Uint8Array(256)
  let view = new DataView(bytes.buffer)
  let length = 0

  const reserve = (size) => {
    if (length + size <= bytes.length) return

    const grown = new Uint8Array(Math.max(bytes.length * 2, length + size))
    grown.set(bytes)
    bytes = grown
    view = new DataView(bytes.buffer)
  }

  const alignTo = (offset, alignment) => Math.ceil(offset / alignment) * alignment

  const pad = (alignment) => {
    const aligned = alignTo(length, alignment)
    reserve(aligned - length)
    length = aligned
  }

  const writeString = (value) => {
    const data = Buffer.from(value)

    pad(4)
    reserve(4 + data.length + 1)

    const at = length
    view.setUint32(at, data.length, true)
    bytes.set(data, at + 4)
    length = at + 4 + data.length + 1

    return at
  }

  const writeVector = (items) => {
    pad(4)
    reserve(4 + items.length * 4)

    const at = length
    view.setUint32(at, items.length, true)
    length = at + 4 + items.length * 4

    items.forEach((item, i) => {
      const slot = at + 4 + i * 4
      const target = write(item)
      view.setUint32(slot, target - slot, true)
    })

    return at
  }

  const writeTable = ({ fields }) => {
    const present = fields.map((field, slot) => field && { field, slot }).filter(Boolean)

    const layout = []
    let size = 4

    for (const entry of present) {
      size = alignTo(size, alignOf(entry.field))
      layout.push({ ...entry, offset: size })
      size += sizeOf(entry.field)
    }

    const vtableSize = 4 + 2 * fields.length
    const at = alignTo(length + vtableSize, 8)
    const vtable = at - vtableSize

    reserve(at + size - length)

    view.setUint16(vtable, vtableSize, true)
    view.setUint16(vtable + 2, size, true)

    for (const { slot, offset } of layout) view.setUint16(vtable + 4 + slot * 2, offset, true)

    view.setInt32(at, at - vtable, true)

    length = at + size

    for (const { field, offset } of layout) {
      if (field.type === 'scalar') field.write(view, at + offset)
    }

    for (const { field, offset } of layout) {
      if (field.type === 'scalar') continue

      const slot = at + offset
      const target = write(field)
      view.setUint32(slot, target - slot, true)
    }

    return at
  }

  const write = (node) => {
    switch (node.type) {
      case 'table':
        return writeTable(node)
      case 'vector':
        return writeVector(node.items)
      case 'string':
        return writeString(node.value)
    }
  }

  reserve(8)
  bytes.set(Buffer.from(identifier), 4)
  length = 8

  const at = write(root)

  view.setUint32(0, at, true)

  return bytes.subarray(0, length)
}

function sizeOf(field) {
  return field.type === 'scalar' ? field.size : 4
}

function alignOf(field) {
  return field.align || sizeOf(field)
}
