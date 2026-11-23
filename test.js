const test = require('brittle')
const fs = require('bare-fs')
const os = require('bare-os')
const path = require('bare-path')
const tcp = require('bare-tcp')
const { spawn, Sandbox } = require('.')

const darwin = Bare.platform === 'darwin'
const linux = Bare.platform === 'linux'
const win32 = Bare.platform === 'win32'
const posix = darwin || linux

// The workload is a release build of Bare running a fixture, so it needs to
// read the runtime and this package.
const executable = require('bare-runtime')()

const runtime = path.dirname(executable)
const workload = path.join(__dirname, 'test', 'fixtures', 'workload.js')

test('does not inherit the environment', async (t) => {
  os.setEnv('BARE_SANDBOX_SENTINEL', '1')
  t.teardown(() => os.unsetEnv('BARE_SANDBOX_SENTINEL'))

  const result = await bare(['env'], { env: { FOO: 'bar' } })

  const env = JSON.parse(result.stdout)

  t.is(env.FOO, 'bar')
  t.absent('BARE_SANDBOX_SENTINEL' in env)
})

test('denies reads outside the policy', async (t) => {
  const dir = await t.tmp()
  fs.writeFileSync(path.join(dir, 'file'), 'secret')

  const result = await bare(['read', path.join(dir, 'file')])

  t.not(result.code, 0)
  t.absent(result.stdout.includes('secret'))
})

test('read grant allows reads but not writes', async (t) => {
  const dir = await t.tmp()
  fs.writeFileSync(path.join(dir, 'file'), 'hello')

  const read = await bare(['read', path.join(dir, 'file')], { filesystem: { read: [dir] } })

  t.is(read.stdout.trim(), 'hello')

  const write = await bare(['write', path.join(dir, 'file'), 'x'], { filesystem: { read: [dir] } })

  t.not(write.code, 0)
  t.is(fs.readFileSync(path.join(dir, 'file'), 'utf8'), 'hello')
})

test('write grant allows writes', async (t) => {
  const dir = await t.tmp()

  const result = await bare(['write', path.join(dir, 'file'), 'hello'], {
    filesystem: { write: [dir] }
  })

  t.is(result.code, 0)
  t.is(fs.readFileSync(path.join(dir, 'file'), 'utf8'), 'hello')
})

test('write grant may name a path that does not exist yet', async (t) => {
  const dir = await t.tmp()
  const target = path.join(dir, 'a')

  await enforcedOrRejected(t, async () => {
    await bare(['mkdir', target], { filesystem: { read: [dir], write: [target] } })

    t.ok(fs.existsSync(target))
  })
})

test('deny overrides a grant on the same path', async (t) => {
  const dir = await t.tmp()
  fs.writeFileSync(path.join(dir, 'file'), 'secret')

  await enforcedOrRejected(t, async () => {
    const result = await bare(['read', path.join(dir, 'file')], {
      filesystem: { read: [dir], deny: [dir] }
    })

    t.absent(result.stdout.includes('secret'))
  })
})

test('deny overrides an enclosing write grant', async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'secret'))
  fs.writeFileSync(path.join(dir, 'secret', 'file'), 'secret')

  await enforcedOrRejected(t, async () => {
    const result = await bare(['read', path.join(dir, 'secret', 'file')], {
      filesystem: { write: [dir], deny: [path.join(dir, 'secret')] }
    })

    t.absent(result.stdout.includes('secret'))
  })
})

test('deny also hides whether a path exists', { skip: !darwin }, async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'secret'))

  const result = await bare(['stat', path.join(dir, 'secret')], {
    filesystem: { write: [dir], deny: [path.join(dir, 'secret')] }
  })

  t.not(result.code, 0)
})

test('deny holds when a directory above it is renamed', async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'a', 'secret'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'a', 'secret', 'file'), 'secret')

  const opts = { filesystem: { write: [dir], deny: [path.join(dir, 'a', 'secret')] } }

  await enforcedOrRejected(t, async () => {
    await bare(['rename', path.join(dir, 'a'), path.join(dir, 'b')], opts)

    t.absent(fs.existsSync(path.join(dir, 'b')))
  })
})

test('read-only grant holds when a directory above it is renamed', async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'a', 'ro'), { recursive: true })

  const opts = { filesystem: { write: [dir], read: [path.join(dir, 'a', 'ro')] } }

  await enforcedOrRejected(t, async () => {
    await bare(['rename', path.join(dir, 'a'), path.join(dir, 'b')], opts)

    t.absent(fs.existsSync(path.join(dir, 'b')))
  })
})

test('read grant nested in a write grant stays read-only', async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'nested'))

  const opts = { filesystem: { write: [dir], read: [path.join(dir, 'nested')] } }

  await enforcedOrRejected(t, async () => {
    t.is((await bare(['write', path.join(dir, 'file'), 'x'], opts)).code, 0)

    await bare(['write', path.join(dir, 'nested', 'file'), 'x'], opts)

    t.absent(fs.existsSync(path.join(dir, 'nested', 'file')))
  })
})

test('read-only grant holds within a write grant on the root', async (t) => {
  const dir = fs.realpathSync(await t.tmp())

  let top = dir
  while (path.dirname(path.dirname(top)) !== path.dirname(top)) top = path.dirname(top)

  const opts = { filesystem: { write: [top, path.dirname(top)], read: [top] } }

  await enforcedOrRejected(t, async () => {
    await bare(['write', path.join(dir, 'file'), 'x'], opts)

    t.absent(fs.existsSync(path.join(dir, 'file')))
  })
})

test('grants on a volume root are rejected', { skip: !win32 }, async (t) => {
  const dir = await t.tmp()

  t.exception(() => spawn(executable, { filesystem: { read: [dir.slice(0, 3)] } }), {
    code: 'UNSUPPORTED_POLICY'
  })
})

test('grants apply to the targets of symlinks', { skip: !posix }, async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'target'))
  fs.writeFileSync(path.join(dir, 'target', 'file'), 'hello')
  fs.symlinkSync(path.join(dir, 'target'), path.join(dir, 'link'))

  const result = await bare(['read', path.join(dir, 'target', 'file')], {
    filesystem: { read: [path.join(dir, 'link')] }
  })

  t.is(result.stdout.trim(), 'hello')
})

test('denials apply to the targets of symlinks', { skip: !posix }, async (t) => {
  const dir = await t.tmp()
  fs.mkdirSync(path.join(dir, 'target'))
  fs.writeFileSync(path.join(dir, 'target', 'file'), 'hello')
  fs.symlinkSync(path.join(dir, 'target'), path.join(dir, 'link'))

  await enforcedOrRejected(t, async () => {
    const result = await bare(['read', path.join(dir, 'target', 'file')], {
      filesystem: { read: [dir], deny: [path.join(dir, 'link')] }
    })

    t.absent(result.stdout.includes('hello'))
  })
})

test('denies executing files outside the policy', { skip: !posix }, async (t) => {
  const dir = await t.tmp()
  const file = path.join(dir, path.basename(executable))
  fs.copyFileSync(fs.realpathSync(executable), file)
  fs.chmodSync(file, 0o755)

  t.exception(() => spawn(file, ['--version']), { code: linux ? 'EACCES' : 'EPERM' })

  const result = await run(file, ['--version'], { filesystem: { read: [dir] } })

  t.is(result.code, 0)
})

test('throws for a missing executable', async (t) => {
  const dir = await t.tmp()

  t.exception(() => spawn('does-not-exist'), { code: 'EXECUTABLE_NOT_FOUND' })
  t.exception(() => spawn(path.join(dir, 'does-not-exist')), { code: 'EXECUTABLE_NOT_FOUND' })
})

test('looks up names only in the PATH, not the working directory', async (t) => {
  const dir = await t.tmp()
  fs.copyFileSync(executable, path.join(dir, 'only-in-cwd' + path.extname(executable)))

  t.exception(() => spawn('only-in-cwd', { cwd: dir, filesystem: { read: [dir] } }), {
    code: 'EXECUTABLE_NOT_FOUND'
  })
})

test('rejects batch files', { skip: !win32 }, async (t) => {
  const dir = await t.tmp()
  fs.writeFileSync(path.join(dir, 'script.bat'), '@echo %*')
  fs.writeFileSync(path.join(dir, 'script.CMD'), '@echo %*')

  for (const file of ['script.bat', 'script.CMD']) {
    t.exception(() => spawn(path.join(dir, file), ['a"&echo b']), {
      code: 'UNSUPPORTED_EXECUTABLE'
    })
  }
})

test('looks up relative PATH entries in the working directory', async (t) => {
  const dir = await t.tmp()
  fs.copyFileSync(
    fs.realpathSync(executable),
    path.join(dir, 'only-in-cwd' + path.extname(executable))
  )

  const result = await run('only-in-cwd', ['--version'], {
    cwd: dir,
    env: { PATH: '.' },
    filesystem: { read: [dir] }
  })

  t.is(result.code, 0)
})

test('rejects policy paths that cannot be resolved as written', async (t) => {
  const dir = await t.tmp()

  const targets = ['', 'relative']

  // Windows applies `..` before resolving links, so it's only rejected elsewhere.
  if (posix) targets.push(dir + path.sep + 'missing' + path.sep + '..')

  for (const target of targets) {
    t.exception(() => spawn(executable, { filesystem: { read: [target] } }), {
      code: 'INVALID_PATH'
    })
  }
})

test('rejects unknown stdio types and signals', (t) => {
  t.exception.all(() => spawn(executable, { stdio: 'toString' }), /Invalid stdio type/)

  const sandbox = spawn(executable, [workload, 'sleep', '30000'], withRuntime())

  t.exception(() => sandbox.kill('toString'), { code: 'UNKNOWN_SIGNAL' })

  sandbox.kill()
})

test('rejects strings that native code would cut short', (t) => {
  t.exception.all(() => spawn(executable, ['a\0b']), /null characters/)
  t.exception.all(() => spawn(executable, { env: { A: 'b\0c' } }), /null characters/)
  t.exception.all(
    () => spawn(executable, { filesystem: { read: ['/tmp\0/x'] } }),
    /null characters/
  )
})

test('rejects strings that native code would cut short when constructed directly', (t) => {
  t.exception.all(() => new Sandbox(executable, ['a\0b'], {}), /null characters/)
  t.exception.all(() => new Sandbox(executable + '\0x', [], {}), /null characters/)
  t.exception.all(() => new Sandbox(executable, [], { cwd: '/\0/x' }), /null characters/)
})

test('denies network access by default', async (t) => {
  const port = await listen(t)

  const result = await bare(['connect', port])

  t.not(result.code, 0)
})

test('egress does not reach this host', async (t) => {
  const port = await listen(t, '0.0.0.0')

  // The host is also reachable through its other addresses, including as
  // IPv4-mapped IPv6 addresses.
  const hosts = ['127.0.0.1']

  for (const { address, family, internal } of Object.values(os.networkInterfaces()).flat()) {
    if (family === 'IPv4' && !internal) hosts.push(address, '::ffff:' + address)
  }

  await enforcedOrRejected(t, async () => {
    for (const host of hosts) {
      const result = await bare(['connect', port, host], { network: { egress: true } })

      t.not(result.code, 0, host)
    }
  })
})

test('loopback reaches this host', async (t) => {
  const port = await listen(t)

  await enforcedOrRejected(t, async () => {
    const result = await bare(['connect', port], { network: { loopback: true } })

    t.is(result.code, 0)
  })
})

test('egress and loopback together reach this host', async (t) => {
  const port = await listen(t)

  const result = await bare(['connect', port], {
    network: { egress: true, loopback: true, ingress: win32 }
  })

  t.is(result.code, 0)
})

test('egress does not reach Unix sockets', { skip: !posix }, async (t) => {
  const dir = await t.tmp()
  const socket = path.join(dir, 'socket')

  const server = require('bare-pipe').createServer((pipe) => pipe.end())
  await new Promise((resolve) => server.listen(socket, resolve))
  t.teardown(() => server.close())

  const result = await bare(['connect-pipe', socket], { network: { egress: true, loopback: true } })

  t.not(result.code, 0)
})

test('proxy reaches only the proxy port', async (t) => {
  const proxy = await listen(t)
  const other = await listen(t)

  const opts = { network: { proxy: `http://127.0.0.1:${proxy}` } }

  await enforcedOrRejected(t, async () => {
    t.is((await bare(['connect', proxy], opts)).code, 0)
    t.not((await bare(['connect', other], opts)).code, 0)

    const env = JSON.parse((await bare(['env'], { ...opts, env: { NO_PROXY: '*' } })).stdout)

    t.is(env.HTTPS_PROXY, `http://127.0.0.1:${proxy}`)
    t.absent('NO_PROXY' in env)
  })
})

test('rejects a proxy that cannot be enforced', (t) => {
  const policies = [
    { egress: true, proxy: 'http://127.0.0.1:8080' },
    { proxy: 'http://example.com:8080' },
    { proxy: 'http://127.0.0.1:0' }
  ]

  for (const network of policies) {
    t.exception(() => spawn(executable, { network }), { code: 'UNSUPPORTED_POLICY' })
  }
})

test('ingress allows accepting connections', async (t) => {
  t.absent(await accepts())
  t.ok(await accepts({ network: { ingress: true, loopback: win32 } }))
})

test('egress does not allow accepting connections', async (t) => {
  await enforcedOrRejected(t, async () => {
    t.absent(await accepts({ network: { egress: true, loopback: true } }))
  })
})

test('kill terminates the run', async (t) => {
  const sandbox = spawn(executable, [workload, 'sleep', '30000'], {
    filesystem: { read: [runtime, __dirname] }
  })

  const exited = new Promise((resolve) => sandbox.on('exit', resolve))

  t.ok(sandbox.kill())

  await exited

  t.is(sandbox.signalCode, 'SIGTERM')
  t.is(sandbox.exitCode, null)
})

test('kills processes that leave the session of the run', async (t) => {
  const result = await bare(['detach'])

  const pid = parseInt(result.stdout, 10)

  t.ok(await gone(pid))
})

test('ends the run when the caller is killed', async (t) => {
  const { spawn: spawnUnsandboxed } = require('bare-subprocess')

  const caller = spawnUnsandboxed(executable, [path.join(__dirname, 'test/fixtures/caller.js')], {
    stdio: ['ignore', 'pipe', 'inherit']
  })

  const pid = await new Promise((resolve) => {
    caller.stdout.on('data', (data) => resolve(parseInt(data, 10)))
  })

  caller.kill('SIGKILL')

  t.ok(await gone(pid))
})

test('hides hardware identifiers', { skip: !darwin }, async (t) => {
  const result = await run('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'])

  t.absent(result.stdout.includes('IOPlatformSerialNumber'))
})

test('denies running setuid programs', { skip: !darwin }, (t) => {
  t.exception(() => spawn('/usr/bin/sudo', ['-n', 'true']), { code: 'EPERM' })
})

test('does not kill processes of another run', async (t) => {
  const other = spawn(executable, [workload, 'detach', '30000'], {
    filesystem: { read: [runtime, __dirname] }
  })

  const pid = await new Promise((resolve) => {
    other.stdout.on('data', (data) => resolve(parseInt(data, 10)))
  })

  await bare(['env'])

  t.execution(() => os.kill(pid, 0))

  other.kill()

  t.ok(await gone(pid))
})

test('does not reach shared memory outside the run', { skip: !posix }, async (t) => {
  const { spawnSync } = require('bare-subprocess')

  const created = spawnSync('/usr/bin/perl', [
    '-e',
    'use IPC::SysV qw(IPC_PRIVATE IPC_CREAT S_IRUSR S_IWUSR); print shmget(IPC_PRIVATE, 8, IPC_CREAT | S_IRUSR | S_IWUSR)'
  ])

  const id = parseInt(created.stdout.toString(), 10)

  t.teardown(() => spawnSync('/usr/bin/perl', ['-e', `shmctl(${id}, 0, 0)`]))

  const result = await perl(`shmread(${id}, my $buf, 0, 8) or exit 1`)

  t.is(result.code, 1)
})

test('denies Unix datagram socket pairs', { skip: !linux }, async (t) => {
  const result = await perl(
    'use Socket; socketpair(my $a, my $b, AF_UNIX, SOCK_DGRAM, 0) or exit 1'
  )

  t.not(result.code, 0)
})

test('denies access to kernel keyrings', { skip: !linux }, async (t) => {
  const keyctl = Bare.arch === 'arm64' ? 219 : 250

  const result = await perl(`syscall(${keyctl}, 0, -4, 0) == -1 or exit 1`)

  t.is(result.code, 0)
})

test('denies TCP Fast Open without egress', { skip: !linux }, async (t) => {
  const port = await listen(t)

  const result = await perl(
    `use Socket; socket(my $s, AF_INET, SOCK_STREAM, 0) or exit 2; send($s, "x", 0x20000000, pack_sockaddr_in(${port}, inet_aton("127.0.0.1"))) or exit 1`,
    { network: { ingress: true } }
  )

  t.is(result.code, 1)
})

test('the run survives an attempt to kill its supervisor', { skip: !linux }, async (t) => {
  const sandbox = spawn('/usr/bin/perl', [
    '-e',
    'use POSIX; $| = 1; my $pid = fork; if (!$pid) { POSIX::setsid(); sleep 30; exit } print "$pid\\n"; kill 9, getppid(); sleep 30'
  ])

  const pid = await new Promise((resolve) => {
    sandbox.stdout.on('data', (data) => resolve(parseInt(data, 10)))
  })

  await sleep(200)

  t.execution(() => os.kill(sandbox.pid, 0))

  sandbox.kill()

  t.ok(await gone(pid))
})

test('inherited terminals can be controlled', { skip: !posix }, async (t) => {
  const pty = require('tt-native')

  const terminal = pty.spawn(executable, [path.join(__dirname, 'test/fixtures/terminal.js')])

  let output = ''
  terminal.on('data', (data) => (output += data))

  const code = await new Promise((resolve) => terminal.on('exit', resolve))

  t.is(code, 0, output)
  t.ok(/^\d+ \d+/.test(output.trim()))
})

// Passes if the backend either enforces what `fn` checks or rejects the
// policy outright, but never if it accepts the policy without enforcing it.
async function enforcedOrRejected(t, fn) {
  try {
    await fn()
  } catch (err) {
    if (err.code !== 'UNSUPPORTED_POLICY') throw err

    t.pass('rejected')
  }
}

function withRuntime(opts = {}) {
  const filesystem = opts.filesystem || {}

  return {
    ...opts,
    filesystem: { ...filesystem, read: [runtime, __dirname, ...(filesystem.read || [])] }
  }
}

function bare(args, opts) {
  return run(executable, [workload, ...args.map(String)], withRuntime(opts))
}

function perl(script, opts) {
  return run('/usr/bin/perl', ['-e', script], opts)
}

async function run(file, args, opts) {
  const sandbox = spawn(file, args, opts)

  let stdout = ''
  sandbox.stdout.on('data', (data) => (stdout += data))
  sandbox.stderr.resume()

  const [code] = await Promise.all([
    new Promise((resolve) => sandbox.on('exit', resolve)),
    new Promise((resolve) => sandbox.stdout.on('end', resolve)),
    new Promise((resolve) => sandbox.stderr.on('end', resolve))
  ])

  return { code, stdout }
}

// Starts a listener in the sandbox and reports whether a connection from this
// host reaches it.
async function accepts(opts) {
  const sandbox = spawn(executable, [workload, 'listen', '3000'], withRuntime(opts))

  let output = ''
  sandbox.stdout.on('data', (data) => (output += data))

  const exited = new Promise((resolve) => sandbox.on('exit', resolve))

  const port = await Promise.race([
    new Promise((resolve) => sandbox.stdout.once('data', (data) => resolve(parseInt(data, 10)))),
    exited.then(() => null)
  ])

  if (port === null) return false

  try {
    await send(port, 'hello')
  } catch {
    sandbox.kill()
    await exited
    return false
  }

  await exited

  return output.includes('hello')
}

// A killed process lingers until its new parent reaps it.
async function gone(pid) {
  for (let i = 0; i < 100; i++) {
    try {
      os.kill(pid, 0)
    } catch {
      return true
    }

    await sleep(20)
  }

  return false
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function listen(t, host = '127.0.0.1') {
  const server = tcp.createServer((socket) => socket.end())

  await new Promise((resolve) => server.listen(0, host, resolve))

  t.teardown(() => server.close())

  return server.address().port
}

function send(port, data) {
  return new Promise((resolve, reject) => {
    const socket = tcp.createConnection(port, '127.0.0.1')

    const timer = setTimeout(() => socket.destroy(new Error('Timed out')), 1000)

    socket
      .on('error', (err) => {
        clearTimeout(timer)
        reject(err)
      })
      .on('connect', () => {
        clearTimeout(timer)
        socket.end(data, resolve)
      })
  })
}
