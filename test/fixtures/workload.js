const fs = require('bare-fs')
const os = require('bare-os')
const tcp = require('bare-tcp')
const Pipe = require('bare-pipe')
const { spawn } = require('bare-subprocess')

const [command, ...args] = Bare.argv.slice(2)

function fail(err) {
  console.error(err.code || err.message)
  Bare.exitCode = 1
}

try {
  switch (command) {
    case 'env': {
      const env = {}
      for (const key of os.getEnvKeys()) env[key] = os.getEnv(key)
      console.log(JSON.stringify(env))
      break
    }

    case 'read':
      console.log(fs.readFileSync(args[0], 'utf8'))
      break

    case 'write':
      fs.writeFileSync(args[0], args[1])
      break

    case 'mkdir':
      fs.mkdirSync(args[0])
      break

    case 'rename':
      fs.renameSync(args[0], args[1])
      break

    case 'stat':
      fs.statSync(args[0])
      break

    case 'connect': {
      const socket = tcp.createConnection(Number(args[0]), args[1] || '127.0.0.1')
      socket.on('connect', () => socket.end()).on('error', fail)
      break
    }

    case 'connect-pipe': {
      const pipe = new Pipe()
      pipe.on('error', fail).connect(args[0], () => pipe.end())
      break
    }

    // Prints the port it listens on, then accepts a single connection for at
    // most as long as asked to and prints what it receives.
    case 'listen': {
      const timer = setTimeout(() => server.close(), Number(args[0]))

      const server = tcp.createServer((socket) => {
        clearTimeout(timer)
        socket.on('data', (data) => console.log(data.toString())).on('end', () => server.close())
      })

      server
        .on('error', (err) => {
          clearTimeout(timer)
          fail(err)
        })
        .listen(0, '127.0.0.1', () => console.log(server.address().port))
      break
    }

    case 'sleep':
      setTimeout(() => {}, Number(args[0]))
      break

    // Starts a process that leaves the session of the run, prints its process
    // ID, and then sleeps for as long as asked to. Otherwise, it exits right
    // away, and without the teardown that would kill the process it started.
    case 'detach': {
      const child = spawn(os.execPath(), [__filename, 'sleep', '30000'], {
        detached: true,
        stdio: 'ignore'
      })
      console.log(child.pid)
      child.unref()
      if (args[0]) setTimeout(() => {}, Number(args[0]))
      else os.kill(os.pid(), os.constants.signals.SIGKILL)
      break
    }
  }
} catch (err) {
  fail(err)
}
