const { spawn } = require('../..')

spawn('stty', ['size'], { stdio: 'inherit' }).on('exit', (code) => {
  Bare.exitCode = code
})
