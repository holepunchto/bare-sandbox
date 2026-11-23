const os = require('bare-os')
const path = require('bare-path')
const { spawn } = require('../..')

// Starts a run whose output goes straight to the output of this process, and
// then waits to be killed.
spawn(os.execPath(), [path.join(__dirname, 'workload.js'), 'detach', '30000'], {
  stdio: ['ignore', 'inherit', 'ignore'],
  filesystem: { read: [path.dirname(os.execPath()), path.join(__dirname, '..', '..')] }
})
