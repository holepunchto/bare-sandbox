# bare-sandbox

Process sandboxing for JavaScript. Spawns a process that can reach only what its policy grants, enforced by the operating system. The policy follows the containment model of [MXC](https://github.com/microsoft/mxc) and is enforced by Seatbelt on macOS, by Landlock and seccomp on Linux, and by BaseContainer process security environments on Windows.

```
npm i bare-sandbox
```

> [!CAUTION]
> `bare-sandbox` is still at version 0 and must not be relied on for security yet. Before using it, check your exact policy against the code, and assume that the workload may reach more than the policy grants.

## Usage

```js
const { spawn } = require('bare-sandbox')

const sandbox = spawn('sh', ['-c', 'cat input.txt > output.txt'], {
  cwd: '/path/to/project',
  filesystem: {
    read: ['/path/to/project'],
    write: ['/path/to/project/output.txt'],
    deny: ['/path/to/project/.env']
  },
  network: {
    proxy: 'http://127.0.0.1:8080'
  }
})

sandbox.on('exit', (code) => console.log('exited with', code))
```

See [`index.d.ts`](index.d.ts) for the API.

## Security

`bare-sandbox` is meant for running code you don't trust, and the policy is the only thing standing between that code and the rest of the system. What it does and does not promise is written down in [`docs/threat-model.md`](docs/threat-model.md), which callers should read before relying on it. In short, the run reaches only what the policy grants, but whatever the policy grants, the run may abuse, including leaving behind files that something outside the sandbox later trusts.

## License

Apache-2.0
