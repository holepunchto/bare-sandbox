const fs = require('bare-fs')
const path = require('bare-path')
const errors = require('./errors')

exports.inside = function inside(child, parent) {
  const relative = path.relative(parent, child)

  return (
    relative === '' ||
    (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative))
  )
}

exports.assertExisting = function assertExisting(paths) {
  for (const target of paths) {
    if (!fs.existsSync(target)) {
      throw errors.UNSUPPORTED_POLICY(
        'Cannot apply a rule to a path that does not exist: ' + target
      )
    }
  }
}

// Every directory above `target`, up to and including the root.
exports.ancestors = function ancestors(target) {
  const result = []

  let dir = target

  while (path.dirname(dir) !== dir) {
    dir = path.dirname(dir)
    result.push(dir)
  }

  return result
}
