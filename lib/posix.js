exports.environment = function environment(overrides) {
  return {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    TERM: 'xterm-256color',
    ...overrides
  }
}

exports.validateFile = function validateFile() {}

exports.extensions = function extensions() {
  return ['']
}
