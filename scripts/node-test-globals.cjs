// npm/test/*.js are upstream's mocha suites (bare describe/it). Expose
// node:test's describe/it as globals so they run under the built-in runner
// unchanged, without pulling mocha's dependency tree into the dev install.
const { describe, it } = require('node:test');
globalThis.describe = describe;
globalThis.it = it;
