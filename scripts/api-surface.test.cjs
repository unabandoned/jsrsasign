const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { surface } = require('./api-surface.cjs');

test('npm/lib/jsrsasign.js exposes the jsrsasign 11.1.5 API surface', () => {
  const expected = require('./api-surface.json');
  const actual = surface(require(path.join(__dirname, '..', 'npm', 'lib', 'jsrsasign.js')));
  assert.deepStrictEqual(actual, expected);
});

test('package main resolves to lib/jsrsasign.js, as in jsrsasign 11.1.5', () => {
  const pkg = require('../npm/package.json');
  assert.strictEqual(pkg.main, 'lib/jsrsasign.js');
  assert.strictEqual(pkg.exports, undefined);
});
