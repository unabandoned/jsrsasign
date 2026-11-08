// Describes the public surface of a jsrsasign build: every top-level export,
// every member reachable from them (KJUR, ASN1HEX, X509, CryptoJS, ...), and
// the prototype methods of the exported constructors. Used to keep @unabandoned/jsrsasign a drop-in for
// jsrsasign 11.1.5 (scripts/api-surface.json was generated from the published
// jsrsasign@11.1.5 tarball).
function surface(lib) {
  const out = {};
  const seen = new Set();
  const walk = (obj, path, depth) => {
    if (obj === null || (typeof obj !== 'object' && typeof obj !== 'function')) return;
    if (seen.has(obj) || depth > 6) return;
    seen.add(obj);
    for (const key of Object.keys(obj).sort()) {
      const val = obj[key];
      const name = path ? path + '.' + key : key;
      out[name] = typeof val;
      if (typeof val === 'function' && val.prototype) {
        for (const m of Object.getOwnPropertyNames(val.prototype).sort()) {
          if (m !== 'constructor') out[name + '#' + m] = typeof val.prototype[m];
        }
      }
      walk(val, name, depth + 1);
    }
  };
  walk(lib, '', 0);
  return out;
}
module.exports = { surface };
if (require.main === module) {
  const lib = require(require('node:path').resolve(process.argv[2]));
  process.stdout.write(JSON.stringify(surface(lib), null, 1) + '\n');
}
