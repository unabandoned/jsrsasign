// Regression tests for signature verification strictness in the shipped npm
// bundle (npm/lib/jsrsasign.js). Reported upstream as kjur/jsrsasign#664 after
// end of support, so fixed here.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const path = require('node:path');
const { KJUR, KEYUTIL, BigInteger } = require(path.join(__dirname, '..', 'npm', 'lib', 'jsrsasign.js'));

const b64u = (b) => Buffer.from(b).toString('base64url');
const SHA256_DI_PREFIX = Buffer.from('3031300d060960864801650304020105000420', 'hex');

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPub = KEYUTIL.getKey(rsa.publicKey.export({ type: 'spki', format: 'pem' }));
const rsaPubPem = rsa.publicKey.export({ type: 'spki', format: 'pem' });

function jws(sigBuf, hdr = b64u('{"alg":"RS256"}'), pl = b64u('{"sub":"x"}')) {
  return `${hdr}.${pl}.${b64u(sigBuf)}`;
}

test('RSA: a valid PKCS#1 v1.5 JWS still verifies', () => {
  const hdr = b64u('{"alg":"RS256"}');
  const pl = b64u('{"sub":"x"}');
  const sig = crypto.sign('sha256', Buffer.from(`${hdr}.${pl}`), rsa.privateKey);
  assert.strictEqual(KJUR.jws.JWS.verify(jws(sig, hdr, pl), rsaPub, ['RS256']), true);
  const v = new KJUR.crypto.Signature({ alg: 'SHA256withRSA' });
  v.init(rsaPubPem);
  v.updateString(`${hdr}.${pl}`);
  assert.strictEqual(v.verify(sig.toString('hex')), true);
});

test('RSA: verifyWithMessageHash rejects an encoded message shorter than the modulus', () => {
  const hdr = b64u('{"alg":"RS256"}');
  const pl = b64u('{"sub":"x"}');
  const H = crypto.createHash('sha256').update(`${hdr}.${pl}`).digest();
  const DI = Buffer.concat([SHA256_DI_PREFIX, H]);
  // 0x00...00 || 0x01 || 0xff || 0x00 || DigestInfo: right numeric value for a
  // short EM, but not the k-octet EM RFC 8017 9.2 requires.
  const EM = Buffer.concat([Buffer.alloc(256 - 3 - DI.length), Buffer.from([1, 0xff, 0]), DI]);
  const sig = crypto.privateDecrypt({ key: rsa.privateKey, padding: crypto.constants.RSA_NO_PADDING }, EM);
  assert.strictEqual(crypto.verify('sha256', Buffer.from(`${hdr}.${pl}`), rsa.publicKey, sig), false);
  assert.strictEqual(rsaPub.verify(`${hdr}.${pl}`, sig.toString('hex')), false);
  assert.strictEqual(rsaPub.verifyWithMessageHash(H.toString('hex'), sig.toString('hex')), false);
  assert.strictEqual(KJUR.jws.JWS.verify(jws(sig, hdr, pl), rsaPub, ['RS256']), false);
});

test('RSA: verifyWithMessageHash rejects a signature representative s >= n', () => {
  const n = rsaPub.n;
  const L = n.bitLength();
  for (let i = 0; i < 200; i++) {
    const msg = Buffer.from('message ' + i);
    const sig = crypto.sign('sha256', msg, rsa.privateKey);
    const s = new BigInteger(sig.toString('hex'), 16);
    const forged = s.add(n);
    if (forged.bitLength() > L) continue;
    const H = crypto.createHash('sha256').update(msg).digest('hex');
    assert.strictEqual(rsaPub.verifyWithMessageHash(H, sig.toString('hex')), true);
    assert.strictEqual(rsaPub.verifyWithMessageHash(H, forged.toString(16)), false);
    return;
  }
  assert.fail('no signature with s + n < 2^bitLength(n) found');
});

test('ECDSA: DER-encoded signatures still verify; negative INTEGER r or s is rejected', () => {
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ecPub = KEYUTIL.getKey(ec.publicKey.export({ type: 'spki', format: 'pem' }));
  const msg = Buffer.from('hello');
  const verify = (sigHex) => {
    const v = new KJUR.crypto.Signature({ alg: 'SHA256withECDSA' });
    v.init(ecPub);
    v.updateHex(msg.toString('hex'));
    return v.verify(sigHex);
  };
  let der;
  for (;;) {
    der = crypto.sign('sha256', msg, ec.privateKey);
    // want r with a 0x00 sign octet (r has its high bit set)
    if (der[3] === 33 && der[4] === 0x00) break;
  }
  assert.strictEqual(verify(der.toString('hex')), true);
  // Drop r's 0x00 sign octet: r now reads as a negative INTEGER.
  const negR = Buffer.concat([Buffer.from([0x30, der[1] - 1, 0x02, 32]), der.subarray(5)]);
  assert.strictEqual(crypto.verify('sha256', msg, ec.publicKey, negR), false);
  assert.strictEqual(verify(negR.toString('hex')), false);
  assert.throws(() => KJUR.crypto.ECDSA.parseSigHexInHexRS(negR.toString('hex')), /negative ASN\.1 integer/);
});

test('ECDSA: jsrsasign sign -> verify and JWS ES256 round-trip still work', () => {
  const kp = KEYUTIL.generateKeypair('EC', 'secp256r1');
  for (let i = 0; i < 5; i++) {
    const sig = new KJUR.crypto.Signature({ alg: 'SHA256withECDSA' });
    sig.init(kp.prvKeyObj);
    sig.updateString('m' + i);
    const h = sig.sign();
    const v = new KJUR.crypto.Signature({ alg: 'SHA256withECDSA' });
    v.init(kp.pubKeyObj);
    v.updateString('m' + i);
    assert.strictEqual(v.verify(h), true);
    const t = KJUR.jws.JWS.sign('ES256', { alg: 'ES256' }, { i }, kp.prvKeyObj);
    assert.strictEqual(KJUR.jws.JWS.verify(t, kp.pubKeyObj, ['ES256']), true);
  }
});
