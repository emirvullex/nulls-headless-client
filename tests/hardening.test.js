const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const ByteStream = require('../DataStream/ByteStream');
const Store = require('../lib/Store');
const Messaging = require('../Messaging/Messaging');
const { parseProbePayload } = require('../utils/FingerprintProbe');

test('ByteStream rejects invalid lengths without corrupting the offset', () => {
  const stream = new ByteStream();
  stream.set(Buffer.from([1, 2, 3]));
  for (const length of [NaN, Infinity, 0.5, -1, 4, undefined]) {
    assert.throws(() => stream.readBytes(length), /Invalid byte length/);
    assert.equal(stream.offset, 0);
  }
  assert.deepEqual(Buffer.from(stream.readBytes(3)), Buffer.from([1, 2, 3]));
});

test('Store uses a distinct temporary file for each atomic write', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nulls-store-hardening-'));
  const file = path.join(dir, 'state.json');
  const temporaryPaths = [];
  const original = fs.writeFileSync;
  try {
    fs.writeFileSync = function (name, ...args) {
      if (String(name).startsWith(file + '.tmp-')) temporaryPaths.push(String(name));
      return original.call(fs, name, ...args);
    };
    Store.write(file, { count: 1 });
    Store.write(file, { count: 2 });
    assert.equal(temporaryPaths.length, 2);
    assert.notEqual(temporaryPaths[0], temporaryPaths[1]);
    assert.deepEqual(Store.read(file), { count: 2 });
  } finally {
    fs.writeFileSync = original;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Messaging fails closed when packet decryption throws or rejects authenticity', () => {
  const saved = globalThis.Debugger;
  globalThis.Debugger = { info() {}, warn() {}, error() {} };
  try {
    for (const decrypt of [
      () => { throw new Error('invalid ciphertext'); },
      () => null,
    ]) {
      const frame = Buffer.alloc(8);
      frame.writeUInt16BE(20104, 0);
      frame.writeUIntBE(1, 2, 3);
      const closed = [];
      const messaging = Object.create(Messaging.prototype);
      messaging._queue = { get: () => frame, release() {} };
      messaging.crypto = { decrypt };
      messaging.dump = false;
      messaging.close = (reason) => closed.push(reason);
      messaging.update();
      assert.equal(closed.length, 1);
      assert.match(closed[0], /decryption error|authentication failed/);
    }
  } finally {
    globalThis.Debugger = saved;
  }
});

test('FingerprintProbe rejects oversized advertised compressed manifests before allocation', () => {
  const p = new ByteStream();
  p.writeInt(7);
  p.writeOptionalString(null);
  p.writeOptionalString(null);
  p.writeOptionalString('https://example.test/content');
  p.writeOptionalString(null);
  p.writeOptionalString(null);
  const n = Buffer.alloc(4);
  n.writeUInt32BE(16 * 1024 * 1024 + 1);
  const bytes = Buffer.concat([p.getBytes(), Buffer.alloc(5), n]);
  assert.throws(() => parseProbePayload(bytes), /size limit/);
});
