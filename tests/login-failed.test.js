const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');

const ByteStream = require('../DataStream/ByteStream');
const LoginFailed = require('../Messaging/Messages/Server/LoginFailedMessage');

function payload(errorCode, fingerprint = '', message = '') {
  const s = new ByteStream();
  s.writeInt(errorCode);
  s.writeOptionalString(fingerprint);
  s.writeOptionalString('');
  s.writeOptionalString('');
  s.writeOptionalString('');
  s.writeOptionalString(message);
  return s.getBytes();
}

function fakeMessaging(config = { major: 69, minor: 252, build: 0 }) {
  const calls = [];
  return {
    calls,
    config,
    crypto: { sessionKey: null },
    saveConfig() { calls.push(['saveConfig']); },
    close(reason) { calls.push(['close', reason]); },
  };
}

test('error 8 carries an actionable hint about a stale build or license block', () => {
  const msg = new LoginFailed();
  msg.ByteStream.set(payload(8));
  msg.decode();
  const messaging = fakeMessaging();
  msg.process(messaging);

  assert.equal(msg.errorCode, 8);
  assert.match(msg.hint, /stale/);
  assert.match(msg.hint, /APK-UPDATE\.md/);
  assert.deepEqual(messaging.calls, [['close', 'LoginFailed']]);
});

test('a LoginFailed fingerprint is diagnostic only and never rewrites config', () => {
  const fingerprint = JSON.stringify({ sha: 'a'.repeat(40), version: '69.253.0' });
  const msg = new LoginFailed();
  msg.ByteStream.set(payload(8, fingerprint));
  msg.decode();
  const messaging = fakeMessaging({ major: 69, minor: 252, build: 0, fingerprintHash: 'b'.repeat(40) });
  msg.process(messaging);
  assert.deepEqual(
    [messaging.config.major, messaging.config.minor, messaging.config.build],
    [69, 252, 0],
  );
  assert.equal(messaging.config.fingerprintHash, 'b'.repeat(40));
  assert.deepEqual(messaging.calls, [['close', 'LoginFailed']]);
});

test('error 7 decompresses its server content manifest without saving unverified data', () => {
  const fp = { version: '70.877.22', sha: '7a43eaf696d48fa587fcf76c8518b5a792ecf65d', files: [] };
  const json = Buffer.from(JSON.stringify(fp));
  const compressed = zlib.deflateSync(json);
  const p = new ByteStream();
  p.writeInt(7);
  p.writeOptionalString(null);
  p.writeOptionalString(null);
  p.writeOptionalString('https://example.com/content');
  p.writeOptionalString(null);
  p.writeOptionalString(null);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(compressed.length);
  const uncompressedLength = Buffer.alloc(4);
  uncompressedLength.writeUInt32LE(json.length);
  const bytes = Buffer.concat([p.getBytes(), Buffer.alloc(5), length, uncompressedLength, compressed]);
  const msg = new LoginFailed();
  msg.ByteStream.set(bytes);
  msg.decode();
  const messaging = fakeMessaging({ major: 69, minor: 252, build: 44, fingerprintHash: 'a'.repeat(40) });
  const previous = globalThis.Debugger;
  const warnings = [];
  globalThis.Debugger = { error() {}, warn(message) { warnings.push(message); } };
  try {
    msg.process(messaging);
  } finally {
    globalThis.Debugger = previous;
  }
  assert.match(msg.hint, /content update/);
  assert.ok(warnings.some((message) => message.includes('70.877.22')));
  assert.ok(warnings.some((message) => message.includes(fp.sha)));
  assert.equal(messaging.config.fingerprintHash, 'a'.repeat(40));
  assert.deepEqual(messaging.calls, [['close', 'LoginFailed']]);
});

test('unknown error code still closes the session without a hint', () => {
  const msg = new LoginFailed();
  msg.ByteStream.set(payload(77));
  msg.decode();
  const messaging = fakeMessaging();
  msg.process(messaging);

  assert.equal(msg.hint, '');
  assert.deepEqual(messaging.calls, [['close', 'LoginFailed']]);
});
