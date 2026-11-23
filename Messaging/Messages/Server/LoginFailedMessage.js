const ByteStream = require('../../../DataStream/ByteStream');

// Код ошибки входа -> что с этим делать. Сервер отдаёт только число, поэтому
// без подсказки пользователь видит "login failed 8" и не понимает, что делать.
const HINTS = {
  8: 'the client build or its license block is stale: client-license.bin is bound to one '
   + 'APK build and its size. Update to the latest release and re-cut the block '
   + '(docs/APK-UPDATE.md).',
  9: 'the server replied with a redirect (ServerHost). The client does not follow it automatically.',
  10: 'the server rejected the session, usually after a duplicate login of the same account.',
};

function safe(fn, fallback = null) {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

module.exports = class LoginFailedMessage {
  constructor() {
    this.ByteStream = new ByteStream();
  }

  decode() {
    const s = this.ByteStream;
    this.errorCode = s.readInt();

    // Brawl's plaintext/pre-handshake 20103 keeps the older Titan-style layout:
    // error, fingerprint, serverHost, patching/contentHost, updateHost, message, ...
    this.fingerprint = safe(() => s.readOptionalString(), '');
    this.serverHost = safe(() => s.readOptionalString(), '');
    this.patchingHost = safe(() => s.readOptionalString(), '');
    this.updateHost = safe(() => s.readOptionalString(), '');
    this.message = safe(() => s.readOptionalString(), '');

    // Preserve remaining bytes for research/debugging.
    this.remaining = Buffer.from(s.payload.slice(s.offset));
    this.remainingHex = this.remaining.toString('hex');
  }

  process(messaging) {
    const phase = messaging.crypto && !messaging.crypto.sessionKey ? 'ClientHello/pre-handshake' : 'Login';
    const extra = [];
    if (this.serverHost) extra.push(`serverHost=${this.serverHost}`);
    if (this.message) extra.push(`message=${this.message}`);
    if (this.patchingHost) extra.push(`patchingHost=${this.patchingHost}`);
    if (this.updateHost) extra.push(`updateHost=${this.updateHost}`);
    if (this.remaining.length) extra.push(`tail=${this.remaining.length}B`);

    this.hint = HINTS[this.errorCode] || '';
    globalThis.Debugger?.error?.(`LoginFailed phase=${phase} error=${this.errorCode}${extra.length ? ' ' + extra.join(' ') : ''}`);
    if (this.hint) globalThis.Debugger?.warn?.(`LoginFailed error=${this.errorCode}: ${this.hint}`);

    if (this.errorCode === 9 && this.serverHost && /stage\.brawlstarsgame\.com/i.test(this.serverHost)) {
      globalThis.Debugger?.warn?.(
        'The stage.brawlstarsgame.com string is a ServerHost field in the Brawl LoginFailed layout; it is not automatically followed as a redirect.',
      );
    }

    if (this.fingerprint) {
      try {
        const fp = JSON.parse(this.fingerprint);
        if (fp && typeof fp === 'object') {
          const version = typeof fp.version === 'string' ? fp.version : '';
          const sha = typeof fp.sha === 'string' ? fp.sha : '';
          const validVersion = /^[0-9]+[.][0-9]+[.][0-9]+$/.test(version);
          const validSha = /^[a-f0-9]{40}$/i.test(sha);
          if (validVersion && validSha) {
            const clientVersion = [messaging.config.major, messaging.config.minor, messaging.config.build].join('.');
            globalThis.Debugger?.warn?.(
              `Server content fingerprint: version=${version} sha=${sha}; configured content version=${clientVersion}`,
            );
            if (clientVersion !== version || messaging.config.fingerprintHash !== sha)
              globalThis.Debugger?.warn?.('Content fingerprint differs; run the verified updater before retrying.');
          } else {
            globalThis.Debugger?.warn?.('LoginFailed fingerprint has invalid version or SHA.');
          }
        }
      } catch (error) {
        globalThis.Debugger?.warn?.(`LoginFailed fingerprint JSON could not be parsed: ${error.message}`);
      }
    }
    // A LoginFailed packet is not proof that a new fingerprint works.
    // Never persist server-supplied fields before successful login verification.
    messaging.close('LoginFailed');
  }
};
