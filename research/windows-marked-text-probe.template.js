// Throwaway, version-bound probe. Exports only the exact user-supplied test text.
const TEST_TEXT = 'TATO-PROBE-20261020-你好';
const TEST_BYTE_LENGTH = 26;
const EXPECTED_CANDIDATES = /*EXPECTED_CANDIDATES*/null;
const module = Process.enumerateModules().find(item => item.name.toLowerCase() === 'tatotalk.exe');
if (!module || module.path.split(String.fromCharCode(92)).filter(Boolean)
    .join(String.fromCharCode(92)).toLowerCase() !== 'd:\\ttt\\tatotalk.exe') {
  throw new Error('Authorized module not found');
}
function readable(address, length) {
  if (address.isNull() || length < 0 || length > 1024) return false;
  const range = Process.findRangeByAddress(address);
  return range !== null && range.protection.indexOf('r') !== -1 &&
    address.add(length).compare(range.base.add(range.size)) <= 0;
}
const counts = {};
let readErrors = 0;
let stringCandidates = 0;
let expectedLengthCandidates = 0;
let completed = false;
let pendingMatch = false;
let timer = null;
const startedAt = new Date().toISOString();
function finish(reason, match) {
  if (completed) return;
  completed = true;
  Interceptor.detachAll();
  if (timer !== null) clearTimeout(timer);
  console.log('TATO_TEXT_PROBE:' + JSON.stringify({
    pid: Process.id, startedAt, finishedAt: new Date().toISOString(),
    reason, matched: match !== null, match, counts, readErrors,
    stringCandidates, expectedLengthCandidates,
    hooksDetached: true,
    scope: 'Only constructor tags and verified-layout string fields; only the exact fixed test text can be exported; no account/profile/session files'
  }));
}
function tryText(field) {
  if (!readable(field, 24)) return null;
  const length = field.add(16).readU64().toNumber();
  stringCandidates++;
  if (length !== TEST_BYTE_LENGTH) return null;
  expectedLengthCandidates++;
  const data = field.add(8).readPointer();
  if (!readable(data, length)) return null;
  const text = data.readUtf8String(length);
  return text === TEST_TEXT ? text : null;
}
try {
  for (const candidate of EXPECTED_CANDIDATES) {
    const address = module.base.add(candidate.rva);
    const bytes = Array.from(new Uint8Array(address.readByteArray(32)))
      .map(value => value.toString(16).padStart(2, '0')).join('');
    if (bytes !== candidate.bytes) throw new Error('Candidate code changed');
  }
  for (const candidate of EXPECTED_CANDIDATES) {
    Interceptor.attach(module.base.add(candidate.rva), {
      onEnter(args) {
        if (completed || pendingMatch) return;
        try {
          const wrapper = args[1];
          if (!readable(wrapper, 16)) return;
          const tag = wrapper.add(8).readU32();
          const label = '0x' + candidate.rva.toString(16) + ':0x' + tag.toString(16);
          counts[label] = (counts[label] || 0) + 1;
          let field = null;
          let layout = null;
          const payload = wrapper.readPointer();
          if (tag === 0x914fbf11 || tag === 0x16812688) {
            if (!readable(payload, 0x38)) return;
            field = payload.add(0x20);
            layout = 'short-update-payload+0x20';
          } else if (tag === 0x1f2b0afd || tag === 0x62ba04d9) {
            if (!readable(payload, 0x20)) return;
            const message = payload.add(0x10);
            if (message.add(8).readU32() !== 0x81ff9c4a) return;
            const messagePayload = message.readPointer();
            if (!readable(messagePayload, 0x60)) return;
            field = messagePayload.add(0x48);
            layout = 'new-message-payload+0x48';
          } else {
            return;
          }
          const text = tryText(field);
          if (text !== null) {
            pendingMatch = true;
            const match = {text, encoding: 'UTF-8', byteLength: TEST_BYTE_LENGTH,
              updateTag: '0x' + tag.toString(16), candidateRva: '0x' + candidate.rva.toString(16), layout,
              observedAt: new Date().toISOString()};
            setImmediate(() => finish('exact-test-message', match));
          }
        } catch (_) {
          readErrors++;
        }
      }
    });
  }
  timer = setTimeout(() => finish('timeout', null), 120000);
  console.log('TATO_TEXT_READY');
} catch (error) {
  Interceptor.detachAll();
  throw error;
}
