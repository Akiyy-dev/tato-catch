// Client path is injected by the runner after PID and file validation.
const TARGET_EXE = /*TARGET_EXE*/null;
if (typeof TARGET_EXE !== 'string' || !TARGET_EXE) {
  throw new Error('Use the text stream runner with --target-exe');
}
const INCLUDE_OUTGOING = /*INCLUDE_OUTGOING*/false;
if (typeof INCLUDE_OUTGOING !== 'boolean') {
  throw new Error('Outgoing-message configuration must be boolean');
}
// Version-bound, fixed-field listener. No profile, session, media or heap reads.
// Peer/sender layouts follow static accessors and conversation helper evidence.
// Native message IDs follow the sample deserializer/getter; date epoch remains unproved.
// Capture keys identify observations; native IDs are scoped by conversation.
const MAX_TEXT_BYTES = 262144;
const MAX_TEXT_CODEPOINTS = 65536;
const EXPECTED_CANDIDATES = [
  {rva: 14393216, bytes: '48895c240848897424185557415441564157488bec4883ec704c8bf933f68b42'},
  {rva: 14390688, bytes: '48894c2408555356574154415541564157488dac2448ffffff4881ecf8010000'},
  {rva: 15019072, bytes: '48895c24085556574154415541564157488dac24b0feffff4881ec5002000048'},
  {rva: 15016016, bytes: '48895c24084c894424185556574154415541564157488d6c24d94881ecf00000'}
];
const module = Process.enumerateModules().find(item => item.name.toLowerCase() === 'tatotalk.exe');
if (!module || module.path.split(String.fromCharCode(92)).filter(Boolean)
    .join(String.fromCharCode(92)).toLowerCase() !== TARGET_EXE.toLowerCase()) {
  throw new Error('Authorized module not found');
}
const sessionKey = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
const activePayloads = new Map();
const counts = {callbacks: 0, recognized: 0, emitted: 0, nestedDuplicates: 0,
  rejectedText: 0, readErrors: 0, outgoingSkipped: 0, identityUnavailable: 0};
let sequence = 0;
let completed = false;
let heartbeatTimer = null;
function readable(address, length) {
  if (address.isNull() || !Number.isSafeInteger(length) || length < 0 || length > MAX_TEXT_BYTES) return false;
  const range = Process.findRangeByAddress(address);
  return range !== null && range.protection.indexOf('r') !== -1 &&
    address.compare(range.base) >= 0 &&
    address.add(length).compare(range.base.add(range.size)) <= 0;
}
// Decode the exact bounded byte array strictly. An embedded NUL is retained;
// malformed sequences and over-limit messages are rejected, never truncated.
function decodeUtf8(bytes) {
  const chars = [];
  for (let offset = 0, points = 0; offset < bytes.length; points++) {
    if (points >= MAX_TEXT_CODEPOINTS) return null;
    const first = bytes[offset++];
    let codepoint;
    let trailing;
    let minimum;
    if (first <= 0x7f) { codepoint = first; trailing = 0; minimum = 0; }
    else if (first >= 0xc2 && first <= 0xdf) { codepoint = first & 0x1f; trailing = 1; minimum = 0x80; }
    else if (first >= 0xe0 && first <= 0xef) { codepoint = first & 0x0f; trailing = 2; minimum = 0x800; }
    else if (first >= 0xf0 && first <= 0xf4) { codepoint = first & 0x07; trailing = 3; minimum = 0x10000; }
    else return null;
    if (offset + trailing > bytes.length) return null;
    for (let index = 0; index < trailing; index++) {
      const next = bytes[offset++];
      if ((next & 0xc0) !== 0x80) return null;
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if (codepoint < minimum || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) return null;
    chars.push(String.fromCodePoint(codepoint));
  }
  return chars.join('');
}
function tryText(field) {
  if (!readable(field, 24)) return null;
  const length = field.add(16).readU64().toNumber();
  if (!Number.isSafeInteger(length) || length <= 0 || length > MAX_TEXT_BYTES) return null;
  const data = field.add(8).readPointer();
  if (!readable(data, length)) return null;
  const text = decodeUtf8(new Uint8Array(data.readByteArray(length)));
  return text !== null && text.trim().length > 0 ? text : null;
}
// Static proof: peer accessors 0x3d7c80/0x3d7cd0/0x3d7d20,
// peer resolver 0x725c00 and Message conversation resolver 0x79ddb0.
// Incoming private Message peers describe the recipient (self); conversation
// identity must therefore come from the sender field when flags include 0x100.
// Normalize outgoing sender omission across short/full observations because
// the short private update does not expose the verified self sender.
function messageMetadata(payload, flags) {
  const metadata = {};
  // Getter 0x79de90 and deserializer 0x3df711 prove uint32 message ID +0x18.
  const messageId = payload.add(0x18).readU32();
  if (messageId > 0) metadata.message_id = String(messageId);
  const sender = (flags & 0x100) ? payload.add(0x1c).readU32() : 0;
  if (sender > 0 && !(flags & 2)) metadata.sender = String(sender);
  const peer = payload.add(0x20);
  const tag = peer.add(8).readU32();
  let kind;
  if (tag === 0x9db1bc6d) kind = 'user';
  else if (tag === 0xbad0e5bb) kind = 'chat';
  else if (tag === 0xbddde532) kind = 'channel';
  else return metadata;
  const peerPayload = peer.readPointer();
  if (!readable(peerPayload, 0x14)) return metadata;
  const peerId = peerPayload.add(0x10).readU32();
  const conversationId = kind === 'user' && !(flags & 2) ? sender : peerId;
  if (peerId > 0 && conversationId > 0) metadata.conversation_id = kind + ':' + conversationId;
  return metadata;
}
function status() {
  return {session: sessionKey, observed_at: new Date().toISOString(),
    running: !completed, counts: Object.assign({}, counts)};
}
function stop(reason) {
  if (completed) return status();
  completed = true;
  Interceptor.detachAll();
  if (heartbeatTimer !== null) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
  activePayloads.clear();
  console.log('TATO_LISTENER_STOPPED:' + JSON.stringify(Object.assign(status(), {reason})));
  return status();
}
function release(context) {
  if (!context.listenerPayloadKey) return;
  const count = activePayloads.get(context.listenerPayloadKey);
  if (count > 1) activePayloads.set(context.listenerPayloadKey, count - 1);
  else activePayloads.delete(context.listenerPayloadKey);
  context.listenerPayloadKey = null;
}
try {
  // Validate every candidate before attaching even one callback.
  for (const candidate of EXPECTED_CANDIDATES) {
    const address = module.base.add(candidate.rva);
    if (!readable(address, 32)) throw new Error('Candidate code unreadable');
    const bytes = Array.from(new Uint8Array(address.readByteArray(32)))
      .map(value => value.toString(16).padStart(2, '0')).join('');
    if (bytes !== candidate.bytes) throw new Error('Candidate code changed');
  }
  for (const candidate of EXPECTED_CANDIDATES) {
    Interceptor.attach(module.base.add(candidate.rva), {
      onEnter(args) {
        if (completed) return;
        counts.callbacks++;
        try {
          const wrapper = args[1];
          if (!readable(wrapper, 16)) return;
          const tag = wrapper.add(8).readU32();
          const payload = wrapper.readPointer();
          let textPayload;
          let field;
          let metadata = {};
          if (tag === 0x914fbf11 || tag === 0x16812688) {
            if (!readable(payload, 0x38)) return;
            const flags = payload.add(0x10).readU32();
            if ((flags & 2) && !INCLUDE_OUTGOING) { counts.outgoingSkipped++; return; }
            // Short synthesis 0xdb95a0 copies short +0x14 to Message +0x18.
            const messageId = payload.add(0x14).readU32();
            if (messageId > 0) metadata.message_id = String(messageId);
            const sender = payload.add(0x18).readU32();
            if (sender > 0 && !(flags & 2)) metadata.sender = String(sender);
            if (tag === 0x914fbf11 && sender > 0) metadata.conversation_id = 'user:' + sender;
            if (tag === 0x16812688) {
              const chatId = payload.add(0x1c).readU32();
              if (chatId > 0) metadata.conversation_id = 'chat:' + chatId;
            }
            textPayload = payload;
            field = payload.add(0x20);
          } else if (tag === 0x1f2b0afd || tag === 0x62ba04d9) {
            if (!readable(payload, 0x20)) return;
            const message = payload.add(0x10);
            if (message.add(8).readU32() !== 0x81ff9c4a) return;
            textPayload = message.readPointer();
            if (!readable(textPayload, 0x60)) return;
            const flags = textPayload.add(0x10).readU32();
            if ((flags & 2) && !INCLUDE_OUTGOING) { counts.outgoingSkipped++; return; }
            metadata = messageMetadata(textPayload, flags);
            field = textPayload.add(0x48);
          } else return;
          counts.recognized++;
          // Suppress only overlapping nested hooks for this exact object and
          // thread. No time window or text hash: a subsequent observation gets
          // a new sequence even when its text or allocation address is reused.
          // Sequential duplicate observations can still occur; no exactly-once
          // or disconnected-history coverage is claimed without native IDs.
          const key = Process.getCurrentThreadId() + ':' + textPayload.toString();
          const active = activePayloads.get(key) || 0;
          activePayloads.set(key, active + 1);
          this.listenerPayloadKey = key;
          if (active) { counts.nestedDuplicates++; return; }
          const text = tryText(field);
          if (text === null) { counts.rejectedText++; return; }
          if (!metadata.conversation_id) counts.identityUnavailable++;
          const event = Object.assign({event_key: 'capture:' + sessionKey + ':' + (++sequence), text}, metadata);
          console.log('TATO_TEXT_EVENT:' + JSON.stringify(event));
          counts.emitted++;
        } catch (_) {
          counts.readErrors++;
        }
      },
      onLeave() { release(this); }
    });
  }
  if (typeof rpc !== 'undefined') {
    rpc.exports = {stop: () => stop('host-request'), status};
  }
  heartbeatTimer = setInterval(() => {
    if (!completed) console.log('TATO_LISTENER_HEARTBEAT:' + JSON.stringify(status()));
  }, 10000);
  console.log('TATO_LISTENER_READY:' + JSON.stringify(status()));
} catch (error) {
  stop('startup-error');
  throw error;
}
