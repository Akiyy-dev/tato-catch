// Client path is injected by the runner after PID and file validation.
const TARGET_EXE = /*TARGET_EXE*/null;
if (typeof TARGET_EXE !== 'string' || !TARGET_EXE) {
  throw new Error('Use run_windows_module_probe.py with --target-exe');
}
// Throwaway, sample-bound probe. Exports media only for the exact test caption.
const TEST_CAPTION = 'TATO-IMG-PROBE';
const EXPECTED_CANDIDATES = /*EXPECTED_CANDIDATES*/null;
const MAX_CACHED_BYTES = 256 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024;
const module = Process.enumerateModules().find(item => item.name.toLowerCase() === 'tatotalk.exe');
if (!module || module.path.split(String.fromCharCode(92)).filter(Boolean)
    .join(String.fromCharCode(92)).toLowerCase() !== TARGET_EXE.toLowerCase()) {
  throw new Error('Authorized module not found');
}
function readable(address, length) {
  if (address.isNull() || !Number.isSafeInteger(length) || length < 0 || length > MAX_TOTAL_BYTES) return false;
  const range = Process.findRangeByAddress(address);
  return range !== null && range.protection.indexOf('r') !== -1 &&
    address.add(length).compare(range.base.add(range.size)) <= 0;
}
function tagString(value) { return '0x' + value.toString(16); }
function exactCaption(field) {
  if (!readable(field, 24)) return false;
  const length = field.add(16).readU64().toNumber();
  if (length !== TEST_CAPTION.length) return false;
  const data = field.add(8).readPointer();
  return readable(data, length) && data.readUtf8String(length) === TEST_CAPTION;
}
function matchedCaptionLayout(message) {
  if (exactCaption(message.add(0x48))) return 'message+0x48';
  const mediaWrapper = message.add(0x60);
  const mediaTag = mediaWrapper.add(8).readU32();
  if (mediaTag !== 0xb5223b0f && mediaTag !== 0x7c4414d3) return null;
  const payload = mediaWrapper.readPointer();
  if (!readable(payload, 0x40) || (payload.add(0x10).readU32() & 2) === 0) return null;
  return exactCaption(payload.add(0x28)) ?
    (mediaTag === 0xb5223b0f ? 'messageMediaPhoto+0x28' : 'messageMediaDocument+0x28') : null;
}
function diagnoseMessage(message) {
  if (diagnosticMessages >= 32) return;
  diagnosticMessages++;
  const media = message.add(0x60);
  const tag = media.add(8).readU32();
  const diagnostic = {mediaTag: tagString(tag),
    bodyByteLength: message.add(0x58).readU64().toString()};
  if (tag === 0xb5223b0f || tag === 0x7c4414d3) {
    const payload = media.readPointer();
    if (readable(payload, 0x40)) {
      diagnostic.mediaFlags = payload.add(0x10).readU32();
      diagnostic.captionByteLength = payload.add(0x38).readU64().toString();
    }
  }
  messageDiagnostics.push(diagnostic);
  console.log('TATO_MEDIA_DIAG:' + JSON.stringify(diagnostic));
}
function photoMetadata(mediaWrapper) {
  const result = {mediaTag: tagString(mediaWrapper.add(8).readU32()), photoRecognized: false, sizes: []};
  if (mediaWrapper.add(8).readU32() !== 0xb5223b0f) return result;
  const mediaPayload = mediaWrapper.readPointer();
  if (!readable(mediaPayload, 0x28)) return result;
  const photoWrapper = mediaPayload.add(0x18);
  result.photoTag = tagString(photoWrapper.add(8).readU32());
  if (photoWrapper.add(8).readU32() !== 0x9288dd29) return result;
  const photo = photoWrapper.readPointer();
  if (!readable(photo, 0x48)) return result;
  result.photoRecognized = true;
  const sizeCount = photo.add(0x40).readU64().toNumber();
  result.sizeCount = sizeCount;
  if (!Number.isSafeInteger(sizeCount) || sizeCount < 0 || sizeCount > 32) {
    result.vectorError = 'size-count-out-of-bounds';
    return result;
  }
  const entries = photo.add(0x38).readPointer();
  if (sizeCount > 0 && !readable(entries, sizeCount * 16)) {
    result.vectorError = 'size-vector-unreadable';
    return result;
  }
  let copiedBytes = 0;
  for (let i = 0; i < sizeCount; i++) {
    const wrapper = entries.add(i * 16);
    const tag = wrapper.add(8).readU32();
    const item = {index: i, tag: tagString(tag)};
    result.sizes.push(item);
    if (tag !== 0x77bfb61b && tag !== 0xe9a734fa) continue;
    const payload = wrapper.readPointer();
    if (!readable(payload, tag === 0xe9a734fa ? 0x58 : 0x44)) {
      item.error = 'size-payload-unreadable';
      continue;
    }
    item.kind = tag === 0xe9a734fa ? 'photoCachedSize' : 'photoSize';
    item.width = payload.add(0x38).readS32();
    item.height = payload.add(0x3c).readS32();
    if (tag === 0x77bfb61b) {
      item.declaredBytesCandidate = payload.add(0x40).readU32();
      continue;
    }
    const length = payload.add(0x50).readU64().toNumber();
    item.embeddedByteLength = length;
    if (!Number.isSafeInteger(length) || length < 1 || length > MAX_CACHED_BYTES || copiedBytes + length > MAX_TOTAL_BYTES) {
      item.byteStatus = 'empty-or-over-probe-limit';
      continue;
    }
    const data = payload.add(0x48).readPointer();
    if (!readable(data, length)) {
      item.byteStatus = 'unreadable';
      continue;
    }
    // Copy while the intercepted update still owns these objects. Never retain pointers.
    item.embeddedHex = Array.from(new Uint8Array(data.readByteArray(length)))
      .map(value => value.toString(16).padStart(2, '0')).join('');
    copiedBytes += length;
    item.byteStatus = 'copied-correlated-embedded-data';
  }
  result.copiedEmbeddedBytes = copiedBytes;
  return result;
}
const counts = {};
const messageDiagnostics = [];
let diagnosticMessages = 0;
let readErrors = 0;
let completed = false;
let pendingMatch = false;
let timer = null;
const startedAt = new Date().toISOString();
function finish(reason, match) {
  if (completed) return;
  completed = true;
  Interceptor.detachAll();
  if (timer !== null) clearTimeout(timer);
  console.log('TATO_MEDIA_PROBE:' + JSON.stringify({
    pid: Process.id, startedAt, finishedAt: new Date().toISOString(), reason,
    matched: match !== null, match, counts, messageDiagnostics, readErrors, hooksDetached: true,
    scope: 'Only media associated with exact fixed caption; bounded embedded thumbnail bytes; no chat history/profile/session files, access hashes or full-image download'
  }));
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
          const label = tagString(candidate.rva) + ':' + tagString(tag);
          counts[label] = (counts[label] || 0) + 1;
          if (tag !== 0x1f2b0afd && tag !== 0x62ba04d9) return;
          const update = wrapper.readPointer();
          if (!readable(update, 0x20)) return;
          const messageWrapper = update.add(0x10);
          const messageTag = messageWrapper.add(8).readU32();
          const messageLabel = 'messageType:' + tagString(messageTag);
          counts[messageLabel] = (counts[messageLabel] || 0) + 1;
          if (messageTag !== 0x81ff9c4a) return;
          const message = messageWrapper.readPointer();
          if (!readable(message, 0x70)) return;
          diagnoseMessage(message);
          const captionLayout = matchedCaptionLayout(message);
          if (captionLayout === null) return;
          const media = photoMetadata(message.add(0x60));
          const match = {caption: TEST_CAPTION, captionLayout, observedAt: new Date().toISOString(),
            updateTag: tagString(tag), candidateRva: tagString(candidate.rva),
            layout: 'message+0x60 -> mediaPhoto+0x18 -> photo+0x30 sizes', media};
          pendingMatch = true;
          setImmediate(() => finish(media.photoRecognized ? 'exact-test-photo' : 'exact-caption-media-unrecognized', match));
        } catch (_) { readErrors++; }
      }
    });
  }
  timer = setTimeout(() => finish('timeout', null), 170000);
  console.log('TATO_MEDIA_READY');
} catch (error) {
  Interceptor.detachAll();
  throw error;
}
