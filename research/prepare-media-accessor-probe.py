"""Bind a narrower media-object probe to verified accessor/consumer functions."""
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(root / "tools/static-python"))
import pefile

sample = root / "samples/windows-extracted/Tatotalk.exe"
assert hashlib.sha256(sample.read_bytes()).hexdigest() == "76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58"
pe = pefile.PE(str(sample), fast_load=True)
candidates = [{"rva": rva, "kind": kind, "bytes": pe.get_data(rva, 32).hex()}
              for rva, kind in [(0x3e4c90, "photo-accessor"),
                                (0x3e4dc0, "document-accessor"),
                                (0x8f2040, "message-consumer")]]
assert candidates[0]["bytes"] == "4883ec288179080f3b22b5750d488b014885c0741f4883c428c341b8f6350000"
assert candidates[1]["bytes"] == "4883ec28817908d314447c750d488b014885c0741f4883c428c341b817360000"
template = (root / "windows-marked-media-probe.template.js").read_text(encoding="utf-8")
prefix = template.split("try {\n  for (const candidate", 1)[0]
prefix = prefix.replace("/*EXPECTED_CANDIDATES*/null", json.dumps(candidates))
tail = r'''
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
          let mediaWrapper, captionLayout;
          counts[candidate.kind] = (counts[candidate.kind] || 0) + 1;
          if (candidate.kind === 'message-consumer') {
            const wrapper = args[1];
            if (!readable(wrapper, 16) || wrapper.add(8).readU32() !== 0x81ff9c4a) return;
            const message = wrapper.readPointer();
            if (!readable(message, 0x70)) return;
            diagnoseMessage(message);
            captionLayout = matchedCaptionLayout(message);
            if (captionLayout === null) return;
            mediaWrapper = message.add(0x60);
          } else {
            mediaWrapper = args[0];
            if (!readable(mediaWrapper, 16)) return;
            const tag = mediaWrapper.add(8).readU32();
            if (tag !== (candidate.kind === 'photo-accessor' ? 0xb5223b0f : 0x7c4414d3)) return;
            const payload = mediaWrapper.readPointer();
            if (!readable(payload, 0x40)) return;
            const flags = payload.add(0x10).readU32();
            if (diagnosticMessages < 32) {
              diagnosticMessages++;
              const diagnostic = {source: candidate.kind, mediaTag: tagString(tag),
                mediaFlags: flags, captionByteLength: payload.add(0x38).readU64().toString()};
              messageDiagnostics.push(diagnostic);
              console.log('TATO_MEDIA_DIAG:' + JSON.stringify(diagnostic));
            }
            if ((flags & 2) === 0 || !exactCaption(payload.add(0x28))) return;
            captionLayout = candidate.kind + ':payload+0x28';
          }
          const media = photoMetadata(mediaWrapper);
          const match = {caption: TEST_CAPTION, captionLayout, observedAt: new Date().toISOString(),
            source: candidate.kind, candidateRva: tagString(candidate.rva),
            newUpdateEventProven: false, media};
          if (this.returnAddress.compare(module.base) >= 0 &&
              this.returnAddress.compare(module.base.add(module.size)) < 0) {
            match.callerRva = this.returnAddress.sub(module.base).toString();
          }
          pendingMatch = true;
          setImmediate(() => finish(media.photoRecognized ? 'exact-test-photo-object' : 'exact-test-media-object', match));
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
'''
target = root / "windows-media-accessor-probe.js"
target.write_text(prefix + tail, encoding="utf-8")
print(json.dumps({"script": str(target), "candidates": candidates}, ensure_ascii=False))
