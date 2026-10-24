"""Exercise the actual listener in a Node VM with synthetic Frida memory only."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
LISTENER = ROOT / "research/windows-text-listener.js"
NODE = shutil.which("node")

HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const spec = JSON.parse(fs.readFileSync(0, 'utf8'));
const separator = String.fromCharCode(92);
const syntheticDrive = 'Q' + ':';
const fixturePath = [syntheticDrive, 'fixture', 'Tatotalk.exe'].join(separator);
const wrongPath = [syntheticDrive, 'wrong', 'Tatotalk.exe'].join(separator);
const regions = [];
let next = 0x20000000;
let reads = 0;
const candidates = [
 [14393216, '48895c240848897424185557415441564157488bec4883ec704c8bf933f68b42'],
 [14390688, '48894c2408555356574154415541564157488dac2448ffffff4881ecf8010000'],
 [15019072, '48895c24085556574154415541564157488dac24b0feffff4881ec5002000048'],
 [15016016, '48895c24084c894424185556574154415541564157488d6c24d94881ecf00000']
];
class Ptr {
 constructor(value) { this.value = Number(value); }
 add(value) { return new Ptr(this.value + value); }
 isNull() { return this.value === 0; }
 compare(other) { return Math.sign(this.value - other.value); }
 toString() { return '0x' + this.value.toString(16); }
 region(length) {
  reads++;
  const result = regions.find(r => this.value >= r.base && this.value + length <= r.base + r.data.length);
  if (!result) throw Error('synthetic invalid read');
  return [result.data, this.value - result.base];
 }
 readPointer() { const [data, offset] = this.region(8); return new Ptr(data.readBigUInt64LE(offset)); }
 readU32() { const [data, offset] = this.region(4); return data.readUInt32LE(offset); }
 readU64() { const [data, offset] = this.region(8); const n = data.readBigUInt64LE(offset); return {toNumber: () => Number(n)}; }
 readByteArray(length) { const [data, offset] = this.region(length); return Uint8Array.from(data.subarray(offset, offset + length)).buffer; }
}
function allocate(size) {
 const region = {base: next, data: Buffer.alloc(size), protection: 'rw-'};
 next += size + 64;
 regions.push(region);
 return {ptr: new Ptr(region.base), data: region.data, region};
}
function pointer(buffer, offset, ptr) { buffer.writeBigUInt64LE(BigInt(ptr.value), offset); }
const base = new Ptr(0x10000000);
for (const [rva, hex] of candidates) regions.push({base: base.value + rva, data: Buffer.from(hex, 'hex'), protection: 'r-x'});
if (spec.code_changed) regions[2].data[0] = 0;
const logs = [];
const callbacks = [];
const intervals = new Map();
let detached = 0;
let timerId = 0;
const context = {
 Process: {
  id: 1234,
  getCurrentThreadId: () => 77,
  enumerateModules: () => [{name: 'Tatotalk.exe', path: spec.wrong_path ? wrongPath : fixturePath, base}],
  findRangeByAddress: ptr => {
   const r = regions.find(r => ptr.value >= r.base && ptr.value < r.base + r.data.length);
   return r ? {base: new Ptr(r.base), size: r.data.length, protection: r.protection} : null;
  }
 },
 Interceptor: {attach: (address, handlers) => {
  if (spec.attach_failure_after === callbacks.length) throw Error('synthetic attach failure');
  callbacks.push({address, handlers}); return {detach() {}};
 }, detachAll: () => {detached++;}},
 console: {log: value => logs.push(value)},
 setInterval: callback => {const id = ++timerId; intervals.set(id, callback); return id;},
 clearInterval: id => intervals.delete(id),
 rpc: {exports: {}},
 Uint8Array, Date, Math, Map, Set, Array, Number, String, JSON, Error
};
vm.createContext(context);
let startupError = null;
try {
 let source = fs.readFileSync(process.argv[1], 'utf8');
 if (!spec.unbound) source = source.replace('/*TARGET_EXE*/null', JSON.stringify(fixturePath));
 source = source.replace('/*INCLUDE_OUTGOING*/false', JSON.stringify(Boolean(spec.include_outgoing)));
 vm.runInContext(source, context);
} catch (error) { startupError = String(error.message); }
const saved = new Map();
function message(operation) {
 if (operation.reuse && saved.has(operation.reuse)) return saved.get(operation.reuse);
 const tag = operation.tag === undefined ? 0x914fbf11 : operation.tag;
 const wrapper = allocate(16);
 const short = tag === 0x914fbf11 || tag === 0x16812688;
 const payload = allocate(short ? 0x38 : 0x20);
 pointer(wrapper.data, 0, operation.invalid_pointer ? new Ptr(1) : payload.ptr);
 wrapper.data.writeUInt32LE(tag >>> 0, 8);
 let field;
 if (short) {
  payload.data.writeUInt32LE((operation.flags || 0) >>> 0, 0x10);
  payload.data.writeUInt32LE((operation.message_id || 0) >>> 0, 0x14);
  payload.data.writeUInt32LE((operation.sender || 0) >>> 0, 0x18);
  payload.data.writeUInt32LE((operation.peer_id || 0) >>> 0, 0x1c);
  field = {data: payload.data, offset: 0x20};
 }
 else {
  const inner = allocate(0x60);
  pointer(payload.data, 0x10, inner.ptr);
  payload.data.writeUInt32LE((operation.inner_tag === undefined ? 0x81ff9c4a : operation.inner_tag) >>> 0, 0x18);
  inner.data.writeUInt32LE((operation.flags || 0) >>> 0, 0x10);
  inner.data.writeUInt32LE((operation.message_id || 0) >>> 0, 0x18);
  inner.data.writeUInt32LE((operation.sender || 0) >>> 0, 0x1c);
  if (operation.peer_tag !== undefined) {
   const peer = allocate(0x14);
   peer.data.writeUInt32LE((operation.peer_id || 0) >>> 0, 0x10);
   if (operation.unreadable_peer) peer.region.protection = '---';
   pointer(inner.data, 0x20, operation.invalid_peer ? new Ptr(1) : peer.ptr);
   inner.data.writeUInt32LE(operation.peer_tag >>> 0, 0x28);
  }
  field = {data: inner.data, offset: 0x48};
 }
 const bytes = operation.bytes ? Buffer.from(operation.bytes) : Buffer.from(operation.text || '', 'utf8');
 const text = allocate(Math.max(1, bytes.length));
 bytes.copy(text.data);
 if (operation.unreadable) text.region.protection = '---';
 pointer(field.data, field.offset + 8, text.ptr);
 field.data.writeBigUInt64LE(BigInt(operation.length === undefined ? bytes.length : operation.length), field.offset + 16);
 const result = wrapper.ptr;
 if (operation.reuse) saved.set(operation.reuse, result);
 return result;
}
for (const operation of spec.operations || []) {
 if (startupError) break;
 if (operation.op === 'heartbeat') { for (const callback of Array.from(intervals.values())) callback(); continue; }
 if (operation.op === 'stop') { context.rpc.exports.stop(); continue; }
 const wrapper = message(operation);
 const first = callbacks[operation.candidate || 0];
 const call = {};
 first.handlers.onEnter.call(call, [new Ptr(0), wrapper]);
 if (operation.nested) {
  const inner = {};
  callbacks[1].handlers.onEnter.call(inner, [new Ptr(0), wrapper]);
  if (callbacks[1].handlers.onLeave) callbacks[1].handlers.onLeave.call(inner);
 }
 if (first.handlers.onLeave) first.handlers.onLeave.call(call);
}
process.stdout.write(JSON.stringify({logs, startupError, detached, hooks: callbacks.length, timers: intervals.size, reads}));
"""


@unittest.skipUnless(NODE, "Node.js is required for the synthetic Frida VM tests")
class TextListenerTests(unittest.TestCase):
    def run_listener(self, **spec):
        result = subprocess.run([NODE, "-e", HARNESS, str(LISTENER)], input=json.dumps(spec),
                                capture_output=True, text=True, encoding="utf-8", timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def events(self, result):
        return [json.loads(line.split(":", 1)[1]) for line in result["logs"]
                if line.startswith("TATO_TEXT_EVENT:")]

    def test_arbitrary_text_remains_continuous_without_fixed_marker(self):
        result = self.run_listener(operations=[{"text": "任意私聊正文"}, {"text": "another message"},
                                              {"text": "频道\U0001f600", "tag": 0x62BA04D9},
                                              {"text": "群聊", "tag": 0x16812688},
                                              {"text": "普通消息", "tag": 0x1F2B0AFD}])
        self.assertIsNone(result["startupError"])
        self.assertEqual(result["hooks"], 4)
        self.assertEqual([event["text"] for event in self.events(result)],
                         ["任意私聊正文", "another message", "频道\U0001f600", "群聊", "普通消息"])
        self.assertTrue(any(line.startswith("TATO_LISTENER_READY") for line in result["logs"]))
        self.assertEqual(result["detached"], 0)

    def test_repeated_same_body_and_reused_pointer_get_distinct_capture_keys(self):
        result = self.run_listener(operations=[{"text": "same", "reuse": "object", "nested": True},
                                              {"reuse": "object"}, {"text": "same"}])
        events = self.events(result)
        self.assertEqual([event["text"] for event in events], ["same"] * 3)
        keys = [event["event_key"] for event in events]
        self.assertEqual(len(set(keys)), 3)
        for event in events:
            self.assertLessEqual(len(event["event_key"]), 256)
            self.assertEqual(set(event), {"event_key", "text"})
            self.assertRegex(event["event_key"], r"^capture:[0-9a-z]+-[0-9a-z]+:[1-9][0-9]*$")

    def test_bad_tags_addresses_empty_and_whitespace_are_ignored(self):
        result = self.run_listener(operations=[{"text": "ignored", "tag": 0x11111111},
                                              {"text": "ignored", "tag": 0x1F2B0AFD, "inner_tag": 0x11111111},
                                              {"text": "ignored", "invalid_pointer": True},
                                              {"text": "ignored", "unreadable": True},
                                              {"text": ""}, {"text": " \t\r\n"}, {"text": "valid"}])
        self.assertEqual([event["text"] for event in self.events(result)], ["valid"])

    def test_overlong_and_invalid_utf8_are_rejected_without_partial_output(self):
        result = self.run_listener(operations=[{"text": "x", "length": 262145},
                                              {"text": "x" * 65537},
                                              {"text": "\U0001f600" * 65536},
                                              {"bytes": [0xC0, 0xAF]},
                                              {"bytes": [0xED, 0xA0, 0x80]},
                                              {"bytes": [0xF4, 0x90, 0x80, 0x80]},
                                              {"bytes": [0xE4, 0xB8]},
                                              {"bytes": [0x80]},
                                              {"text": "ok\u0000whole"}])
        self.assertEqual([event["text"] for event in self.events(result)],
                         ["\U0001f600" * 65536, "ok\u0000whole"])

    def test_readiness_fails_closed_before_attach_on_code_or_target_change(self):
        for spec in ({"code_changed": True}, {"wrong_path": True}, {"unbound": True}):
            with self.subTest(spec=spec):
                result = self.run_listener(**spec)
                self.assertIsNotNone(result["startupError"])
                self.assertEqual(result["hooks"], 0)
                self.assertFalse(self.events(result))
                self.assertFalse(any(line.startswith("TATO_LISTENER_READY") for line in result["logs"]))

    def test_partial_attachment_failure_detaches_before_any_ready_or_event(self):
        result = self.run_listener(attach_failure_after=2)
        self.assertEqual(result["startupError"], "synthetic attach failure")
        self.assertEqual(result["hooks"], 2)
        self.assertEqual(result["detached"], 1)
        self.assertEqual(result["timers"], 0)
        self.assertFalse(self.events(result))
        self.assertFalse(any(line.startswith("TATO_LISTENER_READY") for line in result["logs"]))

    def test_heartbeat_contains_counts_and_stop_detaches_and_clears_timer(self):
        result = self.run_listener(operations=[{"text": "secret body"}, {"op": "heartbeat"},
                                              {"op": "stop"}, {"text": "after stop"},
                                              {"op": "stop"}, {"op": "heartbeat"}])
        self.assertEqual(len(self.events(result)), 1)
        self.assertEqual(result["detached"], 1)
        self.assertEqual(result["timers"], 0)
        statuses = [line for line in result["logs"] if not line.startswith("TATO_TEXT_EVENT:")]
        self.assertFalse(any("secret body" in line for line in statuses))
        self.assertTrue(any(line.startswith("TATO_LISTENER_HEARTBEAT:") for line in statuses))
        self.assertTrue(any(line.startswith("TATO_LISTENER_STOPPED:") for line in statuses))

    def test_verified_peer_identity_uses_sender_for_incoming_private(self):
        result = self.run_listener(operations=[
            {"text": "private", "tag": 0x1F2B0AFD, "flags": 0x100, "sender": 42,
             "peer_tag": 0x9DB1BC6D, "peer_id": 999},
            {"text": "chat", "tag": 0x1F2B0AFD, "flags": 0x100, "sender": 43,
             "peer_tag": 0xBAD0E5BB, "peer_id": 55},
            {"text": "channel", "tag": 0x62BA04D9,
             "peer_tag": 0xBDDDE532, "peer_id": 77},
            {"text": "short private", "sender": 44},
            {"text": "short chat", "tag": 0x16812688, "sender": 45, "peer_id": 56}])
        events = self.events(result)
        self.assertEqual([event.get("conversation_id") for event in events],
                         ["user:42", "chat:55", "channel:77", "user:44", "chat:56"])
        self.assertEqual([event.get("sender") for event in events], ["42", "43", None, "44", "45"])
        self.assertTrue(all("message_id" not in event and "timestamp" not in event for event in events))

    def test_unproved_or_unreadable_peer_identity_keeps_text_without_inventing_metadata(self):
        result = self.run_listener(operations=[
            {"text": "unsupported", "tag": 0x1F2B0AFD, "peer_tag": 0x11111111, "peer_id": 1},
            {"text": "invalid", "tag": 0x1F2B0AFD, "peer_tag": 0xBAD0E5BB, "invalid_peer": True},
            {"text": "unreadable", "tag": 0x1F2B0AFD, "peer_tag": 0xBDDDE532, "unreadable_peer": True},
            {"text": "private sender absent", "tag": 0x1F2B0AFD, "sender": 42,
             "peer_tag": 0x9DB1BC6D, "peer_id": 999},
            {"text": "zero peer", "tag": 0x1F2B0AFD, "peer_tag": 0xBAD0E5BB, "peer_id": 0}])
        events = self.events(result)
        self.assertEqual(len(events), 5)
        self.assertTrue(all(set(event) == {"event_key", "text"} for event in events))

    def test_outgoing_flag_is_filtered_for_short_private_chat_and_full_messages(self):
        result = self.run_listener(operations=[
            {"text": "own private", "flags": 2, "sender": 42},
            {"text": "own chat", "tag": 0x16812688, "flags": 2, "sender": 42},
            {"text": "own full", "tag": 0x1F2B0AFD, "flags": 0x102, "sender": 42,
             "peer_tag": 0x9DB1BC6D, "peer_id": 43},
            {"text": "incoming", "sender": 43}])
        events = self.events(result)
        self.assertEqual([event["text"] for event in events], ["incoming"])
        self.assertEqual(events[0]["conversation_id"], "user:43")

    def test_explicit_include_outgoing_uses_recipient_peer_without_fabricating_sender(self):
        result = self.run_listener(include_outgoing=True, operations=[
            {"text": "own short private", "flags": 2, "sender": 42},
            {"text": "own short chat", "tag": 0x16812688, "flags": 2, "sender": 999, "peer_id": 55},
            {"text": "own full private", "tag": 0x1F2B0AFD, "flags": 0x102, "sender": 999,
             "peer_tag": 0x9DB1BC6D, "peer_id": 42}])
        events = self.events(result)
        self.assertEqual(len(events), 3)
        self.assertEqual([event["conversation_id"] for event in events], ["user:42", "chat:55", "user:42"])
        self.assertEqual([event.get("sender") for event in events], [None, None, None])

    def test_outgoing_short_and_full_native_identity_have_identical_payload_metadata(self):
        result = self.run_listener(include_outgoing=True, operations=[
            {"text": "same", "flags": 2, "sender": 42, "message_id": 101},
            {"text": "same", "tag": 0x1F2B0AFD, "flags": 0x102, "sender": 999,
             "peer_tag": 0x9DB1BC6D, "peer_id": 42, "message_id": 101},
            {"text": "same", "tag": 0x16812688, "flags": 2, "sender": 999,
             "peer_id": 55, "message_id": 102},
            {"text": "same", "tag": 0x1F2B0AFD, "flags": 0x102, "sender": 999,
             "peer_tag": 0xBAD0E5BB, "peer_id": 55, "message_id": 102}])
        events = self.events(result)
        self.assertEqual(len(events), 4)
        payloads = [{key: value for key, value in event.items() if key != "event_key"}
                    for event in events]
        self.assertEqual(payloads[0], payloads[1])
        self.assertEqual(payloads[2], payloads[3])
        self.assertTrue(all("sender" not in event for event in events))
        self.assertEqual(events[0]["conversation_id"], "user:42")
        self.assertEqual(events[2]["conversation_id"], "chat:55")

    def test_verified_native_ids_agree_for_short_and_full_and_preserve_same_body_messages(self):
        result = self.run_listener(operations=[
            {"text": "same", "sender": 42, "message_id": 101},
            {"text": "same", "tag": 0x1F2B0AFD, "flags": 0x100, "sender": 42,
             "peer_tag": 0x9DB1BC6D, "peer_id": 999, "message_id": 101},
            {"text": "same", "sender": 42, "message_id": 102},
            {"text": "same", "tag": 0x1F2B0AFD, "flags": 0x100, "sender": 42,
             "peer_tag": 0x9DB1BC6D, "peer_id": 999, "message_id": 103}])
        events = self.events(result)
        self.assertEqual([event["conversation_id"] for event in events], ["user:42"] * 4)
        self.assertEqual([event["message_id"] for event in events], ["101", "101", "102", "103"])
        self.assertEqual(len({event["event_key"] for event in events}), 4)
        self.assertEqual([event["text"] for event in events], ["same"] * 4)
        self.assertTrue(all("timestamp" not in event for event in events))

    def test_zero_native_id_is_omitted_for_short_and_full(self):
        result = self.run_listener(operations=[
            {"text": "short", "sender": 42, "message_id": 0},
            {"text": "full", "tag": 0x1F2B0AFD, "flags": 0x100, "sender": 42,
             "peer_tag": 0x9DB1BC6D, "peer_id": 999, "message_id": 0}])
        events = self.events(result)
        self.assertEqual(len(events), 2)
        self.assertTrue(all("message_id" not in event for event in events))

    def test_source_limits_reading_to_checked_fields_and_has_no_heap_scan(self):
        source = LISTENER.read_text(encoding="utf-8")
        self.assertEqual(source.count("/*TARGET_EXE*/null"), 1)
        for forbidden in ("Memory.scan", "enumerateRanges", "readUtf8String", "readUtf16String",
                          "TEST_TEXT", "TEST_BYTE_LENGTH", "120000", "File("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
