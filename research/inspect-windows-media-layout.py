"""Bounded static media accessor verification against the extracted PE only."""
from pathlib import Path
import bisect, json, struct, sys, hashlib
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools' / 'static-python'))
import capstone, pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
data = (ROOT / 'samples/windows-extracted/Tatotalk.exe').read_bytes()
pe = pefile.PE(data=data, fast_load=True)
pd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
funcs = list(struct.iter_unpack('<III', pe.get_data(pd.VirtualAddress, pd.Size)))
starts = [x[0] for x in funcs]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
def function_at(rva):
    n = bisect.bisect_right(starts, rva) - 1
    return funcs[n] if n >= 0 and funcs[n][0] <= rva < funcs[n][1] else None
def decode(begin, end):
    return list(md.disasm(pe.get_data(begin, end-begin), begin))
needles = [b'"_type == mtpc_messageMediaPhoto"', b'"_type == mtpc_photo"', b'"_type == mtpc_photoSize"', b'"_type == mtpc_photoCachedSize"', b'"_type == mtpc_messageMediaDocument"']
strings = {}
for needle in needles:
    p = 0
    while (p := data.find(needle, p)) >= 0:
        strings[pe.get_rva_from_offset(p)] = needle.decode(); p += len(needle)
text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
raw = text.get_data(); base = text.VirtualAddress
refs = []
for i in range(len(raw)-6):
    if raw[i] not in (0x8d, 0x8b): continue
    if raw[i+1] & 0xc7 != 5: continue
    target = base+i+6+struct.unpack_from('<i',raw,i+2)[0]
    if target not in strings: continue
    start = base+i-(1 if i > 0 and 0x40 <= raw[i-1] <= 0x4f else 0)
    f = function_at(start)
    if not f: continue
    ins = decode(f[0], f[1])
    at = next((x for x in ins if x.address == start), None)
    if at is None: continue
    refs.append(dict(name=strings[target], string_rva=hex(target), reference_rva=hex(start), function_rva=hex(f[0]), end_rva=hex(f[1]), complete=ins[-1].address+ins[-1].size==f[1], instructions=[dict(rva=hex(x.address), asm=x.mnemonic+' '+x.op_str, bytes=x.bytes.hex(' ')) for x in ins]))
extra=[]
for begin,end in [(0x3e09f0,0x3e0bd9),(0x3f1e40,0x3f1ee8),(0x3f2c50,0x3f2cfe),(0x3f2a27,0x3f2a89),(0x5952e0,0x59540e),(0x3e2124,0x3e2276),(0x3e1d36,0x3e1e4a),(0x3e5740,0x3e57ec),(0x8f2040,0x8f2518)]:
    ins=decode(begin,end)
    extra.append(dict(begin_rva=hex(begin),end_rva=hex(end), instructions=[dict(rva=hex(x.address),asm=x.mnemonic+' '+x.op_str,bytes=x.bytes.hex(' ')) for x in ins]))
call_evidence=[]
for begin,end,wanted in [(0x8f2040,0x8f23f0,[0x8f2248]),(0xdc1ba0,0xdc21e0,[0xdc1c3e,0xdc1c60])]:
    f=function_at(begin)
    ins=decode(f[0],f[1])
    for call in wanted:
        idx=next(i for i,x in enumerate(ins) if x.address==call)
        call_evidence.append(dict(call_rva=hex(call),containing_function_rva=hex(f[0]),instructions=[dict(rva=hex(x.address),asm=x.mnemonic+' '+x.op_str,bytes=x.bytes.hex(' ')) for x in ins[max(0,idx-6):idx+8]]))
out=dict(method='Static PE only; no process/cache/profile reads.',sha256=hashlib.sha256(data).hexdigest(),accessors=refs,construction_and_serialization=extra,media_consumer_calls=call_evidence)
(ROOT/'windows-media-layout-evidence.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
print(json.dumps(dict(accessors=[{k:v for k,v in x.items() if k!='instructions'} for x in refs],report='windows-media-layout-evidence.json'),indent=2))
