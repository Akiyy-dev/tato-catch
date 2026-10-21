"""Conservative PE xref candidate finder; does not execute or disassemble the sample.

RIP-relative byte patterns can occur inside another instruction or inline data.
This tool deliberately emits candidates, never verified function or hook addresses.
"""
from bisect import bisect_right
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parent
EXE = ROOT / 'samples' / 'windows-extracted' / 'Tatotalk.exe'
OUT = ROOT / 'windows-xref-candidates.json'
data = EXE.read_bytes()
def u16(o): return struct.unpack_from('<H', data, o)[0]
def u32(o): return struct.unpack_from('<I', data, o)[0]
pe = u32(0x3c)
coff = pe + 4
optional = coff + 20
assert data[:2] == b'MZ' and data[pe:pe + 4] == b'PE\0\0'
assert u16(coff) == 0x8664 and u16(optional) == 0x20b
image_base = struct.unpack_from('<Q', data, optional + 24)[0]
directories = [struct.unpack_from('<II', data, optional + 112 + n * 8) for n in range(16)]
sections = []
for index in range(u16(coff + 2)):
    offset = optional + u16(coff + 16) + index * 40
    name = data[offset:offset + 8].rstrip(b'\0').decode('ascii', 'replace')
    size, rva, rawsize, rawoffset = struct.unpack_from('<IIII', data, offset + 8)
    flags = u32(offset + 36)
    sections.append(dict(name=name, virtual_size=size, rva=rva, raw_size=rawsize, raw_offset=rawoffset, flags=flags))

def file_to_rva(offset):
    for section in sections:
        if section['raw_offset'] <= offset < section['raw_offset'] + section['raw_size']:
            return section['rva'] + offset - section['raw_offset']
    raise ValueError(f'Unmapped file offset: {offset:x}')

def rva_to_file(rva):
    for section in sections:
        if section['rva'] <= rva < section['rva'] + section['raw_size']:
            return section['raw_offset'] + rva - section['rva']
    raise ValueError(f'Unmapped RVA: {rva:x}')

functions = []
exception_rva, exception_size = directories[3]
exception_offset = rva_to_file(exception_rva)
for offset in range(exception_offset, exception_offset + exception_size - 11, 12):
    begin, end, unwind = struct.unpack_from('<III', data, offset)
    if begin and end > begin:
        functions.append((begin, end, unwind))
functions.sort()
begins = [item[0] for item in functions]

def containing_function(rva):
    position = bisect_right(begins, rva) - 1
    if position < 0:
        return None
    begin, end, unwind = functions[position]
    if not begin <= rva < end:
        return None
    unwind_offset = rva_to_file(unwind)
    first, prolog, unwind_count, frame = struct.unpack_from('<BBBB', data, unwind_offset)
    flags = first >> 3
    result = dict(
        begin_rva=hex(begin), end_rva_exclusive=hex(end), preferred_begin_va=hex(image_base + begin),
        begin_file_offset=hex(rva_to_file(begin)), length=end - begin,
        unwind_info_rva=hex(unwind), unwind_version=first & 7, unwind_flags=flags,
        unwind_prolog_length=prolog, unwind_code_slots=unwind_count,
        boundary_evidence='PE Exception Directory RUNTIME_FUNCTION entry; may describe a compiler funclet/chunk rather than an independently callable function.',
    )
    if flags & 4:
        chained_offset = unwind_offset + 4 + ((unwind_count + 1) & ~1) * 2
        chain_begin, chain_end, chain_unwind = struct.unpack_from('<III', data, chained_offset)
        result['chained_runtime_function'] = dict(begin_rva=hex(chain_begin), end_rva_exclusive=hex(chain_end), unwind_info_rva=hex(chain_unwind))
    return result

diagnostics = [
    ('applyUpdateNoPtsCheck', b'Unexpected: Type in applyUpdateNoPtsCheck()'),
    ('applyUpdatesNoPtsCheck', b'Unexpected: Type in applyUpdatesNoPtsCheck()'),
    ('updateNewMessageDifference', b'getDifference { good - after not all data loaded in updateNewMessage }%1'),
    ('updateNewChannelMessageDifference', b'getDifference { good - after not all data loaded in updateNewChannelMessage }%1'),
    ('updateShortMessageDifference', b'getDifference { good - getting user for updateShortMessage }%1'),
    ('updateShortChatMessageDifference', b'getDifference { good - getting user for updateShortChatMessage }%1'),
]
targets = []
target_by_rva = {}
for label, needle in diagnostics:
    position = 0
    while True:
        offset = data.find(needle, position)
        if offset < 0:
            break
        rva = file_to_rva(offset)
        target = dict(label=label, text=needle.decode(), file_offset=hex(offset), rva=hex(rva), preferred_va=hex(image_base + rva), xref_candidates=[])
        targets.append(target)
        target_by_rva[rva] = target
        position = offset + len(needle)

text_section = next(item for item in sections if item['name'] == '.text')
start = text_section['raw_offset']
end = start + text_section['raw_size']
register64 = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15']
for opcode_offset in range(start, end - 5):
    opcode = data[opcode_offset]
    if opcode not in (0x8d, 0x8b, 0x89, 0x8a, 0x88):
        continue
    modrm = data[opcode_offset + 1]
    if modrm & 0xc7 != 0x05:
        continue
    displacement = struct.unpack_from('<i', data, opcode_offset + 2)[0]
    next_rva = file_to_rva(opcode_offset) + 6
    destination_rva = next_rva + displacement
    target = target_by_rva.get(destination_rva)
    if target is None:
        continue
    prefix_offset = opcode_offset
    rex = 0
    if opcode_offset > start and 0x40 <= data[opcode_offset - 1] <= 0x4f:
        prefix_offset -= 1
        rex = data[prefix_offset]
    instruction_rva = file_to_rva(prefix_offset)
    function = containing_function(instruction_rva)
    register = ((modrm >> 3) & 7) + (8 if rex & 4 else 0)
    width = 64 if rex & 8 else (8 if opcode in (0x8a, 0x88) else 32)
    operation = 'LEA' if opcode == 0x8d else 'MOV'
    direction = 'register_from_address' if opcode == 0x8d else ('register_from_memory' if opcode in (0x8b, 0x8a) else 'memory_from_register')
    confidence = 'medium-byte-pattern-only' if function is not None and opcode == 0x8d and rex & 8 else 'low-byte-pattern-only'
    candidate = dict(
        file_offset=hex(prefix_offset), opcode_file_offset=hex(opcode_offset), rva=hex(instruction_rva),
        preferred_va=hex(image_base + instruction_rva), bytes=data[prefix_offset:opcode_offset + 6].hex(' '),
        apparent_operation=operation, apparent_register_64bit_name=register64[register], apparent_operand_width=width,
        apparent_direction=direction, rip_displacement=displacement, resolved_target_rva=hex(destination_rva),
        containing_runtime_function=function, confidence=confidence,
        limitations=['Instruction boundaries were not validated with a full decoder.', 'The opcode may be embedded in another instruction or inline data.', 'The .pdata boundary is not proof of the semantic function name.', 'Preferred VA changes when ASLR relocates the module; use the actual module base plus RVA.', 'Not validated as a safe hook site.'],
        context_file_offset=hex(max(start, prefix_offset - 16)), context_bytes=data[max(start, prefix_offset - 16):opcode_offset + 22].hex(' '),
    )
    target['xref_candidates'].append(candidate)

report = dict(
    sample_path=str(EXE), sample_sha256=hashlib.sha256(data).hexdigest(), preferred_image_base=hex(image_base),
    method='Static PE mapping, .text x64 RIP-relative LEA/MOV byte-pattern matching, and .pdata RUNTIME_FUNCTION range lookup; no executable launch or injection.',
    dependencies='Python standard library only; no Capstone, iced-x86, pefile, Ghidra, or disassembler installed or used.',
    runtime_function_count=len(functions), text_section=text_section, targets=targets,
    overall_caveat='Candidate references are not full disassembly and are not ready-to-hook addresses. Confirm instruction boundaries and code paths with a real disassembler before dynamic use.',
)
OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
print(json.dumps(dict(report=str(OUT), preferred_image_base=hex(image_base), runtime_function_count=len(functions), targets=targets), indent=2, ensure_ascii=False))
