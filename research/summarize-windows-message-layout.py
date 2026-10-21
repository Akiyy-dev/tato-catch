"""Summarize static input-tag dispatch and candidate message field evidence."""
from collections import deque
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools' / 'static-python'))
import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RDX, X86_REG_EAX

sample = (ROOT / 'samples' / 'windows-extracted' / 'Tatotalk.exe').read_bytes()
pe = pefile.PE(data=sample, fast_load=True)
validation = json.loads((ROOT / 'windows-disassembly-validation.json').read_text())
accessors = json.loads((ROOT / 'windows-payload-accessor-evidence.json').read_text())
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True

name_by_tag = {}
for function in accessors['functions']:
    if len(function.get('comparisons',[])) != 1:
        continue
    names = [item['text'] for item in function.get('diagnostic_strings',[]) if '_type == mtpc_' in item['text']]
    if names:
        name_by_tag[function['comparisons'][0]['value_u32']] = names[0].split('mtpc_',1)[1].rstrip('"')

functions = []
for function in validation['functions']:
    begin = int(function['boundary']['begin_rva'],16)
    end = int(function['boundary']['end_rva_exclusive'],16)
    instructions = list(decoder.disasm(pe.get_data(begin,end-begin),begin))
    by_address = {instruction.address:instruction for instruction in instructions}
    load = next(instruction for instruction in instructions[:30] if instruction.mnemonic=='mov' and len(instruction.operands)==2 and instruction.operands[0].type==X86_OP_REG and instruction.operands[0].reg==X86_REG_EAX and instruction.operands[1].type==X86_OP_MEM and instruction.operands[1].mem.base==X86_REG_RDX and instruction.operands[1].mem.disp==8)
    work = deque([load.address+load.size])
    visited = set()
    comparisons = []
    while work:
        address = work.popleft()
        if address in visited or address not in by_address:
            continue
        visited.add(address)
        instruction = by_address[address]
        operands = instruction.operands
        if instruction.group(capstone.CS_GRP_CALL) or instruction.group(capstone.CS_GRP_RET):
            continue
        if instruction.mnemonic == 'cmp' and len(operands)==2 and operands[0].type==X86_OP_REG and operands[0].reg==X86_REG_EAX and operands[1].type==X86_OP_IMM:
            value = hex(operands[1].imm & 0xffffffff)
            comparisons.append(dict(rva=hex(address), value_u32=value, name_from_sample_accessor_assertion=name_by_tag.get(value)))
        _, writes = instruction.regs_access()
        if any(decoder.reg_name(register) in ('rax','eax','ax','al','ah') for register in writes):
            continue
        if instruction.group(capstone.CS_GRP_JUMP):
            if operands and operands[0].type==X86_OP_IMM:
                work.append(operands[0].imm)
            if instruction.mnemonic != 'jmp':
                work.append(address+instruction.size)
        else:
            work.append(address+instruction.size)
    comparisons.sort(key=lambda item:int(item['rva'],16))
    functions.append(dict(begin_rva=hex(begin), input_tag_load_rva=hex(load.address), input_tag_comparison_candidates=comparisons, caveat='Control-flow walk tracks the original EAX loaded from [RDX+8] only until any EAX write, call, return, or unresolved jump. Constants may include dispatch pivots; not an exhaustive semantic switch reconstruction.'))

report = dict(
    sample_sha256=hashlib.sha256(sample).hexdigest(),
    scope='Static extracted official sample only; no process, profile, or conversation access.',
    input_tag_dispatch=functions,
    sample_verified_type_names=name_by_tag,
    wrapper=dict(size_candidate=16, payload_pointer_offset='0x0', type_u32_offset='0x8', evidence='Small typed accessors compare [RCX+8], return pointer [RCX] after non-null check, and reference exact mtpc_* type assertions.'),
    short_message_text_candidate=dict(tags=['0x914fbf11','0x16812688'], payload_text_object_offset='0x20', object_size=24, refcount_owner_pointer_offset='0x20', data_pointer_candidate_offset='0x28', element_count_candidate_offset='0x30', evidence=['Short-chat branch copies payload qwords +0x20/+0x28/+0x30 into normal-message qwords +0x48/+0x50/+0x58 and increments int refcount at first pointer.', 'Short-private branch supplies payload+0x20 to the normal-message constructor.', 'Type names are confirmed by the sample generated accessor assertion strings.']),
    normal_message_text_candidate=dict(update_tags=['0x1f2b0afd','0x62ba04d9'], message_wrapper_offset_in_update_payload='0x10', required_message_tag='0x81ff9c4a', message_payload_text_object_offset='0x48', data_pointer_candidate_offset='0x50', element_count_candidate_offset='0x58', evidence=['Accessor 0x3e09a0 compares tag 0x81ff9c4a and references _type == mtpc_message.', 'Normal-message destructor 0x3e06d0 uses messageData+0x48 as the array object at instruction 0x3e082d and calls 0x387f80.', '0x387f80 decrements first-pointer int refcount, then passes element size 1 and alignment 8 to array deallocation target 0x26f4840.']),
    qt_evidence=dict(version='6.11.0', compile_path_suffix='Libraries/win64/Qt-6.11.0/include/QtCore/qarraydataops.h', source_reference_in_function_rva='0x387f80', array_element_size=1, allocation_alignment=8, conclusion='Qt one-byte shared array is supported; QByteArray/UTF-8 MTP string is a candidate interpretation. Exact runtime text must still be checked with the unique test prefix.'),
    rejected_tag_interpretation=dict(tag='0x3ded6320', explanation='This appears in an empty media-wrapper constructor and is not the normal message tag.'),
    controlled_validation_limits=['Do not scan the heap.', 'Read only a validated wrapper/payload pointer chain for recognized tags.', 'Check mapped readable ranges and a small bounded length.', 'Compare only the designated unique test prefix before retaining the full test text.', 'UTF-8 decoding and ptr/length word semantics still require actual controlled runtime confirmation.'],
    reference_urls=['https://core.telegram.org/schema','https://core.telegram.org/type/Updates','https://core.telegram.org/api/updates','https://raw.githubusercontent.com/telegramdesktop/tdesktop/dev/Telegram/SourceFiles/mtproto/core_types.h'],
    schema_caveat='Shared constructor IDs and code structure do not prove TatoTalk service/backend, accounts, authorization, or wire protocol compatibility with Telegram or legacy Potato.',
)
out = ROOT/'windows-message-layout-evidence.json'
out.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps(dict(report=str(out), verified_types=name_by_tag, input_tag_candidates=[dict(begin=f['begin_rva'],count=len(f['input_tag_comparison_candidates']),values=[c['value_u32'] for c in f['input_tag_comparison_candidates']]) for f in functions]),indent=2))
