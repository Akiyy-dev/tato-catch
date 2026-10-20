"""Static Capstone validation of previously found PE code-reference candidates.

Reads only the extracted sample and reports. Does not inspect or attach to a process.
"""
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = ROOT / 'tools' / 'python'
sys.path.insert(0, str(DEPENDENCIES))
sys.path.insert(0, str(ROOT / 'tools' / 'static-python'))
try:
    import capstone
    import pefile
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except ImportError as error:
    print(f'WAITING_FOR_DEPENDENCIES: {error}')
    raise SystemExit(2)

EXE = ROOT / 'samples' / 'windows-extracted' / 'Tatotalk.exe'
XREFS = ROOT / 'windows-xref-candidates.json'
OUTPUT = ROOT / 'windows-disassembly-validation.json'
MARKDOWN = ROOT / 'windows-disassembly-validation.md'
sample = EXE.read_bytes()
source = json.loads(XREFS.read_text(encoding='utf-8'))
assert hashlib.sha256(sample).hexdigest() == source['sample_sha256'], 'Sample hash changed'
pe = pefile.PE(data=sample, fast_load=True)
image_base = pe.OPTIONAL_HEADER.ImageBase
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True
decoder.skipdata = False

grouped = {}
for target in source['targets']:
    for xref in target['xref_candidates']:
        function = xref.get('containing_runtime_function')
        if function is None:
            continue
        begin = int(function['begin_rva'], 16)
        group = grouped.setdefault(begin, dict(boundary=function, targets=[]))
        group['targets'].append(dict(label=target['label'], string_rva=target['rva'], reference_rva=xref['rva'], original_bytes=xref['bytes']))

def register_root(name):
    classic = {'eax':'rax','ax':'rax','al':'rax','ah':'rax','ebx':'rbx','bx':'rbx','bl':'rbx','bh':'rbx','ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx','edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx','esi':'rsi','si':'rsi','sil':'rsi','edi':'rdi','di':'rdi','dil':'rdi','ebp':'rbp','bp':'rbp','bpl':'rbp','esp':'rsp','sp':'rsp','spl':'rsp'}
    if name in classic:
        return classic[name]
    if name.startswith('r') and name[-1:] in ('d','w','b') and name[1:-1].isdigit():
        return name[:-1]
    return name

def instruction_record(instruction):
    return dict(rva=hex(instruction.address), preferred_va=hex(image_base + instruction.address), file_offset=hex(pe.get_offset_from_rva(instruction.address)), bytes=bytes(instruction.bytes).hex(' '), mnemonic=instruction.mnemonic, operands=instruction.op_str)

def expression(operand, origins):
    if operand.type == X86_OP_REG:
        name = decoder.reg_name(operand.reg)
        origin = origins.get(register_root(name), name)
        return f'low{operand.size * 8}({origin})' if operand.size < 8 else origin
    if operand.type == X86_OP_MEM:
        memory = operand.mem
        base = decoder.reg_name(memory.base) if memory.base else ''
        index = decoder.reg_name(memory.index) if memory.index else ''
        parts = []
        if base:
            parts.append(origins.get(register_root(base), base))
        if index:
            parts.append(origins.get(register_root(index), index) + f'*{memory.scale}')
        if memory.disp:
            parts.append(hex(memory.disp))
        return f'memory{operand.size * 8}[' + ' + '.join(parts) + ']'
    if operand.type == X86_OP_IMM:
        return hex(operand.imm)
    return 'untracked'

results = []
for begin, group in sorted(grouped.items()):
    end = int(group['boundary']['end_rva_exclusive'], 16)
    code = pe.get_data(begin, end - begin)
    instructions = list(decoder.disasm(code, begin))
    decoded_end = instructions[-1].address + instructions[-1].size if instructions else begin
    contiguous = all(left.address + left.size == right.address for left, right in zip(instructions, instructions[1:]))
    complete = decoded_end == end and contiguous
    instruction_by_address = {item.address:item for item in instructions}
    reference_validation = []
    for target in group['targets']:
        address = int(target['reference_rva'], 16)
        instruction = instruction_by_address.get(address)
        references = []
        if instruction is not None:
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    references.append(instruction.address + instruction.size + operand.mem.disp)
        validated = instruction is not None and int(target['string_rva'], 16) in references
        reference_validation.append(dict(**target, is_instruction_boundary_from_pdata_begin=instruction is not None, rip_target_matches_string=validated, decoded_instruction=instruction_record(instruction) if instruction else None, confidence='high-for-static-instruction-and-reference' if validated else 'unconfirmed', semantic_function_name_verified=False, safe_hook_site_verified=False))

    origins = dict(rcx='arg0/RCX', rdx='arg1/RDX', r8='arg2/R8', r9='arg3/R9')
    argument_flow = []
    for instruction in instructions[:80]:
        operands = instruction.operands
        old = origins.copy()
        try:
            _, writes = instruction.regs_access()
        except capstone.CsError:
            writes = []
        for register in writes:
            origins.pop(register_root(decoder.reg_name(register)), None)
        if instruction.mnemonic in ('mov','movzx','movsxd','lea') and len(operands) >= 2 and operands[0].type == X86_OP_REG:
            destination = register_root(decoder.reg_name(operands[0].reg))
            value = expression(operands[1], old)
            if instruction.mnemonic == 'lea':
                value = 'address(' + value + ')'
            if 'arg0/RCX' in value or 'arg1/RDX' in value:
                origins[destination] = value
                argument_flow.append(dict(**instruction_record(instruction), destination_register=destination, approximate_origin=value))
        if instruction.mnemonic == 'call':
            for name in ('rax','rcx','rdx','r8','r9','r10','r11'):
                origins.pop(name, None)

    immediate_comparisons = []
    direct_calls = defaultdict(list)
    indirect_calls = []
    for instruction in instructions:
        operands = instruction.operands
        if instruction.mnemonic in ('cmp','test') and any(item.type == X86_OP_IMM for item in operands):
            immediates = [item.imm for item in operands if item.type == X86_OP_IMM]
            immediate_comparisons.append(dict(**instruction_record(instruction), immediate_signed=immediates, immediate_as_u32=[hex(value & 0xffffffff) for value in immediates], semantic_role='unclassified comparison/test constant; not proven to be an update discriminator'))
        if instruction.mnemonic == 'call':
            if operands and operands[0].type == X86_OP_IMM:
                direct_calls[operands[0].imm].append(hex(instruction.address))
            else:
                indirect_calls.append(instruction_record(instruction))
    constants = Counter(value for item in immediate_comparisons for value in item['immediate_as_u32'])
    hash_like = {value:count for value,count in constants.items() if 0x10000 <= int(value, 16) < 0xffff0000}
    results.append(dict(
        boundary=group['boundary'], range_bytes=end-begin, instruction_count=len(instructions), decoded_bytes=decoded_end-begin,
        decoded_end_rva=hex(decoded_end), contiguous_decode=contiguous, complete_range_decode=complete,
        undecoded_tail_bytes=code[decoded_end-begin:decoded_end-begin+32].hex(' '),
        reference_validation=reference_validation,
        prologue_and_first_instructions=[instruction_record(item) for item in instructions[:45]],
        approximate_argument_flow_first_80_instructions=argument_flow,
        argument_flow_caveat='Microsoft x64 ABI argument labels only. Linear local register tracking does not model branch joins, aliases, stack spills, callee semantics, or distinguish this/update roles.',
        immediate_comparisons=immediate_comparisons, comparison_constant_counts=dict(constants), large_u32_comparison_candidates=hash_like,
        direct_calls=[dict(target_rva=hex(address), preferred_target_va=hex(image_base+address), count=len(sites), callsite_rvas=sites) for address,sites in sorted(direct_calls.items())],
        indirect_calls=indirect_calls,
    ))

report = dict(
    sample_path=str(EXE), sample_sha256=source['sample_sha256'], preferred_image_base=hex(image_base),
    tool_versions=dict(capstone=capstone.__version__, pefile=pefile.__version__),
    method='Full linear Capstone x64 decode from each .pdata begin RVA to its end, then verify exact string RIP references at decoded boundaries; static sample only.',
    global_caveats=['A complete linear decode proves decodability, not reachability or semantic function identity.', 'The .pdata range may be a compiler funclet or chunk.', 'Comparison constants are not assigned message categories without validated data flow or runtime evidence.', 'No client or process was started, read, attached to, or injected into.', 'These findings alone do not establish safe hook addresses or message field layouts.'],
    functions=results,
)
OUTPUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
lines = ['# TatoTalk Windows 静态反汇编校验', '', f'样本 SHA-256：`{source["sample_sha256"]}`。首选 ImageBase：`{image_base:#x}`。', '', '使用 Capstone 完整线性解码候选 .pdata 范围，并确认字符串引用是否落在真实解码指令起点。未读取进程、未注入、未执行客户端。', '', '| 候选范围 RVA | 指令数 | 完整连续解码 | 已确认引用 |', '| --- | ---: | --- | ---: |']
for item in results:
    bound = item['boundary']
    validated = sum(value['rip_target_matches_string'] for value in item['reference_validation'])
    lines.append(f'| `[{bound["begin_rva"]}, {bound["end_rva_exclusive"]})` | {item["instruction_count"]} | {item["complete_range_decode"]} | {validated}/{len(item["reference_validation"])} |')
lines += ['', '“完整连续解码”不证明执行可达性或函数名称；本报告区分了真实指令引用与此前的纯字节模式候选。所有候选仍未确认适合 Hook。', '', '## 参数与比较常量', '', '参数流仅按 Microsoft x64 ABI 将入口 RCX/RDX 标记为 arg0/arg1，记录前 80 条指令中可见的寄存器拷贝、解引用。没有把它们直接认定为 this 或 update。比较立即数只做统计，不推断对应的新消息类别。', '']
for item in results:
    begin = item['boundary']['begin_rva']
    lines += [f'### 候选范围 {begin}', '', '前几条指令：', '', '```asm']
    lines += [f'{entry["rva"]}: {entry["mnemonic"]} {entry["operands"]}' for entry in item['prologue_and_first_instructions'][:15]]
    lines += ['```', '', '入口参数线性追踪（有限、未经路径验证）：', '']
    if item['approximate_argument_flow_first_80_instructions']:
        lines += [f'- `{entry["rva"]}: {entry["mnemonic"]} {entry["operands"]}` → `{entry["approximate_origin"]}`' for entry in item['approximate_argument_flow_first_80_instructions'][:12]]
    else:
        lines += ['- 未取得可直接追踪的寄存器传递。']
    lines += ['', '较大的 32 位比较常量（语义尚未确认）：`' + json.dumps(item['large_u32_comparison_candidates']) + '`。', '', f'直接调用目标 {len(item["direct_calls"])} 个；各目标 RVA 和调用位置见 JSON。', '']
lines += ['## 仍需验证', '', '需要进一步确认控制流、函数真实语义、参数对象布局，以及运行中的版本/代码是否与样本一致。禁止仅凭比较常量或字符串名称确定消息类别。动态读取正文之前还应以带唯一标记的测试消息验证，避免无意采集现有会话内容。', '']
MARKDOWN.write_text('\n'.join(lines), encoding='utf-8')
print(json.dumps(dict(json_report=str(OUTPUT), markdown_report=str(MARKDOWN), functions=[dict(begin=item['boundary']['begin_rva'], end=item['boundary']['end_rva_exclusive'], complete_decode=item['complete_range_decode'], instructions=item['instruction_count'], validated_references=sum(value['rip_target_matches_string'] for value in item['reference_validation']), comparison_constant_counts=item['comparison_constant_counts'], large_u32_candidates=item['large_u32_comparison_candidates'], direct_call_targets=len(item['direct_calls'])) for item in results]), indent=2, ensure_ascii=False))
