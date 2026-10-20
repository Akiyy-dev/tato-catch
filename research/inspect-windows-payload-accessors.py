"""Static validation of small generated payload accessor candidates."""
from pathlib import Path
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools' / 'static-python'))
import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

data = (ROOT / 'samples' / 'windows-extracted' / 'Tatotalk.exe').read_bytes()
pe = pefile.PE(data=data, fast_load=True)
exception = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
runtime_functions = list(struct.iter_unpack('<III', pe.get_data(exception.VirtualAddress, exception.Size)))
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
decoder.detail = True
targets = [0x3dd6b0,0x3dd700,0x3dd750,0x3dd7a0,0x3dd7f0,0x3dd840,0x3eb0d0,0x3eb9e0,0x3df3d0,0x3e09a0,0x3e0690,0x3e06d0,0x3e09f0,0x3e0cc0,0x387f80]
results = []
for target in targets:
    boundary = next((item for item in runtime_functions if item[0] == target), None)
    if boundary is None:
        results.append(dict(begin_rva=hex(target), error='No exact .pdata entry'))
        continue
    begin, end, unwind = boundary
    instructions = list(decoder.disasm(pe.get_data(begin, end-begin), begin))
    comparisons = []
    strings = []
    for instruction in instructions:
        if instruction.mnemonic == 'cmp':
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM:
                    comparisons.append(dict(rva=hex(instruction.address), instruction=f'{instruction.mnemonic} {instruction.op_str}', value_u32=hex(operand.imm & 0xffffffff)))
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                rva = instruction.address + instruction.size + operand.mem.disp
                try:
                    offset = pe.get_offset_from_rva(rva)
                    end_string = data.index(b'\0', offset, offset+400)
                    value = data[offset:end_string].decode('ascii')
                except (ValueError, UnicodeDecodeError, pefile.PEFormatError):
                    continue
                if 'mtpc_' in value or 'Unexpected:' in value or 'data != nullptr' in value:
                    strings.append(dict(reference_rva=hex(instruction.address), string_rva=hex(rva), text=value))
    results.append(dict(begin_rva=hex(begin), end_rva_exclusive=hex(end), complete_decode=bool(instructions) and instructions[-1].address+instructions[-1].size==end, comparisons=comparisons, diagnostic_strings=strings, instructions=[dict(rva=hex(i.address), bytes=bytes(i.bytes).hex(' '), instruction=f'{i.mnemonic} {i.op_str}') for i in instructions]))
out = ROOT / 'windows-payload-accessor-evidence.json'
out.write_text(json.dumps(dict(method='Static Capstone decode of small generated accessor candidates; no process or profile reads.', functions=results),indent=2),encoding='utf-8')
print(json.dumps(dict(report=str(out), functions=[{k:v for k,v in item.items() if k!='instructions'} for item in results]),indent=2))
