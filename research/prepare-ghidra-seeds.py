from pathlib import Path
import json
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / 'tools' / 'static-python'))
import capstone
import pefile
sample = root / 'samples' / 'windows-extracted' / 'Tatotalk.exe'
pe = pefile.PE(str(sample), fast_load=True)
report = json.loads((root / 'windows-disassembly-validation.json').read_text(encoding='utf-8'))
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
lines = []
for function in report['functions']:
    begin = int(function['boundary']['begin_rva'], 16)
    end = int(function['boundary']['end_rva_exclusive'], 16)
    instructions = list(decoder.disasm(pe.get_data(begin, end - begin), begin))
    assert instructions[-1].address + instructions[-1].size == end
    lines.extend(f'{begin:x},{instruction.address:x}' for instruction in instructions)
target = root / 'windows-instruction-starts.csv'
target.write_text('\n'.join(lines) + '\n', encoding='ascii')
print(f'Wrote {len(lines)} validated instruction starts: {target}')
