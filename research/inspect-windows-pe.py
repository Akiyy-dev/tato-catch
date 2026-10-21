"""Static PE header, import, and selected diagnostic string inspection only."""
from pathlib import Path
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parent
report_path = ROOT / 'windows-triage.json'
report = json.loads(report_path.read_text(encoding='utf-8-sig'))
extract_root = ROOT / 'samples' / 'windows-extracted'
for item in report['files']:
    source = extract_root / item['File']
    name = item['FileName'].split('|')[-1]
    target = extract_root / name
    if source.exists() and not target.exists():
        source.rename(target)

path = extract_root / 'Tatotalk.exe'
data = path.read_bytes()
def u16(offset): return struct.unpack_from('<H', data, offset)[0]
def u32(offset): return struct.unpack_from('<I', data, offset)[0]
def cstr(offset): return data[offset:data.index(b'\0', offset)].decode('ascii', 'replace')
pe = u32(0x3c)
assert data[:2] == b'MZ' and data[pe:pe + 4] == b'PE\0\0'
coff = pe + 4
machine = u16(coff)
section_count = u16(coff + 2)
optional = coff + 20
optional_size = u16(coff + 16)
magic = u16(optional)
directory_offset = optional + (112 if magic == 0x20b else 96)
directories = [struct.unpack_from('<II', data, directory_offset + i * 8) for i in range(16)]
sections = []
for index in range(section_count):
    offset = optional + optional_size + index * 40
    name = data[offset:offset + 8].rstrip(b'\0').decode('ascii', 'replace')
    vsize, rva, rawsize, rawoffset = struct.unpack_from('<IIII', data, offset + 8)
    sections.append(dict(name=name, virtualSize=vsize, rva=rva, rawSize=rawsize, rawOffset=rawoffset))
def rva_offset(rva):
    for section in sections:
        start = section['rva']
        if start <= rva < start + max(section['virtualSize'], section['rawSize']):
            return section['rawOffset'] + rva - start
    if rva < sections[0]['rawOffset']:
        return rva
    raise ValueError(f'Unmapped RVA: {rva:x}')
imports = []
if directories[1][0]:
    offset = rva_offset(directories[1][0])
    while any(data[offset:offset + 20]):
        original, timestamp, forwarder, name_rva, thunk = struct.unpack_from('<IIIII', data, offset)
        dll = cstr(rva_offset(name_rva))
        symbols = []
        current = rva_offset(original or thunk)
        width = 8 if magic == 0x20b else 4
        fmt = '<Q' if width == 8 else '<I'
        high = 1 << (width * 8 - 1)
        while True:
            value = struct.unpack_from(fmt, data, current)[0]
            if not value: break
            if value & high:
                symbols.append(f'ordinal:{value & 0xffff}')
            else:
                symbols.append(cstr(rva_offset(value) + 2))
            current += width
        imports.append(dict(dll=dll, symbols=symbols))
        offset += 20

markers = {
    'QtCore': [b'QCoreApplication', b'QApplication', b'QWidget', b'QObject', b'Qt5Core', b'Qt6Core', b'qwindows', b'qt_version_tag'],
    'Electron': [b'app.asar', b'chrome_elf.dll', b'electron.exe', b'Electron Framework'],
    'DotNet': [b'mscoree.dll', b'_CorExeMain', b'BSJB'],
    'Protocol': [b'MTProto', b'mtproto', b'updates.getDifference', b'updateNewMessage', b'messages.getHistory', b'auth.exportLoginToken', b'auth.importLoginToken'],
    'Storage': [b'SQLite', b'sqlite3_', b'tdata', b'key_datas', b'map0'],
    'Protection': [b'VMProtect', b'.vmp0', b'.vmp1'],
}
marker_results = {}
for group, values in markers.items():
    found = []
    for value in values:
        ascii_count = data.count(value)
        utf16_count = data.count(value.decode('ascii').encode('utf-16-le'))
        if ascii_count or utf16_count:
            found.append(dict(marker=value.decode('ascii'), asciiCount=ascii_count, utf16leCount=utf16_count))
    marker_results[group] = found

candidate_patterns = re.compile(rb'(?:[A-Za-z_][A-Za-z_0-9:<>~.*&()-]{0,80})?(?:updateNewMessage|updateNewChannelMessage|updateShortMessage|updateShortChatMessage|feedUpdate|feedMessage|messageReceived|newMessage|messagesReceived|applyUpdate|processUpdate|HistoryItem|MainWidget|MTP[A-Za-z_0-9]+)[A-Za-z_0-9:<>~.*&()-]{0,100}')
candidates = []
for match in candidate_patterns.finditer(data):
    value = match.group(0).decode('ascii')
    if value not in candidates:
        candidates.append(value)
    if len(candidates) >= 100:
        break
pe_report = dict(
    filePath=str(path), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
    machine=hex(machine), architecture={0x8664: 'x86_64', 0x14c: 'x86', 0xaa64: 'ARM64'}.get(machine, 'unknown'),
    optionalHeaderMagic=hex(magic), subsystem=u16(optional + 68), sections=sections,
    clrRuntimeDirectory=dict(rva=directories[14][0], size=directories[14][1]),
    importLibraries=imports, selectedStaticMarkers=marker_results,
    candidateStrings=candidates,
    caveat='Strings indicate code or library presence only; they do not prove reachable receive handlers, protocol compatibility, login success, or message extraction.'
)
report['staticExecutableInspection'] = pe_report
report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
print(json.dumps({key: value for key, value in pe_report.items() if key != 'importLibraries'}, indent=2, ensure_ascii=False))
print('Imported libraries:', ', '.join(item['dll'] for item in imports))
