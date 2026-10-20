"""Read-only APK ZIP, binary manifest, and DEX structural inspection (stdlib only)."""
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zipfile


def u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def varint(data, off):
    value = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        value |= (b & 127) << shift
        if b < 128:
            return value, off
        shift += 7
        if shift > 35:
            raise ValueError('Invalid variable integer')


def string_pool(data, pos):
    head = u16(data, pos + 2)
    count = u32(data, pos + 8)
    flags = u32(data, pos + 16)
    start = u32(data, pos + 20)
    strings = []
    for i in range(count):
        off = pos + start + u32(data, pos + head + 4 * i)
        if flags & 256:
            n = data[off]
            off += 2 if n & 128 else 1  # UTF-16 character count, not bytes.
            n = data[off]
            off += 1
            if n & 128:
                n = ((n & 127) << 8) | data[off]
                off += 1
            strings.append(data[off:off + n].decode('utf-8', 'replace'))
        else:
            n = u16(data, off)
            off += 2
            if n & 32768:
                n = ((n & 32767) << 16) | u16(data, off)
                off += 2
            strings.append(data[off:off + n * 2].decode('utf-16le', 'replace'))
    return strings


def manifest(data):
    strings = []
    output = {'manifest': {}, 'uses-sdk': {}, 'application': {},
              'activities': [], 'services': [], 'receivers': [], 'permissions': []}
    pos = u16(data, 2)
    size = u32(data, 4)
    stack = []
    launcher = set()
    current_component = None
    def s(i):
        return None if i == 0xffffffff else strings[i]
    while pos + 8 <= min(size, len(data)):
        typ, head, length = struct.unpack_from('<HHI', data, pos)
        if length < 8:
            break
        if typ == 1:
            strings = string_pool(data, pos)
        elif typ == 0x102:
            base = pos + head
            name = s(u32(data, base + 4))
            astart, asize, acount = struct.unpack_from('<HHH', data, base + 8)
            attrs = {}
            for i in range(acount):
                a = base + astart + i * asize
                key = s(u32(data, a + 4))
                raw = u32(data, a + 8)
                value_type, value_data = data[a + 15], u32(data, a + 16)
                if raw != 0xffffffff:
                    value = s(raw)
                elif value_type == 3:
                    value = s(value_data)
                elif value_type == 0x12:
                    value = bool(value_data)
                elif value_type in (0x10, 0x11):
                    value = value_data
                else:
                    value = f'@{value_data:08x}'
                attrs[key] = value
            if name in ('manifest', 'uses-sdk', 'application'):
                output[name] = attrs
            elif name in ('activity', 'activity-alias', 'service', 'receiver'):
                key = {'activity': 'activities', 'activity-alias': 'activities',
                       'service': 'services', 'receiver': 'receivers'}[name]
                output[key].append(attrs)
                current_component = attrs.get('name')
            elif name == 'uses-permission':
                output['permissions'].append(attrs.get('name'))
            elif name == 'category' and attrs.get('name') == 'android.intent.category.LAUNCHER':
                launcher.add(current_component)
            stack.append((name, current_component))
        elif typ == 0x103 and stack:
            name, component = stack.pop()
            if name in ('activity', 'activity-alias', 'service', 'receiver'):
                current_component = None
        pos += length
    output['launcher_components'] = sorted(launcher)
    output['activity_count'] = len(output['activities'])
    output['activities'] = [a for a in output['activities'] if a.get('name') in launcher]
    return output


FEATURE = re.compile(r'MessagesController|MessagesStorage|TLRPC|ConnectionsManager|NotificationCenter|NotificationsController|FileLoader|SendMessagesHelper|UpdateHandler|StubApp|jiagu|secneo|bangcle|tencent\.Stub|shell\.SuperApplication', re.I)
METHOD = re.compile(r'^(processUpdates|processUpdateArray|putMessages|didReceivedNotification|onUpdate|applyNewMessage|updateMessage|onUnparsedMessageReceived|onConnectionStateChanged)$')


def dex_report(data):
    count, off = u32(data, 56), u32(data, 60)
    strings = []
    for i in range(count):
        addr = u32(data, off + 4 * i)
        _, addr = varint(data, addr)
        end = data.index(0, addr)
        strings.append(data[addr:end].decode('utf-8', 'replace'))
    tcount, toff = u32(data, 64), u32(data, 68)
    types = [strings[u32(data, toff + 4 * i)] for i in range(tcount)]
    ccount, coff = u32(data, 96), u32(data, 100)
    classes = [types[u32(data, coff + 32 * i)] for i in range(ccount)]
    defined = set(classes)
    matches = [c for c in classes if FEATURE.search(c)]
    mcount, moff = u32(data, 88), u32(data, 92)
    methods = []
    for i in range(mcount):
        at = moff + 8 * i
        cl = types[u16(data, at)]
        name = strings[u32(data, at + 4)]
        if METHOD.fullmatch(name):
            methods.append({'class': cl, 'method': name, 'class_defined_in_dex': cl in defined})
    prefixes = collections.Counter('/'.join(c.lstrip('L').split('/')[:3]) for c in classes)
    return {
        'magic': data[:8].decode('ascii', 'backslashreplace'),
        'size': len(data), 'string_count': count, 'class_count': ccount,
        'feature_classes': matches[:100], 'feature_class_count': len(matches),
        'candidate_methods': methods[:80], 'candidate_method_count': len(methods),
        'package_prefix_counts': prefixes.most_common(20),
    }


def main():
    source = Path(sys.argv[1])
    target = Path(sys.argv[2])
    result = {'file': str(source), 'sha256': hashlib.file_digest(source.open('rb'), 'sha256').hexdigest(),
              'size': source.stat().st_size, 'scope': 'Static ZIP, AndroidManifest.xml, and DEX inspection only. APK was not installed or executed.'}
    with zipfile.ZipFile(source) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        result['zip_entry_count'] = len(names)
        result['dex_files'] = []
        for name in names:
            if re.fullmatch(r'classes\d*\.dex', name):
                result['dex_files'].append({'name': name, **dex_report(z.read(name))})
        result['native_libraries'] = [{'name': i.filename, 'size': i.file_size} for i in infos if i.filename.startswith('lib/') and i.filename.endswith('.so')]
        result['asset_names'] = [n for n in names if n.startswith('assets/')][:200]
        result['top_level_counts'] = collections.Counter(n.split('/')[0] for n in names)
        result['protection_name_hints'] = [n for n in names if re.search(r'jiagu|secneo|bangcle|dexhelper|ijiami|libshell|protect', n, re.I)]
        result['manifest'] = manifest(z.read('AndroidManifest.xml'))
    target.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('file', 'sha256', 'size', 'zip_entry_count')}, ensure_ascii=False))
    print('Manifest:', json.dumps(result['manifest'], ensure_ascii=False))
    print('DEX:', json.dumps(result['dex_files'], ensure_ascii=False))
    print('Native:', json.dumps(result['native_libraries'], ensure_ascii=False))
    print('Protection filename hints:', json.dumps(result['protection_name_hints'], ensure_ascii=False))
    print('Report:', target)


if __name__ == '__main__':
    main()
