"""Extract selected class method signatures and direct invoke references from DEX."""
import json
from pathlib import Path
import struct
import sys
import zipfile
from inspect_apk import u16, u32, varint


def tables(data):
    count, off = u32(data, 56), u32(data, 60)
    strings = []
    for i in range(count):
        addr = u32(data, off + 4 * i)
        _, addr = varint(data, addr)
        strings.append(data[addr:data.index(0, addr)].decode('utf-8', 'replace'))
    count, off = u32(data, 64), u32(data, 68)
    types = [strings[u32(data, off + 4 * i)] for i in range(count)]
    count, off = u32(data, 72), u32(data, 76)
    protos = []
    for i in range(count):
        at = off + 12 * i
        rtype, args = types[u32(data, at + 4)], u32(data, at + 8)
        params = [] if args == 0 else [types[u16(data, args + 4 + 2 * j)] for j in range(u32(data, args))]
        protos.append('(' + ''.join(params) + ')' + rtype)
    count, off = u32(data, 88), u32(data, 92)
    methods = []
    for i in range(count):
        at = off + 8 * i
        methods.append((types[u16(data, at)], strings[u32(data, at + 4)], protos[u16(data, at + 2)]))
    return strings, types, methods


def width(ins, p):
    op = ins[p] & 255
    if op == 0:
        payload = ins[p] >> 8
        if payload == 1:
            return 4 + 2 * ins[p + 1]
        if payload == 2:
            return 2 + 4 * ins[p + 1]
        if payload == 3:
            elements = ins[p + 2] | (ins[p + 3] << 16)
            return 4 + (elements * ins[p + 1] + 1) // 2
        return 1
    if op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c, 0xfc, 0xfd):
        return 3
    if op in (0xfa, 0xfb):
        return 4
    if op == 0x18:
        return 5
    if op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29, 0xfe, 0xff):
        return 2
    if 0x2d <= op <= 0x3d or 0x44 <= op <= 0x6d or 0x90 <= op <= 0xaf or 0xd0 <= op <= 0xe2:
        return 2
    if 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
        return 3
    return 1


def calls(data, code, methods, strings):
    n = u32(data, code + 12)
    ins = struct.unpack_from('<' + 'H' * n, data, code + 16)
    output = {'invokes': [], 'string_literals': []}
    p = 0
    while p < n:
        op = ins[p] & 255
        if 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:
            idx = ins[p + 1]
            if idx < len(methods):
                cls, name, proto = methods[idx]
                output['invokes'].append({'instruction_offset': p, 'class': cls, 'method': name, 'signature': proto})
        elif op in (0x1a, 0x1b):
            idx = ins[p + 1] | ((ins[p + 2] << 16) if op == 0x1b else 0)
            if idx < len(strings):
                value = strings[idx]
                if len(value) < 160 and not value.startswith(('http:', 'https:')):
                    output['string_literals'].append(value)
        p += width(ins, p)
    return output


def inspect(data, target):
    strings, types, methods = tables(data)
    result = []
    count, off = u32(data, 96), u32(data, 100)
    for i in range(count):
        at = off + i * 32
        cls = types[u32(data, at)]
        if cls != target:
            continue
        addr = u32(data, at + 24)
        sf, addr = varint(data, addr)
        inf, addr = varint(data, addr)
        dm, addr = varint(data, addr)
        vm, addr = varint(data, addr)
        for _ in range(sf + inf):
            _, addr = varint(data, addr)
            _, addr = varint(data, addr)
        for length in (dm, vm):
            idx = 0
            for _ in range(length):
                delta, addr = varint(data, addr)
                idx += delta
                flags, addr = varint(data, addr)
                code, addr = varint(data, addr)
                owner, name, proto = methods[idx]
                item = {'class': owner, 'method': name, 'signature': proto, 'access_flags': hex(flags), 'native': bool(flags & 0x100), 'code_offset': code}
                if code and name in ('onUnparsedMessageReceived', 'onUpdate', 'onConnectionStateChanged', 'run'):
                    item.update(calls(data, code, methods, strings))
                result.append(item)
    return result


def main():
    apk, target = Path(sys.argv[1]), sys.argv[2]
    result = []
    with zipfile.ZipFile(apk) as z:
        for name in z.namelist():
            if name.startswith('classes') and name.endswith('.dex'):
                selected = inspect(z.read(name), target)
                if selected:
                    result.append({'dex': name, 'class': target, 'methods': selected})
    output = Path(sys.argv[3]) if len(sys.argv) > 3 else apk.parent.parent / 'connections-manager-signatures.json'
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    for dex in result:
        print(dex['dex'], dex['class'], len(dex['methods']), 'methods')
        for m in dex['methods']:
            if 'invokes' in m:
                print(json.dumps(m, ensure_ascii=False))
    print(output)


if __name__ == '__main__':
    main()
