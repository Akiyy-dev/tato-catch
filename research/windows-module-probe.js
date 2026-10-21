// Client path is injected by the runner after PID and file validation.
const TARGET_EXE = /*TARGET_EXE*/null;
if (typeof TARGET_EXE !== 'string' || !TARGET_EXE) {
  throw new Error('Use run_windows_module_probe.py with --target-exe');
}
// Throwaway probe: module metadata and executable instructions only. No hooks.
const module = Process.enumerateModules().find(item => item.name.toLowerCase() === 'tatotalk.exe');
if (!module) {
  throw new Error('Authorized TatoTalk module was not enumerated');
}
const normalizedPath = module.path.split(String.fromCharCode(92)).filter(Boolean)
  .join(String.fromCharCode(92)).toLowerCase();
if (normalizedPath !== TARGET_EXE.toLowerCase()) {
  throw new Error('Unexpected target metadata; refusing code reads: ' + JSON.stringify({
    pid: Process.id, name: module.name, path: module.path
  }));
}
const candidates = [0xdb9f80, 0xdb95a0, 0xe52c40, 0xe52050];
const result = {
  pid: Process.id,
  arch: Process.arch,
  moduleName: module.name,
  modulePath: module.path,
  moduleBase: module.base.toString(),
  moduleSize: module.size,
  candidates: candidates.map(rva => {
    let cursor = module.base.add(rva);
    const firstBytes = Array.from(new Uint8Array(cursor.readByteArray(32)))
      .map(value => value.toString(16).padStart(2, '0')).join('');
    const instructions = [];
    for (let count = 0; count < 8; count++) {
      const instruction = Instruction.parse(cursor);
      instructions.push({address: cursor.toString(), instruction: instruction.toString()});
      cursor = instruction.next;
    }
    return {rva: '0x' + rva.toString(16), firstBytes, instructions};
  })
};
console.log('TATO_MODULE_PROBE:' + JSON.stringify(result));
