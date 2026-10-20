"""Read a named MSI stream without installing or invoking any MSI action."""
import ctypes
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MSI = ROOT / 'samples' / 'TatoTalk_3.01.200343.msi'
CAB = ROOT / 'samples' / 'TatoTalk_3.01.200343.cab'
msi = ctypes.WinDLL('msi')
Handle = ctypes.c_uint
msi.MsiOpenDatabaseW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(Handle)]
msi.MsiDatabaseOpenViewW.argtypes = [Handle, wintypes.LPCWSTR, ctypes.POINTER(Handle)]
msi.MsiViewExecute.argtypes = [Handle, Handle]
msi.MsiViewFetch.argtypes = [Handle, ctypes.POINTER(Handle)]
msi.MsiRecordReadStream.argtypes = [Handle, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
msi.MsiCloseHandle.argtypes = [Handle]

def check(status):
    if status:
        raise OSError(f'MSI read operation failed: {status}')

handles = []
try:
    database = Handle()
    check(msi.MsiOpenDatabaseW(str(MSI), None, ctypes.byref(database)))
    handles.append(database)
    view = Handle()
    query = "SELECT `Data` FROM `_Streams` WHERE `Name` = '_2A14F0F40B58BC35D6B0E8B806233D0B'"
    check(msi.MsiDatabaseOpenViewW(database, query, ctypes.byref(view)))
    handles.append(view)
    check(msi.MsiViewExecute(view, Handle(0)))
    record = Handle()
    check(msi.MsiViewFetch(view, ctypes.byref(record)))
    handles.append(record)
    buffer = ctypes.create_string_buffer(1024 * 1024)
    with CAB.open('wb') as target:
        while True:
            count = wintypes.DWORD(len(buffer))
            check(msi.MsiRecordReadStream(record, 1, buffer, ctypes.byref(count)))
            if count.value == 0:
                break
            target.write(buffer.raw[:count.value])
    print(f'Exported cabinet: {CAB} ({CAB.stat().st_size} bytes)')
finally:
    for handle in reversed(handles):
        msi.MsiCloseHandle(handle)
