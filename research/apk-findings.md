# TatoTalk APK static triage

This sample was downloaded from the Android link supplied by the current official download page. It was not installed or executed. No account, session, login, message, key, or credential data was accessed.

- Source URL: `https://downtato.ffvjei.com/android/TatoTalk-3.01.200106.apk`
- File: `samples/tatotalk-official.apk`
- Size: 118,662,823 bytes
- SHA-256: `3769b604e4b7f66c9a44e00e9cab6e60d7723f4b6d2c357c396ae4bf198a54c4`
- Manifest version: **3.03.200105**, versionCode **30032**. The URL filename is not the actual manifest version.
- Manifest package: `w260fk.n922gf.e19tb.df20c`; this differs from the previously observed Google Play package and must be considered when selecting a runtime process.
- Application: `org.tato.messenger.ApplicationLoader`
- Launcher: `org.tato.ui.SplashScreenActivity`
- Minimum API 24; target API 34.

## Static visibility

The ZIP contains 14,758 entries and eight normal DEX files with 65,962 class definitions. There is substantial readable Android bytecode rather than only a small loader DEX. Many application class and method names are obfuscated. No common jiagu/secneo/bangcle/DexHelper/libshell filenames were observed; this does not prove the absence of other protection.

All 26 packaged native libraries are ARM64 (`arm64-v8a`). Notable libraries are `libtmessages.30.so`, `libsqlite3x.so`, and `libemulator_check.so`. The manifest includes `com.snail.antifake.jni.EmulatorCheckService`; the presence of this component alone does not establish whether emulator use is blocked.

## Confirmed bytecode call references

In `classes6.dex`:

1. Public static, non-native `org.tato.tgnet.ConnectionsManager.onUnparsedMessageReceived(long, int)` wraps a native buffer using `org.tato.tgnet.NativeByteBuffer.wrap(long)`.
2. It invokes `org.tato.tgnet.b0.a()` and `b0.b(NativeByteBuffer, int, boolean)`, returning `org.tato.tgnet.c0`.
3. It constructs `org.tato.tgnet.ConnectionsManager$f(int, c0)` and dispatches the runnable through `org.tato.messenger.k6.h(Runnable)`.
4. `ConnectionsManager$f.run()` invokes `org.tato.messenger.bl.s7(int)`, followed by `bl.Zc(org.tato.tgnet.d0$ib0, boolean)`.

This is a concrete candidate boundary between received binary data and application update handling. The names and references do not establish Telegram protocol compatibility. No runtime hooks or message-text extraction have yet been verified.

Suggested single-class analysis targets: `org.tato.tgnet.ConnectionsManager`, `org.tato.tgnet.ConnectionsManager$f`, `org.tato.messenger.bl`, `org.tato.tgnet.b0`, `org.tato.tgnet.c0`, and `org.tato.tgnet.d0$ib0`.

Machine-readable evidence: `apk-triage.json`, `connections-manager-signatures.json`, and `connections-manager-dispatch.json`. The included Python scripts inspect ZIP/AXML/DEX structure using the standard library only; they never execute app code.
