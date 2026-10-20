# TatoTalk Windows 静态反汇编校验

样本 SHA-256：`76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58`。首选 ImageBase：`0x140000000`。

使用 Capstone 完整线性解码候选 .pdata 范围，并确认字符串引用是否落在真实解码指令起点。未读取进程、未注入、未执行客户端。

| 候选范围 RVA | 指令数 | 完整连续解码 | 已确认引用 |
| --- | ---: | --- | ---: |
| `[0xdb95a0, 0xdb9f73)` | 645 | True | 1/1 |
| `[0xdb9f80, 0xdba5ca)` | 380 | True | 1/1 |
| `[0xe52050, 0xe52c40)` | 741 | True | 2/2 |
| `[0xe52c40, 0xe564f8)` | 3356 | True | 2/2 |

“完整连续解码”不证明执行可达性或函数名称；本报告区分了真实指令引用与此前的纯字节模式候选。所有候选仍未确认适合 Hook。

## 参数与比较常量

参数流仅按 Microsoft x64 ABI 将入口 RCX/RDX 标记为 arg0/arg1，记录前 80 条指令中可见的寄存器拷贝、解引用。没有把它们直接认定为 this 或 update。比较立即数只做统计，不推断对应的新消息类别。

### 候选范围 0xdb95a0

前几条指令：

```asm
0xdb95a0: mov qword ptr [rsp + 8], rcx
0xdb95a5: push rbp
0xdb95a6: push rbx
0xdb95a7: push rsi
0xdb95a8: push rdi
0xdb95a9: push r12
0xdb95ab: push r13
0xdb95ad: push r14
0xdb95af: push r15
0xdb95b1: lea rbp, [rsp - 0xb8]
0xdb95b9: sub rsp, 0x1f8
0xdb95c0: xor edi, edi
0xdb95c2: mov eax, dword ptr [rdx + 8]
0xdb95c5: test eax, eax
0xdb95c7: je 0xdb9f59
```

入口参数线性追踪（有限、未经路径验证）：

- `0xdb95c2: mov eax, dword ptr [rdx + 8]` → `memory32[arg1/RDX + 0x8]`
- `0xdb95ee: mov rcx, rdx` → `arg1/RDX`

较大的 32 位比较常量（语义尚未确认）：`{"0x11f1331c": 1, "0x16812688": 1, "0x914fbf11": 1}`。

直接调用目标 14 个；各目标 RVA 和调用位置见 JSON。

### 候选范围 0xdb9f80

前几条指令：

```asm
0xdb9f80: mov qword ptr [rsp + 8], rbx
0xdb9f85: mov qword ptr [rsp + 0x18], rsi
0xdb9f8a: push rbp
0xdb9f8b: push rdi
0xdb9f8c: push r12
0xdb9f8e: push r14
0xdb9f90: push r15
0xdb9f92: mov rbp, rsp
0xdb9f95: sub rsp, 0x70
0xdb9f99: mov r15, rcx
0xdb9f9c: xor esi, esi
0xdb9f9e: mov eax, dword ptr [rdx + 8]
0xdb9fa1: test eax, eax
0xdb9fa3: je 0xdba57c
0xdb9fa9: cmp eax, 0x7f891213
```

入口参数线性追踪（有限、未经路径验证）：

- `0xdb9f99: mov r15, rcx` → `arg0/RCX`
- `0xdb9f9e: mov eax, dword ptr [rdx + 8]` → `memory32[arg1/RDX + 0x8]`
- `0xdb9fec: mov rcx, rdx` → `arg1/RDX`

较大的 32 位比较常量（语义尚未确认）：`{"0x7f891213": 1, "0x2f2f21bf": 1, "0x19360dc0": 1, "0x1b3f4df7": 1, "0x1f2b0afd": 1, "0x81ff9c4a": 2, "0x40771900": 1, "0x62ba04d9": 1, "0x68c13933": 1, "0xe40370a3": 1, "0x9961fd5c": 1, "0xa20db0e5": 1, "0xc37521c9": 1, "0xeba7d672": 1, "0xfb81ea40": 1}`。

直接调用目标 42 个；各目标 RVA 和调用位置见 JSON。

### 候选范围 0xe52050

前几条指令：

```asm
0xe52050: mov qword ptr [rsp + 8], rbx
0xe52055: mov qword ptr [rsp + 0x18], r8
0xe5205a: push rbp
0xe5205b: push rsi
0xe5205c: push rdi
0xe5205d: push r12
0xe5205f: push r13
0xe52061: push r14
0xe52063: push r15
0xe52065: lea rbp, [rsp - 0x27]
0xe5206a: sub rsp, 0xf0
0xe52071: mov rbx, r8
0xe52074: mov r13, rdx
0xe52077: mov r14, rcx
0xe5207a: xor esi, esi
```

入口参数线性追踪（有限、未经路径验证）：

- `0xe52074: mov r13, rdx` → `arg1/RDX`
- `0xe52077: mov r14, rcx` → `arg0/RCX`
- `0xe5207f: mov eax, dword ptr [rdx + 8]` → `memory32[arg1/RDX + 0x8]`
- `0xe520bc: mov rcx, rdx` → `arg1/RDX`
- `0xe520d2: mov ecx, dword ptr [r14 + 0x348]` → `memory32[arg0/RCX + 0x348]`
- `0xe52110: mov rcx, r14` → `arg0/RCX`
- `0xe52136: mov rcx, r13` → `arg1/RDX`

较大的 32 位比较常量（语义尚未确认）：`{"0x74ae4240": 1, "0x11f1331c": 1, "0x16812688": 1, "0x725b04c3": 1, "0x3ffffffd": 1, "0x78d4dec1": 1, "0x914fbf11": 1, "0xe317af7e": 1}`。

直接调用目标 39 个；各目标 RVA 和调用位置见 JSON。

### 候选范围 0xe52c40

前几条指令：

```asm
0xe52c40: mov qword ptr [rsp + 8], rbx
0xe52c45: push rbp
0xe52c46: push rsi
0xe52c47: push rdi
0xe52c48: push r12
0xe52c4a: push r13
0xe52c4c: push r14
0xe52c4e: push r15
0xe52c50: lea rbp, [rsp - 0x150]
0xe52c58: sub rsp, 0x250
0xe52c5f: mov rsi, rdx
0xe52c62: mov r14, rcx
0xe52c65: xor r12d, r12d
0xe52c68: mov dword ptr [rbp + 0x198], r12d
0xe52c6f: mov eax, dword ptr [rdx + 8]
```

入口参数线性追踪（有限、未经路径验证）：

- `0xe52c5f: mov rsi, rdx` → `arg1/RDX`
- `0xe52c62: mov r14, rcx` → `arg0/RCX`
- `0xe52c6f: mov eax, dword ptr [rdx + 8]` → `memory32[arg1/RDX + 0x8]`
- `0xe52cea: mov rcx, rdx` → `arg1/RDX`

较大的 32 位比较常量（语义尚未确认）：`{"0x70db6837": 1, "0x2f2f21bf": 1, "0x1710f156": 1, "0xf84e35b": 1, "0x63d483b": 1, "0x7267562": 1, "0x7761198": 1, "0xbb2d201": 1, "0x10c2404b": 1, "0x12b9417b": 1, "0x12bcbd9a": 1, "0x1f2b0afd": 1, "0x19360dc0": 1, "0x1b3f4df7": 1, "0x1bfbd823": 1, "0x77ebc742": 1, "0x8c703f": 3, "0x7bf09fc": 1, "0x9d05049": 2, "0xe26f42f1": 1, "0xedb93949": 3, "0x2575bbb9": 1, "0x25d6c9c7": 1, "0x28629303": 1, "0x5c486927": 1, "0x4e90bfd6": 1, "0x38fe25b7": 1, "0x40771900": 1, "0x4214f37f": 1, "0x43ae3dec": 1, "0x4f4ded14": 1, "0x56022f4d": 1, "0x571d2742": 1, "0x1242c047": 1, "0x8b7edcab": 1, "0xad1edea1": 1, "0xaf91f212": 1, "0x6e5f8c22": 1, "0x62ba04d9": 1, "0x688a30aa": 1, "0x68c13933": 1, "0x9de7a269": 1, "0x1bf84d13": 1, "0x6e6fe51c": 1, "0x6e947941": 1, "0x7084a7be": 1, "0xb9c12aa8": 2, "0x9a422c20": 1, "0x9375341e": 1, "0x7f891213": 1, "0x80ece81a": 1, "0x89893b45": 1, "0x8e5e9873": 1, "0x95313b0c": 1, "0x964ca1c3": 1, "0x98a12b4b": 1, "0x9961fd5c": 1, "0xa7332b73": 1, "0x9a65ea1f": 1, "0x9d2e67c5": 1, "0xa20db0e5": 1, "0xa229dd06": 1, "0xab0f6b1e": 1, "0xb4a2e88d": 1, "0xb6901959": 1, "0xb6d45656": 1, "0x83761ce4": 1, "0xeba7d672": 1, "0xcdcbfd82": 1, "0xbec268ef": 1, "0xc37521c9": 1, "0xc59b38e7": 1, "0xcb1ccd80": 1, "0xe40370a3": 1, "0xe511996d": 1, "0xea4b0e5c": 1, "0xeb0467fb": 1, "0x4c423b18": 1, "0x6213728e": 1, "0xf5df3f00": 1, "0xebe46819": 1, "0xed85eab5": 1, "0xee2bb969": 1, "0xee3b272a": 1, "0xfd8e711f": 1, "0xfa0f3ca2": 1, "0xfb81ea40": 1, "0xfeca9f02": 1, "0xe56dbf05": 2}`。

直接调用目标 311 个；各目标 RVA 和调用位置见 JSON。

## 仍需验证

需要进一步确认控制流、函数真实语义、参数对象布局，以及运行中的版本/代码是否与样本一致。禁止仅凭比较常量或字符串名称确定消息类别。动态读取正文之前还应以带唯一标记的测试消息验证，避免无意采集现有会话内容。
