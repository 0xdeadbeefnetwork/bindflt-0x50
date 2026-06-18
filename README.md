# bindflt 0x50

`bindflt.sys` bugchecks with `0x50` in `BfValidateShortName` (`bindflt.sys+0x23783`). Seen on Win11 24H2 `26100.8655`.

Needs admin - `\\BindFltPort` won't open otherwise.

## run

elevated cmd:

```
struct_fuzz.exe 2000 8 C:\ batch4
```

wait ~minute. box dies.

## build

```
make
```

needs `fltuser` / fltLib. `bindfltapi.dll` is on the system already.

## what it does

seeds a merged bind map through `bindfltapi`, then spams port type 4 batch messages (`BfStoreBatchedVirtualizationMapping`) with broken lengths/offsets. single-thread one-shot usually survives; this doesn't.

## verified (2026-06-18, win-exp)

`struct_fuzz.exe 2000 8 C:\ batch4` → bugcheck `0x50`, fault `bindflt.sys+0x23783`.

minidump from that run: `061826-31687-01.dmp`

| artifact | sha256 |
|----------|--------|
| `struct_fuzz.c` (repo = VM copy) | `a8aa5b568b5d95f32fe2605aa979a4ab186498080174574c08f3b90532285a7a` |
| `struct_fuzz.exe` (built on VM) | `6bfbbc67a1f09655287ab3f1ec1ed3144dddb099ff914b2865c16937f57334b9` |
