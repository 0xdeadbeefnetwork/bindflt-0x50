#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltuser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <process.h>

#define FSCTL_SET_LAYER_ROOT   0x00090394u
#define FSCTL_SHADOW_REMAP     0x000900FCu
#define FSCTL_SHADOW_FWD       0x00090074u
#define FSCTL_GET_MAPPINGS     0x00090C1Fu
#define FSCTL_REJECT_A         0x00098344u
#define FSCTL_REJECT_B         0x000983E8u

#define PORT_BINDFLT           L"\\BindFltPort"

#define MIN_STORE              0x40u
#define MIN_REMOVE             0x28u
#define MIN_BATCH              0x28u
#define MIN_GETMAP             0x28u
#define MIN_TRACK              0x20u
#define MIN_SHADOW_IN          0x18u

#define FLAG_VOLUME            1u
#define FLAG_SILO              2u
#define FLAG_USER              4u

#pragma pack(push, 1)
typedef struct {
    DWORD Type;
    DWORD Size;
} BINDFLT_MSG_HDR;

typedef struct {
    DWORD Total;
    DWORD Pad04;
    DWORD Flags;
    DWORD Pad0C;
    HANDLE Job;
    DWORD Pad14;
    DWORD Pad18;
    WORD  ExcCount;
    WORD  Pad22;
    DWORD Pad24;
    DWORD VirtOff;
    WORD  VirtLen;
    WORD  Pad2E;
    DWORD TgtOff;
    WORD  TgtLen;
} STORE_HDR;

typedef struct {
    DWORD Off;
    WORD  Len;
    WORD  Pad;
} PATH_DESC;

typedef struct {
    DWORD Total;
    DWORD Flags;
    DWORD Pad08;
    DWORD Pad0C;
    HANDLE Job;
    DWORD Pad14;
    DWORD MapArrOff;
    DWORD ExcArrOff;
} BATCH_HDR;

typedef struct {
    DWORD Total;
    DWORD Pad04;
    DWORD Pad08;
    DWORD Pad0C;
    HANDLE Job;
    DWORD Pad14;
    PATH_DESC Path;
} TRACK_HDR;

typedef struct {
    DWORD Pad00;
    DWORD Flags;
    HANDLE VolHandle;
    HANDLE JobHandle;
    PVOID  SiloHandle;
    BYTE   Sid[8];
} GETMAP_BODY;

typedef struct {
    DWORD OutCap;
    DWORD InCap;
    GETMAP_BODY Body;
} GETMAP_FSCTL_IN;
#pragma pack(pop)

typedef HRESULT (WINAPI *BfSetupFilter_t)(
    HANDLE, ULONG, LPCWSTR, LPCWSTR, LPCWSTR *, ULONG);
typedef HRESULT (WINAPI *BfRemoveMapping_t)(HANDLE, LPCWSTR);

static volatile LONG g_run;
static volatile LONG g_last_port_round;
static volatile LONG g_last_port_type;
static HANDLE g_port = INVALID_HANDLE_VALUE;
static HANDLE g_vol = INVALID_HANDLE_VALUE;
static int g_mode = 0;
static char g_root[MAX_PATH];
static BfSetupFilter_t pSetup;
static BfRemoveMapping_t pRemove;

static void to_wide(const char *src, WCHAR *dst, int n) {
    MultiByteToWideChar(CP_ACP, 0, src, -1, dst, n);
}

static int mkdir_p(const char *path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    for (char *p = tmp + 3; *p; p++) {
        if (*p == '\\' || *p == '/') {
            *p = 0;
            CreateDirectoryA(tmp, NULL);
            *p = '\\';
        }
    }
    return CreateDirectoryA(tmp, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static int load_api(void) {
    HMODULE m = LoadLibraryW(L"bindfltapi.dll");
    if (!m) return 0;
    pSetup = (BfSetupFilter_t)GetProcAddress(m, "BfSetupFilter");
    pRemove = (BfRemoveMapping_t)GetProcAddress(m, "BfRemoveMapping");
    return pSetup && pRemove;
}

static void seed_mappings(void) {
    char virt[MAX_PATH], phys[MAX_PATH], base[MAX_PATH];
    WCHAR wv[MAX_PATH], wp[MAX_PATH];
    snprintf(base, sizeof(base), "%s\\bindfuzz", g_root);
    mkdir_p(base);
    snprintf(virt, sizeof(virt), "%s\\vmerged", base);
    snprintf(phys, sizeof(phys), "%s\\phys0", base);
    mkdir_p(phys);
    mkdir_p(virt);
    to_wide(virt, wv, MAX_PATH);
    to_wide(phys, wp, MAX_PATH);
    pRemove(NULL, wv);
    HRESULT hr = pSetup(NULL, 0x02, wv, wp, NULL, 0);
    printf("[*] seed merged map hr=0x%08lx\n", (unsigned long)hr);
}

static void put_unicode(unsigned char *buf, ULONG cap, ULONG off,
                        const WCHAR *s, USHORT byte_len) {
    if (off + byte_len > cap) return;
    memcpy(buf + off, s, byte_len);
}

static ULONG build_store(unsigned char *buf, ULONG cap, ULONG mutate) {
    static const WCHAR virt[] = L"C:\\bindfuzz\\vmerged";
    static const WCHAR tgt[]  = L"C:\\bindfuzz\\phys0";
    USHORT vlen = (USHORT)(sizeof(virt) - sizeof(WCHAR));
    USHORT tlen = (USHORT)(sizeof(tgt) - sizeof(WCHAR));
    ULONG need = 0x40 + vlen + tlen;
    if (need > cap) need = cap;
    memset(buf, 0, need);

    STORE_HDR *h = (STORE_HDR *)buf;
    h->Total = need;
    h->Flags = 0x02;
    h->VirtOff = 0x40;
    h->VirtLen = vlen;
    h->TgtOff = 0x40 + vlen;
    h->TgtLen = tlen;
    put_unicode(buf, need, h->VirtOff, virt, vlen);
    put_unicode(buf, need, h->TgtOff, tgt, tlen);

    switch (mutate % 12) {
    case 0:  h->Total = MIN_STORE - 1; break;
    case 1:  h->Total = need + 0x1000; break;
    case 2:  h->Flags = 0xCFFFFC01; break;
    case 3:  h->VirtOff = 8; h->VirtLen = 0; break;
    case 4:  h->VirtOff = 0x38; h->VirtLen = 0x4000; break;
    case 5:  h->TgtOff = h->VirtOff; h->TgtLen = vlen; break;
    case 6:  h->ExcCount = 0xFFFF; break;
    case 7:  h->VirtLen = (USHORT)(vlen + 2); break;
    case 8:  h->TgtLen = 1; break;
    case 9:  buf[h->VirtOff] = 0xFF; break;
    case 10: h->Job = (HANDLE)(ULONG_PTR)0x4141414141414141ULL; break;
    case 11: h->Total = need; h->Flags = 0x43; break;
    }
    return need;
}

static ULONG build_remove(unsigned char *buf, ULONG cap, ULONG mutate) {
    static const WCHAR path[] = L"C:\\bindfuzz\\vmerged";
    USHORT plen = (USHORT)(sizeof(path) - sizeof(WCHAR));
    ULONG need = MIN_REMOVE + plen;
    if (need > cap) need = cap;
    memset(buf, 0, need);
    *(DWORD *)(buf + 0) = need;
    PATH_DESC *pd = (PATH_DESC *)(buf + 0x20);
    pd->Off = 0x28;
    pd->Len = plen;
    put_unicode(buf, need, pd->Off, path, plen);

    switch (mutate % 8) {
    case 0: *(DWORD *)buf = MIN_REMOVE - 1; break;
    case 1: *(DWORD *)buf = need + 0x800; break;
    case 2: pd->Off = 0x20; break;
    case 3: pd->Len = 0; break;
    case 4: pd->Len = 0xFFFE; break;
    case 5: pd->Off = need - 2; pd->Len = 4; break;
    case 6: buf[pd->Off] = 0; buf[pd->Off + 1] = 0; break;
    case 7: pd->Off = 0x28; pd->Len = plen + 0x100; break;
    }
    return need;
}

static ULONG build_batch(unsigned char *buf, ULONG cap, ULONG mutate) {
    static const WCHAR virt[] = L"\\??\\C:\\bindfuzz\\vbat";
    static const WCHAR tgt[]  = L"\\??\\C:\\bindfuzz\\phys0";
    USHORT vlen = (USHORT)(sizeof(virt) - sizeof(WCHAR));
    USHORT tlen = (USHORT)(sizeof(tgt) - sizeof(WCHAR));
    ULONG map_base = 0x28;
    ULONG exc_base = map_base + 0x20 + vlen + tlen + 0x10;
    ULONG need = exc_base + 0x20;
    if (need > cap) need = cap;
    memset(buf, 0, need);

    BATCH_HDR *h = (BATCH_HDR *)buf;
    h->Total = need;
    h->Flags = 0x02;
    h->MapArrOff = map_base;
    h->ExcArrOff = exc_base;
    *(DWORD *)(buf + map_base) = 1;
    *(DWORD *)(buf + map_base + 0x20) = 1;
    STORE_HDR *ent = (STORE_HDR *)(buf + map_base + 0x24);
    ent->Flags = 0x02;
    ent->VirtOff = map_base + 0x44;
    ent->VirtLen = vlen;
    ent->TgtOff = ent->VirtOff + vlen;
    ent->TgtLen = tlen;
    put_unicode(buf, need, ent->VirtOff, virt, vlen);
    put_unicode(buf, need, ent->TgtOff, tgt, tlen);
    *(DWORD *)(buf + exc_base) = 0;

    switch (mutate % 10) {
    case 0: h->Total = MIN_BATCH - 1; break;
    case 1: h->MapArrOff = need; break;
    case 2: *(DWORD *)(buf + map_base + 0x20) = 0x100; break;
    case 3: ent->VirtLen = 0x8000; break;
    case 4: h->ExcArrOff = h->MapArrOff; break;
    case 5: h->Flags = 0xD0000002; break;
    case 6: ent->TgtOff = 4; ent->TgtLen = 0x100; break;
    case 7: *(DWORD *)(buf + map_base) = need; break;
    case 8: h->MapArrOff = 0x18; break;
    case 9: ent->VirtOff = ent->TgtOff; break;
    }
    return need;
}

static ULONG build_getmap(unsigned char *buf, ULONG cap, ULONG mutate, int fsctl) {
    ULONG need = MIN_GETMAP;
    if (need > cap) need = cap;
    memset(buf, 0, need);
    if (fsctl) {
        GETMAP_FSCTL_IN *in = (GETMAP_FSCTL_IN *)buf;
        in->OutCap = 0x10000;
        in->InCap = need;
        in->Body.Flags = FLAG_VOLUME;
        in->Body.VolHandle = g_vol;
    } else {
        GETMAP_BODY *b = (GETMAP_BODY *)buf;
        b->Flags = FLAG_VOLUME;
        b->VolHandle = g_vol;
    }

    switch (mutate % 10) {
    case 0: buf[4] = 0; buf[8] = 0; break;
    case 1: ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->Flags = 7; break;
    case 2: ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->Flags = FLAG_SILO;
            ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->JobHandle =
                (HANDLE)(ULONG_PTR)0x42424242; break;
    case 3: ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->Flags = FLAG_USER;
            memset(((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->Sid, 0xFF, 8); break;
    case 4: need = MIN_GETMAP - 1; break;
    case 5: if (fsctl) ((GETMAP_FSCTL_IN *)buf)->OutCap = 4; break;
    case 6: ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->VolHandle =
                (HANDLE)(ULONG_PTR)0x1337; break;
    case 7: ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->Flags = FLAG_VOLUME | 0x100; break;
    case 8: ((GETMAP_BODY *)(buf + (fsctl ? 8 : 0)))->SiloHandle =
                (PVOID)(ULONG_PTR)0xCCCCCCCC; break;
    case 9: need = MIN_GETMAP + 0x200; memset(buf, 0x41, need); break;
    }
    return need;
}

static ULONG build_track(unsigned char *buf, ULONG cap, ULONG mutate) {
    static const WCHAR path[] = L"C:\\bindfuzz\\vmerged\\track.txt";
    USHORT plen = (USHORT)(sizeof(path) - sizeof(WCHAR));
    ULONG need = MIN_TRACK + plen;
    if (need > cap) need = cap;
    memset(buf, 0, need);
    TRACK_HDR *h = (TRACK_HDR *)buf;
    h->Total = need;
    h->Path.Off = 0x20;
    h->Path.Len = plen;
    put_unicode(buf, need, h->Path.Off, path, plen);

    switch (mutate % 7) {
    case 0: h->Total = MIN_TRACK - 1; break;
    case 1: h->Job = (HANDLE)(ULONG_PTR)0x7777; break;
    case 2: h->Path.Off = 0x18; h->Path.Len = 0xFFF0; break;
    case 3: h->Path.Len = 0; break;
    case 4: h->Total = need + 0x400; break;
    case 5: buf[h->Path.Off] = '\\'; buf[h->Path.Off + 1] = 0; break;
    case 6: h->Path.Off = need - 2; h->Path.Len = 4; break;
    }
    return need;
}

static int interesting_port(HRESULT hr) {
    if (SUCCEEDED(hr)) return 0;
    if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)) return 0;
    if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) return 0;
    if (hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)) return 0;
    if (hr == 0x80070005 || hr == 0x8007000D) return 0;
    if (hr == 0x80070057) return 0;
    if (hr == 0x800700BB) return 0;
    return 1;
}

static int interesting_fsctl(DWORD err) {
    if (err == 0) return 0;
    if (err == ERROR_INVALID_FUNCTION) return 0;
    if (err == ERROR_INVALID_PARAMETER) return 0;
    if (err == ERROR_INSUFFICIENT_BUFFER) return 0;
    if (err == ERROR_ACCESS_DENIED) return 0;
    if (err == ERROR_NOT_SUPPORTED) return 0;
    if (err == 0x3E6) return 0;
    if (err == ERROR_INVALID_HANDLE) return 0;
    if (err == 6) return 0;
    if (err == ERROR_MORE_DATA) return 0;
    return 1;
}

static void fuzz_port_round(unsigned char *msg, unsigned char *outb,
                            ULONG cap, ULONG round) {
    static const struct { DWORD type; ULONG (*build)(unsigned char *, ULONG, ULONG); const char *name; }
    cases[] = {
        { 0,  build_store,  "store" },
        { 2,  build_remove, "remove" },
        { 4,  build_batch,  "batch_store" },
        { 6,  build_remove, "batch_remove" },
        { 8,  NULL,         "getmap" },
        { 10, build_track,  "track" },
    };
    const size_t ncase = sizeof(cases) / sizeof(cases[0]);
    size_t idx = round % ncase;
    if (g_mode == 3) idx = 2;
    ULONG paymax = cap - (ULONG)sizeof(BINDFLT_MSG_HDR);
    unsigned char *pay = msg + sizeof(BINDFLT_MSG_HDR);
    ULONG paylen;
    if (cases[idx].build)
        paylen = cases[idx].build(pay, paymax, round);
    else
        paylen = build_getmap(pay, paymax, round, 0);

    ULONG total = (ULONG)(sizeof(BINDFLT_MSG_HDR) + paylen);
    if (total > cap) total = cap;
    BINDFLT_MSG_HDR *hdr = (BINDFLT_MSG_HDR *)msg;
    hdr->Type = cases[idx].type;
    hdr->Size = total;
    InterlockedExchange(&g_last_port_round, (LONG)round);
    InterlockedExchange(&g_last_port_type, (LONG)cases[idx].type);

    if ((round % 17) == 16)
        hdr->Size = total + (round & 0xF);

    DWORD br = 0;
    HRESULT hr = FilterSendMessage(g_port, msg, total, outb, cap, &br);
    if (interesting_port(hr)) {
        printf("HIT port type=%lu %s total=%lu hr=0x%08lX br=%lu\n",
               (unsigned long)cases[idx].type, cases[idx].name,
               (unsigned long)total, (unsigned long)hr, (unsigned long)br);
        if (hr == HRESULT_FROM_WIN32(ERROR_NOACCESS) || hr == 0x80070005)
            InterlockedExchange(&g_run, 0);
    }
}

static void fuzz_fsctl_round(unsigned char *inb, unsigned char *outb, ULONG round) {
    static const struct {
        DWORD code;
        const char *name;
        ULONG min_in;
        ULONG min_out;
        int kind;
    } fsctls[] = {
        { FSCTL_SET_LAYER_ROOT, "set_layer_root", 4, 2, 1 },
        { FSCTL_SHADOW_REMAP,   "shadow_remap",   MIN_SHADOW_IN, 0, 2 },
        { FSCTL_SHADOW_FWD,     "shadow_fwd",     MIN_SHADOW_IN, 0, 2 },
        { FSCTL_GET_MAPPINGS,   "get_mappings",   MIN_GETMAP, 0x0C, 3 },
        { FSCTL_REJECT_A,       "reject_a",       0, 0, 0 },
        { FSCTL_REJECT_B,       "reject_b",       0, 0, 0 },
    };
    const size_t n = sizeof(fsctls) / sizeof(fsctls[0]);
    size_t idx = round % n;
    const DWORD code = fsctls[idx].code;
    ULONG insz = fsctls[idx].min_in;
    ULONG outsz = fsctls[idx].min_out;

    memset(inb, 0, 0x4000);
    memset(outb, 0, 0x4000);

    switch (fsctls[idx].kind) {
    case 1:
        insz = 4 + (round & 0x3F);
        *(DWORD *)inb = (round & 1) ? 0x100 : 0xE0;
        if ((round % 5) == 4) *(DWORD *)inb = 0xCFFFFC01;
        outsz = 2 + (round & 0x1F);
        break;
    case 2:
        insz = MIN_SHADOW_IN + (round & 0xFF);
        *(HANDLE *)(inb + 0) = g_vol;
        *(DWORD *)(inb + 8) = (DWORD)round;
        if ((round % 9) == 8) insz = MIN_SHADOW_IN - 1;
        if ((round % 11) == 10)
            *(HANDLE *)(inb + 0) = (HANDLE)(ULONG_PTR)0xDEAD;
        outsz = (round & 0x7F);
        break;
    case 3:
        insz = build_getmap(inb, 0x4000, round, 1);
        outsz = (round % 4) ? (0x10000 - (round & 0xF)) : 0x0C;
        break;
    default:
        insz = round & 0xFF;
        outsz = round & 0x7F;
        break;
    }

    DWORD br = 0;
    BOOL ok = DeviceIoControl(g_vol, code, inb, insz, outb, outsz, &br, NULL);
    DWORD err = ok ? 0 : GetLastError();
    if (interesting_fsctl(err)) {
        printf("HIT FSCTL 0x%08lX %s insz=%lu outsz=%lu err=%lu br=%lu\n",
               (unsigned long)code, fsctls[idx].name,
               (unsigned long)insz, (unsigned long)outsz,
               (unsigned long)err, (unsigned long)br);
        if (err == ERROR_NOACCESS || err == 0x3E6)
            InterlockedExchange(&g_run, 0);
    }
}

static unsigned __stdcall port_worker(void *arg) {
    ULONG rounds = (ULONG)(uintptr_t)arg;
    static unsigned char pay[0x8000], outb[0x8000];
    for (ULONG r = 0; g_run && r < rounds; r++)
        fuzz_port_round(pay, outb, sizeof(pay), r ^ (ULONG)time(NULL));
    return 0;
}

static unsigned __stdcall fsctl_worker(void *arg) {
    ULONG rounds = (ULONG)(uintptr_t)arg;
    static unsigned char inb[0x4000], outb[0x4000];
    for (ULONG r = 0; g_run && r < rounds; r++)
        fuzz_fsctl_round(inb, outb, r ^ 0xA5A5A5A5u);
    return 0;
}

int main(int argc, char **argv) {
    int rounds = 5000;
    int threads = 4;
    char vol[MAX_PATH] = "C:\\";

    if (argc > 1) rounds = atoi(argv[1]);
    if (argc > 2) threads = atoi(argv[2]);
    if (argc > 3) strncpy(vol, argv[3], sizeof(vol) - 1);
    if (argc > 4) {
        if (!strcmp(argv[4], "port")) g_mode = 1;
        else if (!strcmp(argv[4], "fsctl")) g_mode = 2;
        else if (!strcmp(argv[4], "batch4")) g_mode = 3;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)time(NULL));
    if (!GetEnvironmentVariableA("TEMP", g_root, MAX_PATH))
        strcpy(g_root, "C:\\Users\\Public");

    printf("[*] bindflt_struct_fuzz rounds=%d threads=%d vol=%s mode=%d\n",
           rounds, threads, vol, g_mode);

    int need_vol = (g_mode == 0 || g_mode == 2);

    if (load_api())
        seed_mappings();
    else
        printf("[-] bindfltapi missing, seed skipped\n");

    g_vol = CreateFileA(vol, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (g_vol == INVALID_HANDLE_VALUE) {
        printf("[-] open %s err=%lu\n", vol, GetLastError());
        if (need_vol)
            return 1;
    }

    HRESULT hr = FilterConnectCommunicationPort(
        PORT_BINDFLT, 0, NULL, 0, NULL, &g_port);
    if (FAILED(hr)) {
        printf("[-] port connect hr=0x%08lX (need admin)\n", (unsigned long)hr);
        if (g_vol != INVALID_HANDLE_VALUE)
            CloseHandle(g_vol);
        return 1;
    }
    printf("[+] port open\n");

    g_run = 1;
    uintptr_t hs[16];
    int n = 0;
    if (g_mode == 0 || g_mode == 2)
        hs[n++] = _beginthreadex(NULL, 0, fsctl_worker,
                                 (void *)(uintptr_t)rounds, 0, NULL);
    if (g_mode == 0 || g_mode == 1 || g_mode == 3)
        for (int i = 0; i < threads && n < 16; i++)
            hs[n++] = _beginthreadex(NULL, 0, port_worker,
                                     (void *)(uintptr_t)rounds, 0, NULL);

    for (int i = 0; i < n; i++)
        WaitForSingleObject((HANDLE)hs[i], INFINITE);

    CloseHandle(g_port);
    if (g_vol != INVALID_HANDLE_VALUE)
        CloseHandle(g_vol);
    printf("[*] done\n");
    return 0;
}