// version.dll for Marvel's Midnight Suns: keeps the suit registry pak in sync, every time the game starts.
//
// MidnightSuns-Win64-Shipping.exe imports version.dll and Windows looks next to the exe first, so this DLL loads
// before the engine starts (long before it mounts the paks). Its 17 exports lead to the real implementations (see
// version.def).
//
// On load (in the game only) it checks quickly whether the suit paks still match the registry pak (file reads only:
// DllMain runs under the loader lock, so no threads, downloads or windows here). If something changed it copies itself
// to %LOCALAPPDATA%\MidnightSunsSuitRegistry\SuitRegistrySync.dll and runs
//   rundll32.exe SuitRegistrySync.dll,SuitRegistrySync --from-game <Paks folder>
// and waits: that process rebuilds the registry pak with a small console window, then the game carries on.
// Build: see build.sh (zig cc -target x86_64-windows-gnu -shared).
#include "sr.h"
#include <tlhelp32.h>

// found by `strings` / tools to tell this DLL apart from other mods' version.dll
__attribute__((used)) const char suit_registry_marker[] = "MidnightSunsSuitRegistryProxy v3";

HINSTANCE sr_self;

// The game's anti-tamper crashes it when an imported function starts with a jmp (a hook), or when a second module
// named version.dll (the real one) is loaded. So every export that kernelbase.dll also has is a real PE forwarder
// (version.def): the loader binds the game straight to kernelbase. Only the three that kernelbase lacks (nothing in
// the game imports them) load the real version.dll lazily, on their first call.
#define EXPORTS(X) X(GetFileVersionInfoByHandle) X(VerInstallFileA) X(VerInstallFileW)

#define THUNK(name) \
    void *real_##name; \
    __asm__(".text\n.globl " #name "\n" #name ":\n" \
            "\tmovq real_" #name "(%rip), %rax\n\ttestq %rax, %rax\n\tjz 1f\n\tjmp *%rax\n" \
            "1:\tpushq %rcx\n\tpushq %rdx\n\tpushq %r8\n\tpushq %r9\n\tsubq $40, %rsp\n\tcall load_real\n" \
            "\taddq $40, %rsp\n\tpopq %r9\n\tpopq %r8\n\tpopq %rdx\n\tpopq %rcx\n\tjmp *real_" #name "(%rip)\n");
EXPORTS(THUNK)

static BOOL WINAPI not_available(void) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }

void load_real(void)
{
    wchar_t path[MAX_PATH];
    HMODULE real = NULL;
    UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (n && n < MAX_PATH - 20) {
        lstrcatW(path, L"\\version.dll");
        real = LoadLibraryW(path);
        if (real == sr_self) real = NULL;
    }
#define RESOLVE(name) \
    if (!(real_##name = real ? (void *)GetProcAddress(real, #name) : NULL)) real_##name = (void *)not_available;
    EXPORTS(RESOLVE)
}

static wchar_t *file_part(wchar_t *path)
{
    wchar_t *p = path, *last = path;
    for (; *p; p++)
        if (*p == L'\\' || *p == L'/') last = p + 1;
    return last;
}

// ---------------------------------------------------------------- user32 / shell32, loaded only when needed

static void message(const wchar_t *text, int error)
{
    HMODULE u = LoadLibraryW(L"user32.dll");
    typedef int (WINAPI *mb_t)(HWND, LPCWSTR, LPCWSTR, UINT);
    mb_t mb = u ? (mb_t)GetProcAddress(u, "MessageBoxW") : NULL;
    if (mb) mb(NULL, text, L"Midnight Suns suit registry", (error ? MB_ICONERROR : MB_ICONINFORMATION) | MB_SETFOREGROUND);
}

static int run_elevated(const wchar_t *args)
{
    typedef struct {
        DWORD cbSize; ULONG fMask; HWND hwnd; LPCWSTR lpVerb, lpFile, lpParameters, lpDirectory; int nShow;
        HINSTANCE hInstApp; void *lpIDList; LPCWSTR lpClass; HKEY hkeyClass; DWORD dwHotKey; HANDLE hIcon; HANDLE hProcess;
    } sei_t;
    HMODULE s = LoadLibraryW(L"shell32.dll");
    typedef BOOL (WINAPI *exec_t)(sei_t *);
    exec_t ex = s ? (exec_t)GetProcAddress(s, "ShellExecuteExW") : NULL;
    if (!ex) return -1;
    wchar_t rundll[MAX_PATH];
    GetSystemDirectoryW(rundll, MAX_PATH - 20);
    lstrcatW(rundll, L"\\rundll32.exe");
    sei_t sei = {sizeof sei, 0x40 /* SEE_MASK_NOCLOSEPROCESS */, NULL, L"runas", rundll, args, NULL, SW_HIDE};
    if (!ex(&sei) || !sei.hProcess) return -1;
    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return (int)code;
}

static int game_running(void)
{
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof pe};
    int found = 0;
    for (BOOL ok = Process32FirstW(h, &pe); ok; ok = Process32NextW(h, &pe))
        if (!_wcsicmp(pe.szExeFile, L"MidnightSuns-Win64-Shipping.exe")) found = 1;
    CloseHandle(h);
    return found;
}

// ---------------------------------------------------------------- the sync process (rundll32 entry point)

// cmd: [--from-game] [--quiet] [--elevated] <Paks folder>
void CALLBACK SuitRegistrySyncW(HWND hwnd, HINSTANCE hinst, LPWSTR cmd, int show)
{
    (void)hwnd; (void)hinst; (void)show;
    int from_game = 0, quiet = 0, elevated = 0;
    wchar_t *p = cmd;
    for (;;) {
        while (*p == L' ') p++;
        if (!wcsncmp(p, L"--from-game", 11)) { from_game = 1; p += 11; }
        else if (!wcsncmp(p, L"--quiet", 7)) { quiet = 1; p += 7; }
        else if (!wcsncmp(p, L"--elevated", 10)) { elevated = 1; p += 10; }
        else break;
    }
    wchar_t paks[MAX_PATH * 2];
    lstrcpynW(paks, p, MAX_PATH * 2);
    size_t n = wcslen(paks);
    while (n && (paks[n - 1] == L' ' || paks[n - 1] == L'"' || paks[n - 1] == L'\\')) paks[--n] = 0;
    wchar_t *start = paks;
    if (*start == L'"') start++;

    log_open();
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\MidnightSunsSuitRegistry");
    if (mutex) WaitForSingleObject(mutex, 10 * 60 * 1000);
    int rc = 0;
    jmp_buf j;
    sr_jmp = &j;
    if (!setjmp(j)) {
        if (!*start || GetFileAttributesW(start) == INVALID_FILE_ATTRIBUTES)
            sr_fail("Paks folder not found: %ls", start);
        if (!from_game && game_running())
            sr_fail("Midnight Suns is running: close it first (replacing paks under the running game crashes it)");
        rc = sync_run(start, from_game);
        if (rc == 5 && !elevated) {
            log_msg("the game folder needs administrator rights - asking Windows for permission...");
            if (mutex) ReleaseMutex(mutex);
            static wchar_t args[MAX_PATH * 3];
            wchar_t self[MAX_PATH];
            GetModuleFileNameW(sr_self, self, MAX_PATH);
            swprintf(args, MAX_PATH * 3, L"\"%ls\",SuitRegistrySync --elevated %ls%ls%ls", self,
                     from_game ? L"--from-game " : L"", quiet ? L"--quiet " : L"", start);
            rc = run_elevated(args);
            if (rc < 0) sr_fail("administrator rights are needed to update the registry pak in %ls", start);
        } else if (rc == 5) sr_fail("no permission to write to %ls", start);
    } else {
        log_msg("error: %s", sr_error);
        if (!quiet) {
            wchar_t *w = utf8_to_w(sr_error);
            static wchar_t text[2048];
            swprintf(text, 2048, L"%ls\n\n%lsLog: %ls\\SuitRegistry.log", w,
                     from_game ? L"The game will start, but suit changes were not applied.\n\n" : L"", data_dir());
            message(text, 1);
        }
        rc = 3;
    }
    if (mutex) { ReleaseMutex(mutex); CloseHandle(mutex); }
    ExitProcess((UINT)rc);
}

void CALLBACK SuitRegistrySync(HWND hwnd, HINSTANCE hinst, LPSTR cmd, int show)
{
    wchar_t *w = utf8_to_w(cmd);
    SuitRegistrySyncW(hwnd, hinst, w, show);
}

// ---------------------------------------------------------------- in the game: check, and start the sync if needed

static void start_sync(const wchar_t *paks)
{
    wchar_t self[MAX_PATH], rundll[MAX_PATH];
    if (!GetModuleFileNameW(sr_self, self, MAX_PATH)) return;
    wchar_t *copy = wpath(data_dir(), L"SuitRegistrySync.dll");
    if (!CopyFileW(self, copy, FALSE) && GetFileAttributesW(copy) == INVALID_FILE_ATTRIBUTES) { free(copy); return; }
    GetSystemDirectoryW(rundll, MAX_PATH - 20);
    lstrcatW(rundll, L"\\rundll32.exe");
    static wchar_t cmd[MAX_PATH * 4];
    swprintf(cmd, MAX_PATH * 4, L"\"%ls\" \"%ls\",SuitRegistrySync --from-game %ls", rundll, copy, paks);
    free(copy);
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(rundll, cmd, NULL, NULL, FALSE, 0, NULL, data_dir(), &si, &pi)) return;
    WaitForSingleObject(pi.hProcess, 15 * 60 * 1000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

static void on_game_start(void)
{
    wchar_t exe[MAX_PATH], dir[MAX_PATH], rel[MAX_PATH + 32], paks[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH) || _wcsicmp(file_part(exe), L"MidnightSuns-Win64-Shipping.exe"))
        return;                                                 // only in the game itself
    if (GetEnvironmentVariableW(L"SUITREGISTRY_SKIP", NULL, 0)) return;
    DWORD n = GetModuleFileNameW(sr_self, dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return;
    *file_part(dir) = 0;                                        // ...\MidnightSuns\Binaries\Win64\  .
    swprintf(rel, MAX_PATH + 32, L"%ls..\\..\\Content\\Paks", dir);
    if (!GetFullPathNameW(rel, MAX_PATH, paks, NULL)) return;
    int need = 1;
    jmp_buf j;
    sr_jmp = &j;
    if (!setjmp(j)) need = sync_quick_check(paks);
    sr_jmp = NULL;
    if (need) start_sync(paks);
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        sr_self = self;
        DisableThreadLibraryCalls(self);
        on_game_start();
    }
    return TRUE;
}
