#include        "defs.h"

WCHAR   g_wsFilePath[MAX_PATH];


//0 - means load all
//1 - load pe32...
//2 - load pe64...
#define TYPE_LOAD_ALL   0
#define TYPE_LOAD_PE32  1
#define TYPE_LOAD_PE64  2

PVOID   xLoadLibraryExW(__in WCHAR *wsFileName, __in ULONG   dwType){
        HANDLE hFile = INVALID_HANDLE_VALUE, hSection = NULL;
        PVOID  mhandle = NULL, lpMappedImage = NULL;
        PIMAGE_DOS_HEADER       pmz;
        PPEHEADER32             pe32;
        PPEHEADER64             pe64;
        PSECTION_HEADER         section;
        DWORD                   index;
        BOOL                    b_pe64 = FALSE;
        ULONG_PTR               delta, apply_reloc;
        ULONGLONG               delta64;
        ULONG                   dwRelocSize, dwRelocChunkSize;
        PUSHORT                 preloc;
        PIMAGE_BASE_RELOCATION  p_reloc;
        
        hFile = CreateFile(wsFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
        if (hFile == INVALID_HANDLE_VALUE) goto __Exit0;
        hSection = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0,0,0);
        if (!hSection) goto __Exit0;
        mhandle = MapViewOfFile(hSection, FILE_MAP_READ, 0,0,0);
        if (!mhandle) goto __Exit0;
        
        pmz = (PIMAGE_DOS_HEADER)mhandle;
        if (pmz->e_magic != IMAGE_DOS_SIGNATURE) goto __Exit0;
        if ((DWORD)pmz->e_lfanew > 0x1000) goto __Exit0;
                
        pe32= (PPEHEADER32)((ULONG_PTR)mhandle + pmz->e_lfanew);
        pe64= (PPEHEADER64)((ULONG_PTR)mhandle + pmz->e_lfanew);
        
        if (pe32->pe_signature != IMAGE_NT_SIGNATURE) goto __Exit0;
            
        //section offset is calculated same for pe32 and pe64 as those fields are on same offset in PE/PE+ but just to make
        //everything nice and clean we do it like this :)
        if (pe32->pe_magic == 0x20b){
                b_pe64 = TRUE;
                if (dwType != TYPE_LOAD_ALL && dwType != TYPE_LOAD_PE64) goto __Exit0; 
                section = (PSECTION_HEADER)((ULONG_PTR)pe64 + 4 + sizeof(IMAGE_FILE_HEADER) + pe64->pe_sizeofoptionalheader);
                lpMappedImage = VirtualAlloc(0, pe64->pe_sizeofimage, MEM_COMMIT, PAGE_READWRITE);
        }else{
                if (dwType != TYPE_LOAD_ALL && dwType != TYPE_LOAD_PE32) goto __Exit0;
                section = (PSECTION_HEADER)((ULONG_PTR)pe32 + 4 + sizeof(IMAGE_FILE_HEADER) + pe32->pe_sizeofoptionalheader);
                lpMappedImage = NULL;
                lpMappedImage = VirtualAlloc(0, pe32->pe_sizeofimage, MEM_COMMIT, PAGE_READWRITE);
        }

        if (!lpMappedImage) goto __Exit0;
                
        if (b_pe64)            
                memcpy(lpMappedImage, mhandle, pe64->pe_sizeofheaders);
        else
                memcpy(lpMappedImage, mhandle, pe32->pe_sizeofheaders);
        
        for (index = 0; index < pe32->pe_numberofsections; index++)
                memcpy((void *)((ULONG_PTR)lpMappedImage + section[index].sh_virtualaddress),
                       (void *)((ULONG_PTR)mhandle       + section[index].sh_pointertorawdata),
                       section[index].sh_sizeofrawdata);
        
        if (b_pe64){
                if (pe64->pe_reloc == 0) goto __Exit0;
        }else{
                if (pe32->pe_reloc == 0) goto __Exit0;
        }
        
        if (b_pe64){
                p_reloc     = (PIMAGE_BASE_RELOCATION)(pe64->pe_reloc + (ULONG_PTR)lpMappedImage);
                dwRelocSize = pe64->pe_relocsize;
                delta64 = (ULONGLONG)lpMappedImage - pe64->pe_imagebase;
        }else{
                p_reloc     = (PIMAGE_BASE_RELOCATION)(pe32->pe_reloc + (ULONG_PTR)lpMappedImage);
                dwRelocSize = pe32->pe_relocsize;
                delta = (ULONG_PTR)lpMappedImage - pe32->pe_imagebase;
        }
        
        while (dwRelocSize){
                preloc      = (PUSHORT)((ULONG_PTR)p_reloc + sizeof(IMAGE_BASE_RELOCATION));
                dwRelocChunkSize = p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
                apply_reloc = (ULONG_PTR)lpMappedImage + p_reloc->VirtualAddress;
                while (dwRelocChunkSize){
                        if (b_pe64){
                                if (((*preloc & 0xF000) >> 12) == 10)
                                        *(ULONGLONG *)(apply_reloc + (*preloc & 0xFFF)) += delta64;
                           
                        }else{
                                if (((*preloc & 0xF000) >> 12) == 0x3)
                                        *(PULONG_PTR)(apply_reloc + (*preloc & 0xFFF)) += delta;
                        }        
                        preloc++;
                        dwRelocChunkSize -= sizeof(USHORT);        
                }                
                
                dwRelocSize -= p_reloc->SizeOfBlock;
                p_reloc     = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)p_reloc + p_reloc->SizeOfBlock);
        }
        
__Exit0:
        if (mhandle)
                UnmapViewOfFile(mhandle);
        if (hSection)
                CloseHandle(hSection);
        if (hFile != INVALID_HANDLE_VALUE)
                CloseHandle(hFile);
                
        return lpMappedImage;
}

VOID    ParseFolders(__in WCHAR *wsFolderPath){
        WIN32_FIND_DATA wfd;
        HANDLE          hFind;
        PIMAGE_DOS_HEADER       pmz;
        PPEHEADER32             pe32;
        PSECTION_HEADER         psection;
        ULONG                   index;
        ULONG_PTR               imagebase;
        WCHAR                   wsCurrentFolder[MAX_PATH];
        WCHAR                   wsSubFolder[MAX_PATH];
        
        memset(wsCurrentFolder, 0, sizeof(wsCurrentFolder));
        GetCurrentDirectory(MAX_PATH, wsCurrentFolder);
        
        SetCurrentDirectory(wsFolderPath);
        
        hFind = FindFirstFile(L"*", &wfd);
        if (hFind == INVALID_HANDLE_VALUE) goto __Exit0;        
        do{
                if (wfd.cFileName[0] == '.' && wfd.cFileName[1] == 0) continue;
                if (wfd.cFileName[0] == '.' && wfd.cFileName[1] == '.' && wfd.cFileName[2] == 0) continue;                
                
                if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
                        StringCchPrintf(wsSubFolder, MAX_PATH, L"%s\\%s", wsFolderPath, wfd.cFileName);
                        ParseFolders(wsSubFolder);
                        if (g_wsFilePath[0] != 0) break;
                }
                //else
                //        wprintf(L"%s\n", wfd.cFileName);
                #ifdef _WIN64
                imagebase = (ULONG_PTR)xLoadLibraryExW(wfd.cFileName, TYPE_LOAD_PE64);
                #else
                imagebase = (ULONG_PTR)xLoadLibraryExW(wfd.cFileName, TYPE_LOAD_PE32);
                #endif
                
                if (imagebase == 0) continue;
                pmz = (PIMAGE_DOS_HEADER)imagebase;
                pe32= (PPEHEADER32)(imagebase + pmz->e_lfanew);
                psection = (PSECTION_HEADER)((ULONG_PTR)pe32 + 4 + sizeof(IMAGE_FILE_HEADER) + pe32->pe_sizeofoptionalheader);
                for (index = 0; index < pe32->pe_numberofsections; index++){
                        if ((psection[index].sh_characteristics & 0xF0000000) == (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) && \
                             psection[index].sh_virtualsize > 0x2000){
                                //wprintf(L"found rwx at : %s\\%s\n", wsFolderPath, wfd.cFileName);
                                StringCchPrintf(g_wsFilePath, MAX_PATH, L"%s\\%s", wsFolderPath, wfd.cFileName);       
                        }
                }
                VirtualFree((PVOID)imagebase, 0, MEM_RELEASE);
                
                if (g_wsFilePath[0] != 0) break;
        }while (FindNextFile(hFind, &wfd));
        
        FindClose(hFind);
__Exit0:        
        SetCurrentDirectory(wsCurrentFolder);        
}


BOOL    FindRWXImage(__in WCHAR *wsFilePath){
        WCHAR   wsSearchPath[MAX_PATH];        
                       
        memset(wsSearchPath, 0, sizeof(wsSearchPath));
        ExpandEnvironmentStrings(L"%windir%\\assembly", wsSearchPath, MAX_PATH);
        ParseFolders(wsSearchPath);
        StringCchCopy(wsFilePath, MAX_PATH, g_wsFilePath);
        if (g_wsFilePath[0] != 0) return TRUE;
        
        memset(wsSearchPath, 0, sizeof(wsSearchPath));
        ExpandEnvironmentStrings(L"%windir%\\Microsoft.NET\\assembly", wsSearchPath, MAX_PATH);
        ParseFolders(wsSearchPath);
        StringCchCopy(wsFilePath, MAX_PATH, g_wsFilePath);
        if (g_wsFilePath[0] != 0) return TRUE;
                
        return FALSE;
}