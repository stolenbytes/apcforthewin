include                 pe64.inc

                        .code
public ExportShellcode
ExportShellcode:
                        mov     dword ptr[rcx], shellcode_end - shellcode
                        mov     rax, offset shellcode
                        ret
                        
shellcode:              ;int     3
                        ;align and create shadow stack right away...
                        sub     rsp, 28h
                        ;is there ActivationContextStack ??                  
                        cmp     qword ptr gs:[02c8h], 0
                        jne     __noactivation_needed
                        
                        ;Nope, create one...
                        ;by calling ntdll!RtlAllocateActivationContextStack
                        mov     ecx, 00135A08Ah
                        call    get_api_mshash
                        test    rax, rax
                        jz      __noactivation_needed
                        
                        mov     rcx, qword ptr gs:[030h]
                        lea     rcx, [rcx+02c8h]
                        call    rax
__noactivation_needed:  
                        mov     ecx, 0BC4DA2A8h
                        call    get_api_mshash
                        
                        xor     r9, r9
                        lea     r8, msgtitle
                        lea     rdx, msgtext
                        xor     rcx, rcx
                        call    rax
                        
                        add     rsp, 28h
                        ret
                        
msgtext                 db      "All ok injection worked...", 0
msgtitle                db      "oki...", 0                          


get_api_mshash:         push    rsi
                        push    rbx
                        push    rdi
                        mov     rbx, rcx
                        mov     rsi, qword ptr gs:[60h]	
                        mov     rsi, qword ptr [rsi+018h] 
                        lea     rdi, qword ptr [rsi+30h]
                        mov     rsi, qword ptr [rsi+30h]

__loop_api1:            cmp     rdi, rsi
                        je      __exit_gam
                        mov     rdx, rbx
                        mov     rcx, qword ptr[rsi+10h]                                                
                        call    getprocaddress
                        mov     rsi, qword ptr[rsi]
                        test    rax, rax
                        jz      __loop_api1
__exit_gam:
                        pop     rdi
                        pop     rbx
                        pop     rsi
                        ret     
                        
getprocaddress:         push    rsi
                        xor     rax, rax
                        test    rcx, rcx
                        jz      __exit_gpa
                        mov     r8, rcx
                        mov     r9, rdx
                        
                        mov     eax, dword ptr[r8+3ch]
                        add     rax, r8
                        mov     eax, dword ptr[rax.peheader64.pe_export]
                        test    eax, eax
                        jz      __exit_gpa
                        add     rax, r8
                        mov     r10, rax
                        
                        xor     rcx, rcx
                        mov     r11d, dword ptr[r10.export_directory.ed_addressofnames]
                        add     r11, r8

__loop_names:                        
                        mov     esi, dword ptr[r11]
                        add     rsi, r8
                            
                        xor     rax, rax
                        cdq
__get_hash:             lodsb
                        test    al, al
                        jz      __cmphash
                        ror     edx, 0dh
                        add     edx, eax
                        jmp     __get_hash
__cmphash:              cmp     r9d, edx
                        jz      __get_api
                        add     r11, 4
                        inc     ecx
                        cmp     ecx, dword ptr[r10.export_directory.ed_numberofnames]
                        jne     __loop_names
                        xor     eax, eax
                        jmp     __exit_gpa
__get_api:              mov     eax, dword ptr[r10.export_directory.ed_addressofordinals]   
                        add     rax, r8
                        movzx   eax, word ptr[rax+rcx*2]
                        mov     ecx, dword ptr[r10.export_directory.ed_addressoffunctions]
                        add     rcx, r8
                        mov     eax, dword ptr[rcx+rax*4]
                        add     rax, r8                     
__exit_gpa:             pop     rsi
                        ret             

shellcode_end:

                        end


