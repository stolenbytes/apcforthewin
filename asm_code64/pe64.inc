peheader64      struct
        pe_signature            dd      ?       
        ;FILE_HEADER
        pe_machine              dw      ?
        pe_numberofsections     dw      ?
        pe_timedatastamp        dd      ?
        pe_pointertosymboltalbe dd      ?
        pe_numberofsymbols      dd      ?
        pe_sizeofoptionalheader dw      ?
        pe_characteristics      dw      ?
        ;OPTIONAL_HEADER                
        pe_magic                dw      ?
        pe_majorlinkerversion   db      ?
        pe_minorlinkerversion   db      ?
        pe_sizeofcode           dd      ?
        pe_sizeofidata          dd      ?
        pe_sizeofudata          dd      ?
        pe_addressofentrypoint  dd      ?
        pe_baseofcode           dd      ?     
        pe_imagebase            dq      ?
        pe_sectionalignment     dd      ?
        pe_filealignment        dd      ?
        pe_majorosversion       dw      ?
        pe_minorosversion       dw      ?
        pe_majorimgversion      dw      ?
        pe_minorimgversion      dw      ?        
        pe_majorsubsystemver    dw      ?
        pe_minorsubsystemver    dw      ?
        pe_reserved1            dd      ?
        pe_sizeofimage          dd      ?
        pe_sizeofheaders        dd      ?
        pe_checksum             dd      ?
        pe_subsystem            dw      ?
        pe_dllcharacteristics   dw      ?
        pe_sizeofstackreserve   dq      ?
        pe_sizeofstackcommit    dq      ?
        pe_sizeofheapreserve    dq      ?
        pe_sizeofhealcommit     dq      ?
        pe_loaderflags          dd      ?
        pe_numberofrvaandsizes  dd      ?
        ;data directories               
        pe_export               dd      ?
        pe_exportsize           dd      ?
        pe_import               dd      ?
        pe_importsize           dd      ?                        
        pe_resource             dd      ?
        pe_resourcesize         dd      ?
        pe_exception            dd      ?
        pe_exceptionsize        dd      ?
        pe_security             dd      ?
        pe_securitysize         dd      ?
        pe_reloc                dd      ?
        pe_relocsize            dd      ?
        pe_debug                dd      ?
        pe_debugsize            dd      ?        
        pe_copyright            dd      ?
        pe_copyrightsize        dd      ?
        pe_globalptr            dd      ?
        pe_globalptrsize        dd      ?
        pe_tls                  dd      ?
        pe_tlssize              dd      ?
        pe_loadconfig           dd      ?
        pe_loadconfigsize       dd      ?
        pe_boundimport          dd      ?
        pe_boundimportsize      dd      ?
        pe_iat                  dd      ?
        pe_iatsize              dd      ?        
peheader64      ends       

export_directory        struct
        ed_characteristics      dd      ?       ;0
        ed_timedatastamp        dd      ?       ;4
        ed_majorversion         dw      ?       ;8
        ed_minorversion         dw      ?       ;0A
        ed_name                 dd      ?       ;0C
        ed_base                 dd      ?       ;10
        ed_numberoffunctions    dd      ?       ;14
        ed_numberofnames        dd      ?       ;18
        ed_addressoffunctions   dd      ?       ;1C
        ed_addressofnames       dd      ?       ;20
        ed_addressofordinals    dd      ?       ;24
export_directory        ends
;
;import_directory        struct
;        id_originalfirstthunk   dd      ?
;        id_timedatastamp        dd      ?
;        id_forwardchain         dd      ?
;        id_name                 dd      ?
;        id_firstthunk           dd      ?
;import_directory        ends
;
;image_section_header    struct           
;        sh_name                  db     8       dup(?)
;        sh_virtualsize           dd     ?
;        sh_virtualaddress        dd     ?
;        sh_sizeofrawdata         dd     ?
;        sh_pointertorawdata      dd     ?
;        sh_pointertorelocations  dd     ?
;        sh_pointertolinenumbers  dd     ?
;        sh_numberofrelocations   dw     ?
;        sh_numberoflinenumbers   dw     ?
;        sh_characteristics       dd     ?
;image_section_header    ends

