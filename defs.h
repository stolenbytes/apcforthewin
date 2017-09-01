#define         INITGUID
#include        <windows.h>
#include        <strsafe.h>
#include        <stddef.h>
#include        <stdlib.h>
#pragma         warning(disable:4005)
#include        <ntstatus.h>
#include        <objbase.h>
#include        "pe64.h"
#include        "exapi.h"

#pragma         warning(disable:4146)

BOOL            FindRWXImage(__in WCHAR *wsFilePath);
PVOID           ExportShellcode(DWORD *);

typedef HRESULT (WINAPI *DLLGETCLASSOBJECT)(
  __in  REFCLSID rclsid,
  __in  REFIID   riid,
  __out LPVOID   *ppv
);

DEFINE_GUID(CLSID_ComActivator,
            0x0000033C, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
            
PVOID NTAPI RtlAllocateHeap(
  __in     PVOID  HeapHandle,
  __in_opt ULONG  Flags,
  __in     SIZE_T Size
);

BOOLEAN NTAPI RtlFreeHeap(
  __in     PVOID HeapHandle,
  __in_opt ULONG Flags,
  __in     PVOID HeapBase
);

