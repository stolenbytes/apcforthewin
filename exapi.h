#ifndef __EX_API__
#define __EX_API__

//KeDelayExecutionThread macros...
//http://www.osronline.com/article.cfm?article=261
#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

typedef LONG    NTSTATUS;
typedef LONG    KPRIORITY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    USHORT * Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// begin_ntddk begin_wdm begin_nthal begin_ntifs
// begin_winnt

//
// Define access rights to files and directories
//

//
// The FILE_READ_DATA and FILE_WRITE_DATA constants are also defined in
// devioctl.h as FILE_READ_ACCESS and FILE_WRITE_ACCESS. The values for these
// constants *MUST* always be in sync.
// The values are redefined in devioctl.h because they must be available to
// both DOS and NT.
//

#define FILE_READ_DATA            ( 0x0001 )    // file & pipe
#define FILE_LIST_DIRECTORY       ( 0x0001 )    // directory

#define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
#define FILE_ADD_FILE             ( 0x0002 )    // directory

#define FILE_APPEND_DATA          ( 0x0004 )    // file
#define FILE_ADD_SUBDIRECTORY     ( 0x0004 )    // directory
#define FILE_CREATE_PIPE_INSTANCE ( 0x0004 )    // named pipe


#define FILE_READ_EA              ( 0x0008 )    // file & directory

#define FILE_WRITE_EA             ( 0x0010 )    // file & directory

#define FILE_EXECUTE              ( 0x0020 )    // file
#define FILE_TRAVERSE             ( 0x0020 )    // directory

#define FILE_DELETE_CHILD         ( 0x0040 )    // directory

#define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all

#define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ     |\
                                   FILE_READ_DATA           |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_READ_EA             |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE    |\
                                   FILE_WRITE_DATA          |\
                                   FILE_WRITE_ATTRIBUTES    |\
                                   FILE_WRITE_EA            |\
                                   FILE_APPEND_DATA         |\
                                   SYNCHRONIZE)


#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE  |\
                                   FILE_READ_ATTRIBUTES     |\
                                   FILE_EXECUTE             |\
                                   SYNCHRONIZE)

// end_winnt


//
// Define share access rights to files and directories
//

#define FILE_SHARE_READ                 0x00000001  // winnt
#define FILE_SHARE_WRITE                0x00000002  // winnt
#define FILE_SHARE_DELETE               0x00000004  // winnt
#define FILE_SHARE_VALID_FLAGS          0x00000007

//
// Define the file attributes values
//
// Note:  0x00000008 is reserved for use for the old DOS VOLID (volume ID)
//        and is therefore not considered valid in NT.
//
// Note:  0x00000010 is reserved for use for the old DOS SUBDIRECTORY flag
//        and is therefore not considered valid in NT.  This flag has
//        been disassociated with file attributes since the other flags are
//        protected with READ_ and WRITE_ATTRIBUTES access to the file.
//
// Note:  Note also that the order of these flags is set to allow both the
//        FAT and the Pinball File Systems to directly set the attributes
//        flags in attributes words without having to pick each flag out
//        individually.  The order of these flags should not be changed!
//

#define FILE_ATTRIBUTE_READONLY             0x00000001  // winnt
#define FILE_ATTRIBUTE_HIDDEN               0x00000002  // winnt
#define FILE_ATTRIBUTE_SYSTEM               0x00000004  // winnt
//OLD DOS VOLID                             0x00000008

#define FILE_ATTRIBUTE_DIRECTORY            0x00000010  // winnt
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020  // winnt
#define FILE_ATTRIBUTE_DEVICE               0x00000040  // winnt
#define FILE_ATTRIBUTE_NORMAL               0x00000080  // winnt

#define FILE_ATTRIBUTE_TEMPORARY            0x00000100  // winnt
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200  // winnt
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400  // winnt
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  // winnt

#define FILE_ATTRIBUTE_OFFLINE              0x00001000  // winnt
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000  // winnt
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000  // winnt

#define FILE_ATTRIBUTE_VALID_FLAGS          0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS      0x000031a7

//
// Define the create disposition values
//

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

//
// Define the create/open option flags
//

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441


#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

//
// Valid values for the Attributes field
//

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

//++
//
// VOID
// InitializeObjectAttributes(
//     OUT POBJECT_ATTRIBUTES p,
//     IN PUNICODE_STRING n,
//     IN ULONG a,
//     IN HANDLE r,
//     IN PSECURITY_DESCRIPTOR s
//     )
//
//--

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
    
NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(
    PANSI_STRING DestinationString,
    PUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSYSAPI
VOID
NTAPI
RtlFreeAnsiString(
    PANSI_STRING AnsiString
    );
                
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation
// end_wdm
    ,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    MaxKeyInfoClass  // MaxKeyInfoClass should always be the last enum
// begin_wdm
} KEY_INFORMATION_CLASS;

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG   TitleIndex;
    ULONG   ClassOffset;
    ULONG   ClassLength;
    ULONG   SubKeys;
    ULONG   MaxNameLen;
    ULONG   MaxClassLen;
    ULONG   Values;
    ULONG   MaxValueNameLen;
    ULONG   MaxValueDataLen;
    WCHAR   Class[1];           // Variable length
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
  KeyValueBasicInformation,
  KeyValueFullInformation,
  KeyValuePartialInformation
} KEY_VALUE_INFORMATION_CLASS;


typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataOffset;
    ULONG   DataLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateValueKey(
    __in HANDLE KeyHandle,
    __in ULONG Index,
    __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    __out_bcount_opt(Length) PVOID KeyValueInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtEnumerateKey(
    __in HANDLE KeyHandle,
    __in ULONG Index,
    __in KEY_INFORMATION_CLASS KeyInformationClass,
    __out_bcount_opt(Length) PVOID KeyInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenKey(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryKey(
    __in HANDLE KeyHandle,
    __in KEY_INFORMATION_CLASS KeyInformationClass,
    __out_bcount_opt(Length) PVOID KeyInformation,
    __in ULONG Length,
    __out PULONG ResultLength
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory (
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __in ULONG_PTR ZeroBits,
    __inout PSIZE_T RegionSize,
    __in ULONG AllocationType,
    __in ULONG Protect
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory (
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __inout PSIZE_T RegionSize,
    __in ULONG FreeType
    );

ULONG
__cdecl
DbgPrint (
    __in PCH Format,
    ...
    );


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

#if defined(_WIN64)
typedef ULONG SYSINF_PAGE_COUNT;
#else
typedef SIZE_T SYSINF_PAGE_COUNT;
#endif

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    SYSINF_PAGE_COUNT NumberOfPhysicalPages;
    SYSINF_PAGE_COUNT LowestPhysicalPageNumber;
    SYSINF_PAGE_COUNT HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation (
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtTerminateProcess (
    __in_opt HANDLE ProcessHandle,
    __in NTSTATUS ExitStatus
    );


NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenProcess (
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtClose (
    __in HANDLE Handle
    );

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          // Note: this is kernel mode only
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessResourceManagement,
    ProcessCookie,
    ProcessImageInformation,
    MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenDirectoryObject (
    __out PHANDLE DirectoryHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryDirectoryObject (
    __in HANDLE DirectoryHandle,
     PVOID Buffer,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in BOOLEAN RestartScan,
    __inout PULONG Context,
    __out_opt PULONG ReturnLength
    );  
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenMutant (
    __out PHANDLE MutantHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenEvent (
    __out PHANDLE EventHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForSingleObject (
    __in HANDLE Handle,
    __in BOOLEAN Alertable,
    __in_opt PLARGE_INTEGER Timeout
    ); 
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetEvent (
    __in HANDLE EventHandle,
    __out_opt PLONG PreviousState
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtReleaseMutant (
    __in HANDLE MutantHandle,
    __out_opt PLONG PreviousCount
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenSection (
    __out PHANDLE SectionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection (
    __out PHANDLE SectionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PLARGE_INTEGER MaximumSize,
    __in ULONG SectionPageProtection,
    __in ULONG AllocationAttributes,
    __in_opt HANDLE FileHandle
    );
// begin_ntddk begin_wdm
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSection (
    __in HANDLE SectionHandle,
    __in HANDLE ProcessHandle,
    __inout PVOID *BaseAddress,
    __in ULONG_PTR ZeroBits,
    __in SIZE_T CommitSize,
    __inout_opt PLARGE_INTEGER SectionOffset,
    __inout PSIZE_T ViewSize,
    __in SECTION_INHERIT InheritDisposition,
    __in ULONG AllocationType,
    __in ULONG Win32Protect
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection (
    __in HANDLE ProcessHandle,
    __in PVOID BaseAddress
    ); 
    
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateFile (
    __out PHANDLE FileHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __in_opt PLARGE_INTEGER AllocationSize,
    __in ULONG FileAttributes,
    __in ULONG ShareAccess,
    __in ULONG CreateDisposition,
    __in ULONG CreateOptions,
    __in_bcount_opt(EaLength) PVOID EaBuffer,
    __in ULONG EaLength
    );  

typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );
        
NTSYSCALLAPI
NTSTATUS
NTAPI
NtReadFile (
    __in HANDLE FileHandle,
    __in_opt HANDLE Event,
    __in_opt PIO_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcContext,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out_bcount(Length) PVOID Buffer,
    __in ULONG Length,
    __in_opt PLARGE_INTEGER ByteOffset,
    __in_opt PULONG Key
    );

typedef enum _FILE_INFORMATION_CLASS {
// end_wdm
    FileDirectoryInformation         = 1,
    FileFullDirectoryInformation,   // 2
    FileBothDirectoryInformation,   // 3
    FileBasicInformation,           // 4  wdm
    FileStandardInformation,        // 5  wdm
    FileInternalInformation,        // 6
    FileEaInformation,              // 7
    FileAccessInformation,          // 8
    FileNameInformation,            // 9
    FileRenameInformation,          // 10
    FileLinkInformation,            // 11
    FileNamesInformation,           // 12
    FileDispositionInformation,     // 13
    FilePositionInformation,        // 14 wdm
    FileFullEaInformation,          // 15
    FileModeInformation,            // 16
    FileAlignmentInformation,       // 17
    FileAllInformation,             // 18
    FileAllocationInformation,      // 19
    FileEndOfFileInformation,       // 20 wdm
    FileAlternateNameInformation,   // 21
    FileStreamInformation,          // 22
    FilePipeInformation,            // 23
    FilePipeLocalInformation,       // 24
    FilePipeRemoteInformation,      // 25
    FileMailslotQueryInformation,   // 26
    FileMailslotSetInformation,     // 27
    FileCompressionInformation,     // 28
    FileObjectIdInformation,        // 29
    FileCompletionInformation,      // 30
    FileMoveClusterInformation,     // 31
    FileQuotaInformation,           // 32
    FileReparsePointInformation,    // 33
    FileNetworkOpenInformation,     // 34
    FileAttributeTagInformation,    // 35
    FileTrackingInformation,        // 36
    FileIdBothDirectoryInformation, // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation,       // 40
    FileMaximumInformation
// begin_wdm
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationFile (
    __in HANDLE FileHandle,
    __out PIO_STATUS_BLOCK IoStatusBlock,
    __out PVOID FileInformation,
    __in ULONG Length,
    __in FILE_INFORMATION_CLASS FileInformationClass
    );   
    
typedef struct _FILE_BASIC_INFORMATION {                    // ntddk wdm nthal
    LARGE_INTEGER CreationTime;                             // ntddk wdm nthal
    LARGE_INTEGER LastAccessTime;                           // ntddk wdm nthal
    LARGE_INTEGER LastWriteTime;                            // ntddk wdm nthal
    LARGE_INTEGER ChangeTime;                               // ntddk wdm nthal
    ULONG FileAttributes;                                   // ntddk wdm nthal
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;         // ntddk wdm nthal
                                                            // ntddk wdm nthal
typedef struct _FILE_STANDARD_INFORMATION {                 // ntddk wdm nthal
    LARGE_INTEGER AllocationSize;                           // ntddk wdm nthal
    LARGE_INTEGER EndOfFile;                                // ntddk wdm nthal
    ULONG NumberOfLinks;                                    // ntddk wdm nthal
    BOOLEAN DeletePending;                                  // ntddk wdm nthal
    BOOLEAN Directory;                                      // ntddk wdm nthal
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;   // ntddk wdm nthal
                                                            // ntddk wdm nthal
typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {                 // ntddk wdm nthal
    LARGE_INTEGER CurrentByteOffset;                        // ntddk wdm nthal
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;   // ntddk wdm nthal
                                                            // ntddk wdm nthal
typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {                // ntddk nthal
    ULONG AlignmentRequirement;                             // ntddk nthal
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION; // ntddk nthal
                                                            // ntddk nthal
typedef struct _FILE_NAME_INFORMATION {                     // ntddk
    ULONG FileNameLength;                                   // ntddk
    WCHAR FileName[1];                                      // ntddk
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;           // ntddk
                                                            // ntddk
typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {                 // ntddk wdm nthal
    LARGE_INTEGER CreationTime;                                 // ntddk wdm nthal
    LARGE_INTEGER LastAccessTime;                               // ntddk wdm nthal
    LARGE_INTEGER LastWriteTime;                                // ntddk wdm nthal
    LARGE_INTEGER ChangeTime;                                   // ntddk wdm nthal
    LARGE_INTEGER AllocationSize;                               // ntddk wdm nthal
    LARGE_INTEGER EndOfFile;                                    // ntddk wdm nthal
    ULONG FileAttributes;                                       // ntddk wdm nthal
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;   // ntddk wdm nthal
                                                                // ntddk wdm nthal
typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {               // ntddk nthal
    ULONG FileAttributes;                                       // ntddk nthal
    ULONG ReparseTag;                                           // ntddk nthal
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;  // ntddk nthal
                                                                // ntddk nthal
typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;


typedef struct _FILE_COMPRESSION_INFORMATION {
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {                  // ntddk nthal
    BOOLEAN DeleteFile;                                         // ntddk nthal
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION; // ntddk nthal
                                                                // ntddk nthal
typedef struct _FILE_END_OF_FILE_INFORMATION {                  // ntddk nthal
    LARGE_INTEGER EndOfFile;                                    // ntddk nthal
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION; // ntddk nthal


NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(
    __in PCWSTR DosFileName,
    __out PUNICODE_STRING NtFileName,
    __out_opt PWSTR *FilePart,
    __reserved PVOID Reserved
    );
                                                                    // ntddk nthal                                           
typedef
VOID
(*PPS_APC_ROUTINE) (
    __in_opt PVOID ApcArgument1,
    __in_opt PVOID ApcArgument2,
    __in_opt PVOID ApcArgument3
    );
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueueApcThread (
    __in HANDLE ThreadHandle,
    __in PPS_APC_ROUTINE ApcRoutine,
    __in_opt PVOID ApcArgument1,
    __in_opt PVOID ApcArgument2,
    __in_opt PVOID ApcArgument3
    );

typedef USHORT RTL_ATOM, *PRTL_ATOM;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAddAtom (
    __in_bcount_opt(Length) PWSTR AtomName,
    __in ULONG Length,
    __out_opt PRTL_ATOM Atom
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtFindAtom (
    __in_bcount_opt(Length) PWSTR AtomName,
    __in ULONG Length,
    __out_opt PRTL_ATOM Atom
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDeleteAtom (
    __in RTL_ATOM Atom
    );

typedef enum _ATOM_INFORMATION_CLASS {
    AtomBasicInformation,
    AtomTableInformation
} ATOM_INFORMATION_CLASS;

typedef struct _ATOM_BASIC_INFORMATION {
    USHORT UsageCount;
    USHORT Flags;
    USHORT NameLength;
    WCHAR Name[ 1 ];
} ATOM_BASIC_INFORMATION, *PATOM_BASIC_INFORMATION;

typedef struct _ATOM_TABLE_INFORMATION {
    ULONG NumberOfAtoms;
    RTL_ATOM Atoms[ 1 ];
} ATOM_TABLE_INFORMATION, *PATOM_TABLE_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationAtom(
    __in RTL_ATOM Atom,
    __in ATOM_INFORMATION_CLASS AtomInformationClass,
    __out_bcount(AtomInformationLength) PVOID AtomInformation,
    __in ULONG AtomInformationLength,
    __out_opt PULONG ReturnLength
    );


typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;    


typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    MaxThreadInfoClass
    } THREADINFOCLASS;
// end_ntddk end_ntifs

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION;
typedef THREAD_BASIC_INFORMATION *PTHREAD_BASIC_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationThread (
    __in HANDLE ThreadHandle,
    __in THREADINFOCLASS ThreadInformationClass,
    __out PVOID ThreadInformation,
    __in ULONG ThreadInformationLength,
    __out_opt PULONG ReturnLength
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThread (
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt PCLIENT_ID ClientId
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDelayExecution (
    __in BOOLEAN Alertable,
    __in PLARGE_INTEGER DelayInterval
    );
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSuspendThread (
    __in HANDLE ThreadHandle,
    __out_opt PULONG PreviousSuspendCount
    );

NTSYSCALLAPI
NTSTATUS
NTAPI
NtResumeThread (
    __in HANDLE ThreadHandle,
    __out_opt PULONG PreviousSuspendCount
    );    
    
NTSYSCALLAPI
NTSTATUS
NTAPI
NtWaitForSingleObject (
    __in HANDLE Handle,
    __in BOOLEAN Alertable,
    __in_opt PLARGE_INTEGER Timeout
    );
    
    
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
#if DEVL
    ,MemoryWorkingSetInformation
#endif
    ,MemoryMappedFilenameInformation
    ,MemoryRegionInformation
    ,MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryVirtualMemory (
    __in HANDLE ProcessHandle,
    __in PVOID BaseAddress,
    __in MEMORY_INFORMATION_CLASS MemoryInformationClass,
    __out PVOID MemoryInformation,
    __in SIZE_T MemoryInformationLength,
    __out_opt PSIZE_T ReturnLength
    );
 
typedef struct _LDR_DATA_TABLE_ENTRY                         
{                                                            
        LIST_ENTRY InLoadOrderLinks;                 
        LIST_ENTRY InMemoryOrderLinks;               
        LIST_ENTRY InInitializationOrderLinks;       
        PVOID        DllBase;                                
        PVOID        EntryPoint;                             
        ULONG32      SizeOfImage;                            
        UNICODE_STRING FullDllName;                  
        UNICODE_STRING BaseDllName;     
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
    
NTSTATUS
NTAPI
LdrFindEntryForAddress(
    IN PVOID Address,
    OUT PVOID *TableEntry //PLDR_DATA_TABLE_ENTRY *TableEntry
    );
#endif

