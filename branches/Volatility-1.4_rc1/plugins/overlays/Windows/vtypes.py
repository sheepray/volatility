# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

## The following is a conversion of basic C99 types to python struct
## format strings. NOTE: since volatility is analysing images which
## are not necessarily the same bit size as the currently running
## platform you may not use platform specific format specifiers here
## like l or L - you must use i or I.
x86_native_types_32bit = { \
    'int' : [4, 'i'], \
    'long': [4, 'i'], \
    'unsigned long' : [4, 'I'], \
    'unsigned int' : [4, 'I'], \
    'address' : [4, 'I'], \
    'char' : [1, 'c'], \
    'unsigned char' : [1, 'B'], \
    'unsigned short int' : [2, 'H'], \
    'unsigned short' : [2, 'H'], \
    'unsigned be short' : [2, '>H'], \
    'short' : [2, 'h'], \
    'long long' : [8, 'q'], \
    'unsigned long long' : [8, 'Q'], \
    }

xpsp2types = { \
  '_LIST_ENTRY' : [ 0x8, { \
    'Flink' : [ 0x0, ['pointer', ['_LIST_ENTRY']]], \
    'Blink' : [ 0x4, ['pointer', ['_LIST_ENTRY']]], \
} ], \
  '_KUSER_SHARED_DATA' : [ 0x338, { \
    'SystemTime' : [ 0x14, ['WinTimeStamp', dict(is_utc=True)]], \
    'TimeZoneBias' : [ 0x20, ['WinTimeStamp']], \
    'SuiteMask' : [ 0x2d0, ['unsigned long']], \
    'NumberOfPhysicalPages' : [ 0x2e8, ['unsigned long']], \
} ], \
  '_LARGE_INTEGER' : [ 0x8, { \
    'LowPart' : [ 0x0, ['unsigned long']], \
    'HighPart' : [ 0x4, ['long']], \
} ], \
  '_KSYSTEM_TIME' : [ 0xc, { \
    'LowPart' : [ 0x0, ['unsigned long']], \
    'High1Time' : [ 0x4, ['long']], \
} ], \
  '_EPROCESS' : [ 0x260, { \
    'Pcb' : [ 0x0, ['_KPROCESS']], \
    'CreateTime' : [ 0x70, ['_LARGE_INTEGER']], \
    'ExitTime' : [ 0x78, ['_LARGE_INTEGER']], \
    'UniqueProcessId' : [ 0x84, ['pointer', ['void']]], \
    'ActiveProcessLinks' : [ 0x88, ['_LIST_ENTRY']], \
    'VirtualSize' : [ 0xb0, ['unsigned long']], \
    'ObjectTable' : [ 0xc4, ['pointer', ['_HANDLE_TABLE']]], \
    'WorkingSetLock' : [ 0xcc, ['_FAST_MUTEX']], \
    'AddressCreationLock' : [ 0xf0, ['_FAST_MUTEX']], \
    'VadRoot' : [ 0x11c, ['pointer', ['void']]], \
    'InheritedFromUniqueProcessId' : [ 0x14c, ['pointer', ['void']]], \
    'ImageFileName' : [ 0x174, ['array', 16,['unsigned char']]], \
    'ThreadListHead' : [ 0x190, ['_LIST_ENTRY']], \
    'ActiveThreads' : [ 0x1a0, ['unsigned long']], \
    'Peb' : [ 0x1b0, ['pointer', ['_PEB']]], \
    'ExitStatus' : [ 0x24c, ['long']], \
} ], \
  '_KPROCESS' : [ 0x6c, { \
    'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
    'DirectoryTableBase' : [ 0x18, ['unsigned long']], \
} ], \
  '_PEB' : [ 0x210, { \
    'ImageBaseAddress' : [ 0x8, ['pointer', ['void']]], \
    'Ldr' : [ 0xc, ['pointer', ['_PEB_LDR_DATA']]], \
    'ProcessParameters' : [ 0x10, ['pointer', ['_RTL_USER_PROCESS_PARAMETERS']]], \
    'NumberOfProcessors' : [ 0x64, ['unsigned long']], \
    'OSMajorVersion' : [ 0xa4, ['unsigned long']], \
    'OSMinorVersion' : [ 0xa8, ['unsigned long']], \
    'OSBuildNumber' : [ 0xac, ['unsigned short']], \
    'CSDVersion' : [ 0x1f0, ['_UNICODE_STRING']], \
} ], \
  '_RTL_USER_PROCESS_PARAMETERS' : [ 0x290, { \
    'CommandLine' : [ 0x40, ['_UNICODE_STRING']], \
} ], \
  '_UNICODE_STRING' : [ 0x8, { \
    'Length' : [ 0x0, ['unsigned short']], \
    'Buffer' : [ 0x4, ['pointer', ['unsigned short']]], \
} ], \
  '_PEB_LDR_DATA' : [ 0x28, { \
    'InLoadOrderModuleList' : [ 0xc, ['_LIST_ENTRY']], \
} ], \
  '_ADDRESS_OBJECT' : [ 0x68, { \
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]], \
    'LocalIpAddress' : [ 0x0c, ['unsigned long']], \
    'LocalPort' : [ 0x30, ['unsigned short']], \
    'Protocol'  : [ 0x32, ['unsigned short']], \
    'Pid' : [ 0x148, ['unsigned long']], \
    'CreateTime' : [ 0x158, ['_LARGE_INTEGER']], \
} ], \
  '_TCPT_OBJECT' : [ 0x20, { \
  'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]], \
  'RemoteIpAddress' : [ 0xc, ['unsigned long']], \
  'LocalIpAddress' : [ 0x10, ['unsigned long']], \
  'RemotePort' : [ 0x14, ['unsigned short']], \
  'LocalPort' : [ 0x16, ['unsigned short']], \
  'Pid' : [ 0x18, ['unsigned long']], \
} ], \
  '_HANDLE_TABLE' : [ 0x44, { \
    'TableCode' : [ 0x0, ['unsigned long']], \
    'UniqueProcessId' : [ 0x8, ['pointer', ['void']]], \
    'HandleTableList' : [ 0x1c, ['_LIST_ENTRY']], \
    'HandleCount' : [ 0x3c, ['long']], \
} ], \
  '_HANDLE_TABLE_ENTRY' : [ 0x8, { \
    'Object' : [ 0x0, ['pointer', ['void']]], \
} ], \
'_OBJECT_HEADER' : [ 0x18, {
    'PointerCount' : [ 0x0, ['int']],
    'HandleCount' : [ 0x4, ['int']],
    'Type' : [ 0x8, ['pointer', ['_OBJECT_TYPE']]],
    'NameInfoOffset' : [ 0x0c, ['unsigned char']],
    'HandleInfoOffset' : [ 0xd, ['unsigned char']],    
    'QuotaInfoOffset' : [ 0xe, ['unsigned char']],
    'Flags' : [ 0xf, ['unsigned char']],
    'ObjectCreateInfo' : [ 0x10, ['pointer', ['_OBJECT_TYPE']]],
    'SecurityDescriptor' : [ 0x14, ['pointer', ['_OBJECT_TYPE']]],
    'Body': [ 0x18, ['_QUAD']],
    } ], \
    '_OBJECT_TYPE_INITIALIZER' : [ 0x4c, {
        'Length' : [ 0x0, ['unsigned short']],
        'UseDefaultObject' : [ 0x2, ['unsigned char']],
        'CaseInsensitive' : [ 0x3, ['unsigned char']],
        'InvalidAttributes' : [ 0x4, ['unsigned long']],
        'GenericMapping' : [ 0x8, ['_GENERIC_MAPPING']],
        'ValidAccessMask' : [ 0x18, ['unsigned long']],
        'SecurityRequired' : [ 0x1c, ['unsigned char']],
        'MaintainHandleCount' : [ 0x1d, ['unsigned char']],
        'MaintainTypeList' : [ 0x1e, ['unsigned char']],
        'PoolType' : [ 0x20, ['unsigned long']],
        'DefaultPagedPoolCharge' : [ 0x24, ['unsigned long']],
        'DefaultNonPagedPoolCharge' : [ 0x28, ['unsigned long']],
        'DumpProcedure' : [ 0x2c, ['pointer', ['void']]],
        'OpenProcedure' : [ 0x30, ['pointer', ['void']]],
        'CloseProcedure' : [ 0x34, ['pointer', ['void']]],
        'DeleteProcedure' : [ 0x38, ['pointer', ['void']]],
        'ParseProcedure' : [ 0x3c, ['pointer', ['void']]],
        'SecurityProcedure' : [ 0x40, ['pointer', ['void']]],
        'QueryNameProcedure' : [ 0x44, ['pointer', ['void']]],
        'OkayToCloseProcedure' : [ 0x48, ['pointer', ['void']]],
    } ],
'_OBJECT_TYPE' : [ 0x190, { \
            'Mutex' : [0x0, ['_ERESOURCE']],
            'TypeList' : [0x38, ['_LIST_ENTRY']],
            'Name' : [ 0x40, ['_UNICODE_STRING']], 
            'DefaultObject' : [ 0x48, ['pointer', ['void']]],
            'Index' : [ 0x4c, ['unsigned long']],
            'TotalNumberOfObjects' : [ 0x50, ['unsigned long']],
            'TotalNumberOfHandles' : [ 0x54, ['unsigned long']],
            'HighWaterNumberOfObjects' : [ 0x58, ['unsigned long']],
            'HighWaterNumberOfHandles' : [ 0x5c, ['unsigned long']],
            'TypeInfo' : [ 0x60, ['_OBJECT_TYPE_INITIALIZER']],
            'Key' : [ 0xac, ['array', 4, ['unsigned char']]],
            'ObjectLocks' : [ 0xb0, ['array', 4, ['_ERESOURCE']]],
} ], \
'_FILE_OBJECT' : [ 0x70, {
    'Type' : [ 0x0, ['unsigned short']],
    'Size' : [ 0x2, ['unsigned short']],
    'DeviceObject' : [ 0x4, ['pointer', ['_DEVICE_OBJECT']]],
    'Vpb' : [ 0x8, ['pointer', ['_VPB']]],
    'FsContext' : [ 0xc, ['pointer', ['void']]],
    'FsContext2' : [ 0x10, ['pointer', ['void']]],      
    'SectionObjectPointer' : [ 0x14, ['pointer', ['_SECTION_OBJECT_POINTERS']]],
    'PrivateCacheMap' : [ 0x18, ['pointer', ['void']]],
    'FinalStatus' : [ 0x1c, ['unsigned long']],
    'RelatedFileObject' : [ 0x20, ['pointer', ['_FILE_OBJECT']]],
    'LockOperation' : [ 0x24, ['unsigned char']],
    'DeletePending' : [ 0x25, ['unsigned char']],
    'ReadAccess' : [ 0x26, ['unsigned char']],
    'WriteAccess' : [ 0x27, ['unsigned char']],
    'DeleteAccess' : [ 0x28, ['unsigned char']],
    'SharedRead' : [ 0x29, ['unsigned char']],
    'SharedWrite' : [ 0x2a, ['unsigned char']],
    'SharedDelete' : [ 0x2b, ['unsigned char']],
    'Flags' : [ 0x2c, ['unsigned long']],
    'FileName' : [ 0x30, ['_UNICODE_STRING']],
    'CurrentByteOffset' : [ 0x38, ['_LARGE_INTEGER']],
    'Waiters' : [ 0x40, ['unsigned long']],
    'Busy' : [ 0x44, ['unsigned long']],
    'LastLock' : [ 0x48, ['pointer', ['void']]],
    'Lock' : [ 0x4c, ['_KEVENT']],
    'Event' : [ 0x5c, ['_KEVENT']],
    'CompletionContext' : [ 0x6c, ['pointer', ['_IO_COMPLETION_CONTEXT']]],
    } ],
'_KPCR' : [ 0xd70, {
    'NtTib' : [ 0x0, ['_NT_TIB']],
    'SelfPcr' : [ 0x1c, ['pointer', ['_KPCR']]],
    'Prcb' : [ 0x20, ['pointer', ['_KPRCB']]],
    'Irql' : [ 0x24, ['unsigned char']],
    'IRR' : [ 0x28, ['unsigned long']],
    'IrrActive' : [ 0x2c, ['unsigned long']],
    'IDR' : [ 0x30, ['unsigned long']],
    'KdVersionBlock' : [ 0x34, ['pointer', ['void']]],
    'IDT' : [ 0x38, ['pointer', ['_KIDTENTRY']]],
    'GDT' : [ 0x3c, ['pointer', ['_KGDTENTRY']]],
    'TSS' : [ 0x40, ['pointer', ['_KTSS']]],
    'MajorVersion' : [ 0x44, ['unsigned short']],
    'MinorVersion' : [ 0x46, ['unsigned short']],
    'SetMember' : [ 0x48, ['unsigned long']],
    'StallScaleFactor' : [ 0x4c, ['unsigned long']],
    'DebugActive' : [ 0x50, ['unsigned char']],
    'Number' : [ 0x51, ['unsigned char']],
    'Spare0' : [ 0x52, ['unsigned char']],
    'SecondLevelCacheAssociativity' : [ 0x53, ['unsigned char']],
    'VdmAlert' : [ 0x54, ['unsigned long']],
    'KernelReserved' : [ 0x58, ['array', 14, ['unsigned long']]],
    'SecondLevelCacheSize' : [ 0x90, ['unsigned long']],
    'HalReserved' : [ 0x94, ['array', 16, ['unsigned long']]],
    'InterruptMode' : [ 0xd4, ['unsigned long']],
    'Spare1' : [ 0xd8, ['unsigned char']],
    'KernelReserved2' : [ 0xdc, ['array', 17, ['unsigned long']]],
    'PrcbData' : [ 0x120, ['_KPRCB']],
} ], \
  '_KPRCB' : [ 0xc50, {
    'MinorVersion' : [ 0x0, ['unsigned short']],
    'MajorVersion' : [ 0x2, ['unsigned short']],
    'CurrentThread' : [ 0x4, ['pointer', ['_KTHREAD']]],
    'NextThread' : [ 0x8, ['pointer', ['_KTHREAD']]],
    'IdleThread' : [ 0xc, ['pointer', ['_KTHREAD']]],
    'Number' : [ 0x10, ['unsigned char']],
    'Reserved' : [ 0x11, ['unsigned char']],
    'BuildType' : [ 0x12, ['unsigned short']],
    'SetMember' : [ 0x14, ['unsigned long']],
    'CpuType' : [ 0x18, ['unsigned char']],
    'CpuID' : [ 0x19, ['unsigned char']],
    'CpuStep' : [ 0x1a, ['unsigned short']],
    'ProcessorState' : [ 0x1c, ['_KPROCESSOR_STATE']],
    'KernelReserved' : [ 0x33c, ['array', 16, ['unsigned long']]],
    'HalReserved' : [ 0x37c, ['array', 16, ['unsigned long']]],
    'PrcbPad0' : [ 0x3bc, ['array', 92, ['unsigned char']]],
    'LockQueue' : [ 0x418, ['array', 16, ['_KSPIN_LOCK_QUEUE']]],
    'PrcbPad1' : [ 0x498, ['array', 8, ['unsigned char']]],
    'NpxThread' : [ 0x4a0, ['pointer', ['_KTHREAD']]],
    'InterruptCount' : [ 0x4a4, ['unsigned long']],
    'KernelTime' : [ 0x4a8, ['unsigned long']],
    'UserTime' : [ 0x4ac, ['unsigned long']],
    'DpcTime' : [ 0x4b0, ['unsigned long']],
    'DebugDpcTime' : [ 0x4b4, ['unsigned long']],
    'InterruptTime' : [ 0x4b8, ['unsigned long']],
    'AdjustDpcThreshold' : [ 0x4bc, ['unsigned long']],
    'PageColor' : [ 0x4c0, ['unsigned long']],
    'SkipTick' : [ 0x4c4, ['unsigned long']],
    'MultiThreadSetBusy' : [ 0x4c8, ['unsigned char']],
    'Spare2' : [ 0x4c9, ['array', 3, ['unsigned char']]],
    'ParentNode' : [ 0x4cc, ['pointer', ['_KNODE']]],
    'MultiThreadProcessorSet' : [ 0x4d0, ['unsigned long']],
    'MultiThreadSetMaster' : [ 0x4d4, ['pointer', ['_KPRCB']]],
    'ThreadStartCount' : [ 0x4d8, ['array', 2, ['unsigned long']]],
    'CcFastReadNoWait' : [ 0x4e0, ['unsigned long']],
    'CcFastReadWait' : [ 0x4e4, ['unsigned long']],
    'CcFastReadNotPossible' : [ 0x4e8, ['unsigned long']],
    'CcCopyReadNoWait' : [ 0x4ec, ['unsigned long']],
    'CcCopyReadWait' : [ 0x4f0, ['unsigned long']],
    'CcCopyReadNoWaitMiss' : [ 0x4f4, ['unsigned long']],
    'KeAlignmentFixupCount' : [ 0x4f8, ['unsigned long']],
    'KeContextSwitches' : [ 0x4fc, ['unsigned long']],
    'KeDcacheFlushCount' : [ 0x500, ['unsigned long']],
    'KeExceptionDispatchCount' : [ 0x504, ['unsigned long']],
    'KeFirstLevelTbFills' : [ 0x508, ['unsigned long']],
    'KeFloatingEmulationCount' : [ 0x50c, ['unsigned long']],
    'KeIcacheFlushCount' : [ 0x510, ['unsigned long']],
    'KeSecondLevelTbFills' : [ 0x514, ['unsigned long']],
    'KeSystemCalls' : [ 0x518, ['unsigned long']],
    'SpareCounter0' : [ 0x51c, ['array', 1, ['unsigned long']]],
    'PPLookasideList' : [ 0x520, ['array', 16, ['_PP_LOOKASIDE_LIST']]],
    'PPNPagedLookasideList' : [ 0x5a0, ['array', 32, ['_PP_LOOKASIDE_LIST']]],
    'PPPagedLookasideList' : [ 0x6a0, ['array', 32, ['_PP_LOOKASIDE_LIST']]],
    'PacketBarrier' : [ 0x7a0, ['unsigned long']],
    'ReverseStall' : [ 0x7a4, ['unsigned long']],
    'IpiFrame' : [ 0x7a8, ['pointer', ['void']]],
    'PrcbPad2' : [ 0x7ac, ['array', 52, ['unsigned char']]],
    'CurrentPacket' : [ 0x7e0, ['array', 3, ['pointer', ['void']]]],
    'TargetSet' : [ 0x7ec, ['unsigned long']],
    'WorkerRoutine' : [ 0x7f0, ['pointer', ['void']]],
    'IpiFrozen' : [ 0x7f4, ['unsigned long']],
    'PrcbPad3' : [ 0x7f8, ['array', 40, ['unsigned char']]],
    'RequestSummary' : [ 0x820, ['unsigned long']],
    'SignalDone' : [ 0x824, ['pointer', ['_KPRCB']]],
    'PrcbPad4' : [ 0x828, ['array', 56, ['unsigned char']]],
    'DpcListHead' : [ 0x860, ['_LIST_ENTRY']],
    'DpcStack' : [ 0x868, ['pointer', ['void']]],
    'DpcCount' : [ 0x86c, ['unsigned long']],
    'DpcQueueDepth' : [ 0x870, ['unsigned long']],
    'DpcRoutineActive' : [ 0x874, ['unsigned long']],
    'DpcInterruptRequested' : [ 0x878, ['unsigned long']],
    'DpcLastCount' : [ 0x87c, ['unsigned long']],
    'DpcRequestRate' : [ 0x880, ['unsigned long']],
    'MaximumDpcQueueDepth' : [ 0x884, ['unsigned long']],
    'MinimumDpcRate' : [ 0x888, ['unsigned long']],
    'QuantumEnd' : [ 0x88c, ['unsigned long']],
    'PrcbPad5' : [ 0x890, ['array', 16, ['unsigned char']]],
    'DpcLock' : [ 0x8a0, ['unsigned long']],
    'PrcbPad6' : [ 0x8a4, ['array', 28, ['unsigned char']]],
    'CallDpc' : [ 0x8c0, ['_KDPC']],
    'ChainedInterruptList' : [ 0x8e0, ['pointer', ['void']]],
    'LookasideIrpFloat' : [ 0x8e4, ['long']],
    'SpareFields0' : [ 0x8e8, ['array', 6, ['unsigned long']]],
    'VendorString' : [ 0x900, ['array', 13, ['unsigned char']]],
    'InitialApicId' : [ 0x90d, ['unsigned char']],
    'LogicalProcessorsPerPhysicalProcessor' : [ 0x90e, ['unsigned char']],
    'MHz' : [ 0x910, ['unsigned long']],
    'FeatureBits' : [ 0x914, ['unsigned long']],
    'UpdateSignature' : [ 0x918, ['_LARGE_INTEGER']],
    'NpxSaveArea' : [ 0x920, ['_FX_SAVE_AREA']],
    'PowerState' : [ 0xb30, ['_PROCESSOR_POWER_STATE']],
} ], \
  '_KDDEBUGGER_DATA32' : [ 0x44, { \
  'PsLoadedModuleList' : [ 0x70, ['pointer', ['void']]], \
  'PsActiveProcessHead' : [ 0x78, ['pointer', ['void']]], \
} ], \
  '_KDDEBUGGER_DATA64' : [ 0x44, { \
  'PsLoadedModuleList' : [ 0x48, ['pointer', ['void']]], \
  'PsActiveProcessHead' : [ 0x50, ['pointer', ['void']]], \
  'MmPfnDatabase' : [ 0xC0, ['unsigned long']], \
} ], \
'_DBGKD_GET_VERSION64' : [  0x2a, { \
  'DebuggerDataList' : [ 0x20, ['unsigned long']], \
} ], \
'_MMVAD_LONG' : [  0x34, { \
  'StartingVpn' : [ 0x0, ['unsigned long']], \
  'EndingVpn' : [ 0x4, ['unsigned long']], \
  'Parent' : [ 0x8, ['pointer', ['_MMVAD']]], \
  'LeftChild' : [ 0xc, ['pointer', ['_MMVAD']]], \
  'RightChild' : [ 0x10, ['pointer', ['_MMVAD']]], \
  'Flags' : [ 0x14, ['unsigned long']], \
  'ControlArea' : [ 0x18, ['pointer', ['_CONTROL_AREA']]], \
  'FirstPrototypePte' : [ 0x1c, ['pointer', ['_MMPTE']]], \
  'LastContiguousPte' : [ 0x20, ['pointer', ['_MMPTE']]], \
  'Flags2' : [ 0x24, ['unsigned long']], \
  'u3' : [ 0x28, ['__unnamed']], \
  'u4' : [ 0x30, ['__unnamed']], \
} ], \
'_MMVAD' : [  0x28, { \
  'StartingVpn' : [ 0x0, ['unsigned long']], \
  'EndingVpn' : [ 0x4, ['unsigned long']], \
  'Parent' : [ 0x8, ['pointer', ['_MMVAD']]], \
  'LeftChild' : [ 0xc, ['pointer', ['_MMVAD']]], \
  'RightChild' : [ 0x10, ['pointer', ['_MMVAD']]], \
  'Flags' : [ 0x14, ['unsigned long']], \
  'ControlArea' : [ 0x18, ['pointer', ['_CONTROL_AREA']]], \
  'FirstPrototypePte' : [ 0x1c, ['pointer', ['_MMPTE']]], \
  'LastContiguousPte' : [ 0x20, ['pointer', ['_MMPTE']]], \
  'Flags2' : [ 0x24, ['unsigned long']], \
} ], \
'_MMVAD_SHORT' : [  0x18, { \
  'StartingVpn' : [ 0x0, ['unsigned long']], \
  'EndingVpn' : [ 0x4, ['unsigned long']], \
  'Parent' : [ 0x8, ['pointer', ['_MMVAD']]], \
  'LeftChild' : [ 0xc, ['pointer', ['_MMVAD']]], \
  'RightChild' : [ 0x10, ['pointer', ['_MMVAD']]], \
  'Flags' : [ 0x14, ['unsigned long']], \
} ], \
'_CONTROL_AREA' : [  0x30, { \
  'Segment' : [ 0x0, ['pointer', ['_SEGMENT']]], \
  'DereferenceList' : [ 0x4, ['_LIST_ENTRY']], \
  'NumberOfSectionReferences' : [ 0xc, ['unsigned long']], \
  'NumberOfPfnReferences' : [ 0x10, ['unsigned long']], \
  'NumberOfMappedViews' : [ 0x14, ['unsigned long']], \
  'NumberOfSubsections' : [ 0x18, ['unsigned short']], \
  'FlushInProgressCount' : [ 0x1a, ['unsigned short']], \
  'NumberOfUserReferences' : [ 0x1c, ['unsigned long']], \
  'Flags' : [ 0x20, ['unsigned long']], \
  'FilePointer' : [ 0x24, ['pointer', ['_FILE_OBJECT']]], \
  'WaitingForDeletion' : [ 0x28, ['pointer', ['_EVENT_COUNTER']]], \
  'ModifiedWriteCount' : [ 0x2c, ['unsigned short']], \
  'NumberOfSystemCacheViews' : [ 0x2e, ['unsigned short']], \
} ], \
'_POOL_HEADER' : [  0x8, { \
  'Ulong1' : [ 0x0, ['unsigned long']], \
  'BlockSize': [ 0x2, ['unsigned short']], \
  'PoolType': [ 0x2, ['unsigned short']], \
  'ProcessBilled' : [ 0x4, ['pointer', ['_EPROCESS']]], \
  'PoolTag' : [ 0x4, ['unsigned long']], \
  'AllocatorBackTraceIndex' : [ 0x4, ['unsigned short']], \
  'PoolTagHash' : [ 0x6, ['unsigned short']], \
} ], \
'_FAST_MUTEX' : [  0x20, { \
  'Event' : [ 0xc, ['_KEVENT']], \
} ], \
'_KEVENT' : [  0x10, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
} ], \
'_DISPATCHER_HEADER' : [  0x10, { 
  'Type' : [ 0x0, ['unsigned char']], 
  'Absolute' : [ 0x1, ['unsigned char']],
  'Size' : [ 0x2, ['unsigned char']], 
  'Inserted' : [0x3, ['unsigned char']],
  'SignalState' : [ 0x4, ['long']],
  'WaitListHead' : [ 0x8, ['_LIST_ENTRY']],
} ], \
'_ETHREAD' : [  0x258, { \
  'Tcb' : [ 0x0, ['_KTHREAD']], \
  'Cid' : [ 0x1ec, ['_CLIENT_ID']], \
  'LpcReplySemaphore' : [ 0x1f4, ['_KSEMAPHORE']], \
  'CreateTime' : [ 0x1c0, ['ThreadCreateTimeStamp']],  # Note, this is not a WinTimeStamp, it needs to be >> 3
  'ExitTime' : [ 0x1c8, ['WinTimeStamp']], \
  'ThreadsProcess' : [ 0x220, ['pointer', ['_EPROCESS']]], \
  'StartAddress' : [ 0x224, ['pointer', ['void']]], \
} ], \
'_CLIENT_ID' : [  0x8, { \
  'UniqueProcess' : [ 0x0, ['pointer', ['void']]], \
  'UniqueThread' : [ 0x4, ['pointer', ['void']]], \
} ], \
'_KTHREAD' : [  0x1c0, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
  'Timer' : [ 0xf0, ['_KTIMER']], \
  'SuspendSemaphore' : [ 0x19c, ['_KSEMAPHORE']], \
} ], \
'_KTIMER' : [  0x28, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
} ], \
'_KSEMAPHORE' : [  0x14, { \
  'Header' : [ 0x0, ['_DISPATCHER_HEADER']], \
} ], \
'_PHYSICAL_MEMORY_RUN' : [ 0x8, { \
  'BasePage' : [ 0x0, ['unsigned long']], \
  'PageCount' : [ 0x4, ['unsigned long']], \
} ], \
'_PHYSICAL_MEMORY_DESCRIPTOR' : [ 0x10, { \
  'NumberOfRuns' : [ 0x0, ['unsigned long']], \
  'NumberOfPages' : [ 0x4, ['unsigned long']], \
  'Run' : [ 0x8, ['array', 1,['_PHYSICAL_MEMORY_RUN']]], \
} ], \
'_DMP_HEADER' : [ 0x1000, { \
  'Signature' : [ 0x0, ['array', 4,['unsigned char']]], \
  'ValidDump' : [ 0x4, ['array', 4,['unsigned char']]], \
  'MajorVersion' : [ 0x8, ['unsigned long']], \
  'MinorVersion' : [ 0xc, ['unsigned long']], \
  'DirectoryTableBase' : [ 0x10, ['unsigned long']], \
  'PfnDataBase' : [ 0x14, ['unsigned long']], \
  'PsLoadedModuleList' : [ 0x18, ['unsigned long']], \
  'PsActiveProcessHead' : [ 0x1c, ['unsigned long']], \
  'MachineImageType' : [ 0x20, ['unsigned long']], \
  'NumberProcessors' : [ 0x24, ['unsigned long']], \
  'BugCheckCode' : [ 0x28, ['unsigned long']], \
  'BugCheckCodeParameter' : [ 0x2c, ['array', 4,['unsigned long']]], \
  'VersionUser' : [ 0x3c, ['array', 32,['unsigned char']]], \
  'PaeEnabled' : [ 0x5c, ['unsigned char']], \
  'KdSecondaryVersion' : [ 0x5d, ['unsigned char']], \
  'VersionUser' : [ 0x5e, ['array', 2,['unsigned char']]], \
  'KdDebuggerDataBlock' : [ 0x60, ['unsigned long']], \
  'PhysicalMemoryBlockBuffer' : [ 0x64, ['_PHYSICAL_MEMORY_DESCRIPTOR']], \
  'ContextRecord' : [ 0x320, ['array', 1200,['unsigned char']]], \
  'Exception' : [ 0x7d0, ['_EXCEPTION_RECORD32']], \
  'Comment' : [ 0x820, ['array', 128,['unsigned char']]], \
  'DumpType' : [ 0xf88, ['unsigned long']], \
  'MiniDumpFields' : [ 0xf8c, ['unsigned long']], \
  'SecondaryDataState' : [ 0xf90, ['unsigned long']], \
  'ProductType' : [ 0xf94, ['unsigned long']], \
  'SuiteMask' : [ 0xf98, ['unsigned long']], \
  'WriterStatus' : [ 0xf9c, ['unsigned long']], \
  'RequiredDumpSpace' : [ 0xfa0, ['unsigned __int64']], \
  'SystemUpTime' : [ 0xfb8, ['unsigned __int64']], \
  'SystemTime' : [ 0xfc0, ['unsigned __int64']], \
  'reserved3' : [ 0xfc8, ['array', 56,['unsigned char']]], \
} ], \
  '_TEB' : [ 0xfb8, { \
    'ProcessEnvironmentBlock' : [ 0x30, ['pointer', ['_PEB']]], \
} ], \
  '_KPROCESSOR_STATE' : [ 0x320, { \
    'SpecialRegisters' : [ 0x2cc, ['_KSPECIAL_REGISTERS']], \
} ], \
  '_KSPECIAL_REGISTERS' : [ 0x54, { \
    'Cr0' : [ 0x0, ['unsigned long']], \
    'Cr3' : [ 0x8, ['unsigned long']], \
    'Cr4' : [ 0xc, ['unsigned long']], \
    'Gdtr' : [ 0x28, ['_DESCRIPTOR']], \
} ], \
    '_DESCRIPTOR' : [ 0x8, { \
    'Pad' : [ 0x0, ['unsigned short']], \
    'Limit' : [ 0x2, ['unsigned short']], \
    'Base' : [ 0x4, ['unsigned long']], \
} ], \
'_CM_KEY_BODY' : [  0x44, { \
  'Type' : [ 0x0, ['unsigned long']], \
  'KeyControlBlock' : [ 0x4, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]], \
} ], \
'_CM_KEY_CONTROL_BLOCK' : [  0x48, { \
  'ParentKcb' : [ 0x18, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]], \
  'NameBlock' : [ 0x1c, ['pointer', ['_CM_NAME_CONTROL_BLOCK']]], \
  'KcbLastWriteTime' : [ 0x38, ['_LARGE_INTEGER']], \
} ], \
'_CM_NAME_CONTROL_BLOCK' : [  0x10, { \
  'NameLength' : [ 0xc, ['unsigned short']], \
  'Name' : [ 0xe, ['String', dict(length=lambda x: x.NameLength)]], \
} ], \
'_IMAGE_DOS_HEADER' : [  0x40, { \
  'e_lfanew' : [ 0x3c, ['long']], \
} ], \
'_IMAGE_NT_HEADERS' : [  0xf8, { \
  'FileHeader' : [ 0x4, ['_IMAGE_FILE_HEADER']], \
  'OptionalHeader' : [ 0x18, ['_IMAGE_OPTIONAL_HEADER']], \
} ], \
'_IMAGE_OPTIONAL_HEADER' : [  0xe0, { \
  'SectionAlignment' : [ 0x20, ['unsigned long']], \
  'FileAlignment' : [ 0x24, ['unsigned long']], \
  'SizeOfImage' : [ 0x38, ['unsigned long']], \
  'SizeOfHeaders' : [ 0x3c, ['unsigned long']], \
} ], \
'_IMAGE_FILE_HEADER' : [  0x14, { \
  'NumberOfSections' : [ 0x2, ['unsigned short']], \
  'SizeOfOptionalHeader' : [ 0x10, ['unsigned short']], \
} ], \
  '__misc' : [ 0x4, {
    'PhysicalAddress' : [ 0x0, ['unsigned long']],
    'VirtualSize' : [ 0x0, ['unsigned long']],
} ],
'_IMAGE_SECTION_HEADER' : [  0x28, { \
  'Name' : [ 0x0, ['array', 8,['unsigned char']]], \
  'Misc' : [ 0x8, ['__misc']],
  'VirtualAddress' : [ 0xc, ['unsigned long']], \
  'SizeOfRawData' : [ 0x10, ['unsigned long']], \
  'PointerToRawData' : [ 0x14, ['unsigned long']], \
} ], \
'_LDR_DATA_TABLE_ENTRY' : [ 0x50, { \
    'InLoadOrderLinks' : [ 0x0, ['_LIST_ENTRY']], \
    'InMemoryOrderLinks' : [ 0x8, ['_LIST_ENTRY']], \
    'InInitializationOrderLinks' : [ 0x10, ['_LIST_ENTRY']], \
    'DllBase' : [ 0x18, ['pointer', ['void']]], \
    'EntryPoint' : [ 0x1c, ['pointer', ['void']]], \
    'SizeOfImage' : [ 0x20, ['unsigned long']], \
    'FullDllName' : [ 0x24, ['_UNICODE_STRING']], \
    'BaseDllName' : [ 0x2c, ['_UNICODE_STRING']], \
} ], \

## These are registry related types
  '_CM_KEY_NODE' : [ 0x50, {
    'Signature' : [ 0x0, ['String', dict(length=2)]],
    'Flags' : [ 0x2, ['unsigned short']],
    'LastWriteTime' : [ 0x4, ['WinTimeStamp', {}]],
    'Spare' : [ 0xc, ['unsigned long']],
    'Parent' : [ 0x10, ['unsigned long']],
    'SubKeyCounts' : [ 0x14, ['array', 2, ['unsigned long']]],
    'SubKeyLists' : [ 0x1c, ['array', 2, ['unsigned long']]],
    'ValueList' : [ 0x24, ['_CHILD_LIST']],
    'ChildHiveReference' : [ 0x1c, ['_CM_KEY_REFERENCE']],
    'Security' : [ 0x2c, ['unsigned long']],
    'Class' : [ 0x30, ['unsigned long']],
    'MaxNameLen' : [ 0x34, ['unsigned long']],
    'MaxClassLen' : [ 0x38, ['unsigned long']],
    'MaxValueNameLen' : [ 0x3c, ['unsigned long']],
    'MaxValueDataLen' : [ 0x40, ['unsigned long']],
    'WorkVar' : [ 0x44, ['unsigned long']],
    'NameLength' : [ 0x48, ['unsigned short']],
    'ClassLength' : [ 0x4a, ['unsigned short']],
    'Name' : [ 0x4c, ['String', dict(length=lambda x: x.NameLength)]],
} ],
  '_CM_KEY_REFERENCE' : [ 0x8, {
    'KeyCell' : [ 0x0, ['unsigned long']],
    'KeyHive' : [ 0x4, ['pointer', ['_HHIVE']]],
} ],
  '_CHILD_LIST' : [ 0x8, {
    'Count' : [ 0x0, ['unsigned long']],
    'List' : [ 0x4, ['pointer', ['array', lambda x: x.Count,
                                 ['pointer', ['_CM_KEY_VALUE']]]]],
} ],
  '_CM_KEY_SECURITY' : [ 0x28, {
    'Signature' : [ 0x0, ['unsigned short']],
    'Reserved' : [ 0x2, ['unsigned short']],
    'Flink' : [ 0x4, ['unsigned long']],
    'Blink' : [ 0x8, ['unsigned long']],
    'ReferenceCount' : [ 0xc, ['unsigned long']],
    'DescriptorLength' : [ 0x10, ['unsigned long']],
    'Descriptor' : [ 0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
} ],
  '_SECURITY_DESCRIPTOR_RELATIVE' : [ 0x14, {
    'Revision' : [ 0x0, ['unsigned char']],
    'Sbz1' : [ 0x1, ['unsigned char']],
    'Control' : [ 0x2, ['unsigned short']],
    'Owner' : [ 0x4, ['unsigned long']],
    'Group' : [ 0x8, ['unsigned long']],
    'Sacl' : [ 0xc, ['unsigned long']],
    'Dacl' : [ 0x10, ['unsigned long']],
} ],
  '_CM_KEY_VALUE' : [ 0x18, {
    'Signature' : [ 0x0, ['String', dict(length=2)]],
    'NameLength' : [ 0x2, ['unsigned short']],
    'DataLength' : [ 0x4, ['unsigned long']],
    'Data' : [ 0x8, ['unsigned long']],
    'Type' : [ 0xc, ['unsigned long']],
    'Flags' : [ 0x10, ['unsigned short']],
    'Spare' : [ 0x12, ['unsigned short']],
    'Name' : [ 0x14, ['String', dict(length=lambda x: x.NameLength)]],
} ],
  '_CM_KEY_INDEX' : [ 0x8, {
    'Signature' : [ 0x0, ['String', dict(length=2)]],
    'Count' : [ 0x2, ['unsigned short']],
    'List' : [ 0x4, ['array', lambda x: 2*x.Count.v(), ['pointer', ['_CM_KEY_NODE']]]],
} ],
  '_CMHIVE' : [ 0x49c, {
    'Hive' : [ 0x0, ['_HHIVE']],
    'FileHandles' : [ 0x210, ['array', 3, ['pointer', ['void']]]],
    'NotifyList' : [ 0x21c, ['_LIST_ENTRY']],
    'HiveList' : [ 0x224, ['_LIST_ENTRY']],
    'HiveLock' : [ 0x22c, ['pointer', ['_FAST_MUTEX']]],
    'ViewLock' : [ 0x230, ['pointer', ['_FAST_MUTEX']]],
    'LRUViewListHead' : [ 0x234, ['_LIST_ENTRY']],
    'PinViewListHead' : [ 0x23c, ['_LIST_ENTRY']],
    'FileObject' : [ 0x244, ['pointer', ['_FILE_OBJECT']]],
    'FileFullPath' : [ 0x248, ['_UNICODE_STRING']],
    'FileUserName' : [ 0x250, ['_UNICODE_STRING']],
    'MappedViews' : [ 0x258, ['unsigned short']],
    'PinnedViews' : [ 0x25a, ['unsigned short']],
    'UseCount' : [ 0x25c, ['unsigned long']],
    'SecurityCount' : [ 0x260, ['unsigned long']],
    'SecurityCacheSize' : [ 0x264, ['unsigned long']],
    'SecurityHitHint' : [ 0x268, ['long']],
    'SecurityCache' : [ 0x26c, ['pointer', ['_CM_KEY_SECURITY_CACHE_ENTRY']]],
    'SecurityHash' : [ 0x270, ['array', 64, ['_LIST_ENTRY']]],
    'UnloadEvent' : [ 0x470, ['pointer', ['_KEVENT']]],
    'RootKcb' : [ 0x474, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
    'Frozen' : [ 0x478, ['unsigned char']],
    'UnloadWorkItem' : [ 0x47c, ['pointer', ['_WORK_QUEUE_ITEM']]],
    'GrowOnlyMode' : [ 0x480, ['unsigned char']],
    'GrowOffset' : [ 0x484, ['unsigned long']],
    'KcbConvertListHead' : [ 0x488, ['_LIST_ENTRY']],
    'KnodeConvertListHead' : [ 0x490, ['_LIST_ENTRY']],
    'CellRemapArray' : [ 0x498, ['pointer', ['_CM_CELL_REMAP_BLOCK']]],
} ],
  '_HHIVE' : [ 0x210, {
    'Signature' : [ 0x0, ['unsigned long']],
     'GetCellRoutine' : [ 0x4, ['pointer', ['void']]],
     'ReleaseCellRoutine' : [ 0x8, ['pointer', ['void']]],
     'Allocate' : [ 0xc, ['pointer', ['void']]],
     'Free' : [ 0x10, ['pointer', ['void']]],
     'FileSetSize' : [ 0x14, ['pointer', ['void']]],
     'FileWrite' : [ 0x18, ['pointer', ['void']]],
     'FileRead' : [ 0x1c, ['pointer', ['void']]],
     'FileFlush' : [ 0x20, ['pointer', ['void']]],
    'BaseBlock' : [ 0x24, ['pointer', ['_HBASE_BLOCK']]],
    'DirtyVector' : [ 0x28, ['_RTL_BITMAP']],
    'DirtyCount' : [ 0x30, ['unsigned long']],
    'DirtyAlloc' : [ 0x34, ['unsigned long']],
    'RealWrites' : [ 0x38, ['unsigned char']],
    'Cluster' : [ 0x3c, ['unsigned long']],
    'Flat' : [ 0x40, ['unsigned char']],
    'ReadOnly' : [ 0x41, ['unsigned char']],
    'Log' : [ 0x42, ['unsigned char']],
    'HiveFlags' : [ 0x44, ['unsigned long']],
    'LogSize' : [ 0x48, ['unsigned long']],
    'RefreshCount' : [ 0x4c, ['unsigned long']],
    'StorageTypeCount' : [ 0x50, ['unsigned long']],
    'Version' : [ 0x54, ['unsigned long']],
    'Storage' : [ 0x58, ['array', 2, ['_DUAL']]],
} ],
  '_HBASE_BLOCK' : [ 0x1000, {
    'Signature' : [ 0x0, ['unsigned long']],
    'Sequence1' : [ 0x4, ['unsigned long']],
    'Sequence2' : [ 0x8, ['unsigned long']],
    'TimeStamp' : [ 0xc, ['_LARGE_INTEGER']],
    'Major' : [ 0x14, ['unsigned long']],
    'Minor' : [ 0x18, ['unsigned long']],
    'Type' : [ 0x1c, ['unsigned long']],
    'Format' : [ 0x20, ['unsigned long']],
    'RootCell' : [ 0x24, ['unsigned long']],
    'Length' : [ 0x28, ['unsigned long']],
    'Cluster' : [ 0x2c, ['unsigned long']],
    'FileName' : [ 0x30, ['array', 64, ['unsigned char']]],
    'Reserved1' : [ 0x70, ['array', 99, ['unsigned long']]],
    'CheckSum' : [ 0x1fc, ['unsigned long']],
    'Reserved2' : [ 0x200, ['array', 894, ['unsigned long']]],
    'BootType' : [ 0xff8, ['unsigned long']],
    'BootRecover' : [ 0xffc, ['unsigned long']],
} ],
  '_DUAL' : [ 0xdc, {
    'Length' : [ 0x0, ['unsigned long']],
    'Map' : [ 0x4, ['pointer', ['_HMAP_DIRECTORY']]],
    'SmallDir' : [ 0x8, ['pointer', ['_HMAP_TABLE']]],
    'Guard' : [ 0xc, ['unsigned long']],
    'FreeDisplay' : [ 0x10, ['array', 24, ['_RTL_BITMAP']]],
    'FreeSummary' : [ 0xd0, ['unsigned long']],
    'FreeBins' : [ 0xd4, ['_LIST_ENTRY']],
} ],
  '_HMAP_DIRECTORY' : [ 0x1000, {
    'Directory' : [ 0x0, ['array', 1024, ['pointer', ['_HMAP_TABLE']]]],
} ],
  '_HMAP_TABLE' : [ 0x2000, {
    'Table' : [ 0x0, ['array', 512, ['_HMAP_ENTRY']]],
} ],
  '_HMAP_ENTRY' : [ 0x10, {
    'BlockAddress' : [ 0x0, ['unsigned long']],
    'BinAddress' : [ 0x4, ['unsigned long']],
    'CmView' : [ 0x8, ['pointer', ['_CM_VIEW_OF_FILE']]],
    'MemAlloc' : [ 0xc, ['unsigned long']],
} ],
  '_CM_KEY_SECURITY_CACHE_ENTRY' : [ 0x8, {
    'Cell' : [ 0x0, ['unsigned long']],
    'CachedSecurity' : [ 0x4, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
} ],
  '_CM_KEY_SECURITY_CACHE' : [ 0x28, {
    'Cell' : [ 0x0, ['unsigned long']],
    'ConvKey' : [ 0x4, ['unsigned long']],
    'List' : [ 0x8, ['_LIST_ENTRY']],
    'DescriptorLength' : [ 0x10, ['unsigned long']],
    'Descriptor' : [ 0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
} ],
  '_CM_CELL_REMAP_BLOCK' : [ 0x8, {
    'OldCell' : [ 0x0, ['unsigned long']],
    'NewCell' : [ 0x4, ['unsigned long']],
} ],
  '_LARGE_INTEGER' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['long']],
    'QuadPart' : [ 0x0, ['long long']],
} ],
    '_IMAGE_HIBER_HEADER' : [ 0xbc, { \
    'Signature' : [ 0x0, ['array', 4,['unsigned char']]], \
    'SystemTime' : [ 0x20, ['_LARGE_INTEGER']], \
    'FirstTablePage' : [ 0x58, ['unsigned long']], \
} ], \
    'MEMORY_RANGE_ARRAY_LINK' : [ 0x10, { \
    'NextTable' : [ 0x4, ['unsigned long']], \
    'EntryCount' : [ 0xc, ['unsigned long']], \
} ], \
    'MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, { \
    'StartPage' : [ 0x4, ['unsigned long']], \
    'EndPage' : [ 0x8, ['unsigned long']], \
} ], \
    '_MEMORY_RANGE_ARRAY' : [ 0x20, { \
    'MemArrayLink' : [ 0x0, ['MEMORY_RANGE_ARRAY_LINK']], \
    'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['MEMORY_RANGE_ARRAY_RANGE']]],
} ], \
  '_KGDTENTRY' : [  0x8 , { \
  'BaseLow' : [ 0x2 , ['unsigned short']], \
  'BaseMid' : [ 0x4, ['unsigned char']], \
  'BaseHigh' : [ 0x7, ['unsigned char']], \
} ], \
'_IMAGE_XPRESS_HEADER' : [  0x20 , { \
  'u09' : [ 0x9, ['unsigned char']], \
  'u0A' : [ 0xA, ['unsigned char']], \
  'u0B' : [ 0xB, ['unsigned char']], \
} ], \

## These types are for crash dumps
    '_PHYSICAL_MEMORY_RUN' : [ 0x8, { \
    'BasePage' : [ 0x0, ['unsigned long']], \
    'PageCount' : [ 0x4, ['unsigned long']], \
} ], \
    '_PHYSICAL_MEMORY_DESCRIPTOR' : [ 0x10, { \
    'NumberOfRuns' : [ 0x0, ['unsigned long']], \
    'NumberOfPages' : [ 0x4, ['unsigned long']], \
    'Run' : [ 0x8, ['array', 1,['_PHYSICAL_MEMORY_RUN']]], \
} ], \
  '_DMP_HEADER' : [ 0x1000, { \
    'Signature' : [ 0x0, ['array', 4,['unsigned char']]], \
    'ValidDump' : [ 0x4, ['array', 4,['unsigned char']]], \
    'MajorVersion' : [ 0x8, ['unsigned long']], \
    'MinorVersion' : [ 0xc, ['unsigned long']], \
    'DirectoryTableBase' : [ 0x10, ['unsigned long']], \
    'PfnDataBase' : [ 0x14, ['unsigned long']], \
    'PsLoadedModuleList' : [ 0x18, ['unsigned long']], \
    'PsActiveProcessHead' : [ 0x1c, ['unsigned long']], \
    'MachineImageType' : [ 0x20, ['unsigned long']], \
    'NumberProcessors' : [ 0x24, ['unsigned long']], \
    'BugCheckCode' : [ 0x28, ['unsigned long']], \
    'BugCheckCodeParameter' : [ 0x2c, ['array', 4,['unsigned long']]], \
    'VersionUser' : [ 0x3c, ['array', 32,['unsigned char']]], \
    'PaeEnabled' : [ 0x5c, ['unsigned char']], \
    'KdSecondaryVersion' : [ 0x5d, ['unsigned char']], \
    'VersionUser' : [ 0x5e, ['array', 2,['unsigned char']]], \
    'KdDebuggerDataBlock' : [ 0x60, ['unsigned long']], \
    'PhysicalMemoryBlockBuffer' : [ 0x64, ['_PHYSICAL_MEMORY_DESCRIPTOR']], \
    'ContextRecord' : [ 0x320, ['array', 1200,['unsigned char']]], \
    'Exception' : [ 0x7d0, ['_EXCEPTION_RECORD32']], \
    'Comment' : [ 0x820, ['array', 128,['unsigned char']]], \
    'DumpType' : [ 0xf88, ['unsigned long']], \
    'MiniDumpFields' : [ 0xf8c, ['unsigned long']], \
    'SecondaryDataState' : [ 0xf90, ['unsigned long']], \
    'ProductType' : [ 0xf94, ['unsigned long']], \
    'SuiteMask' : [ 0xf98, ['unsigned long']], \
    'WriterStatus' : [ 0xf9c, ['unsigned long']], \
    'RequiredDumpSpace' : [ 0xfa0, ['unsigned __int64']], \
    'SystemUpTime' : [ 0xfb8, ['unsigned __int64']], \
    'SystemTime' : [ 0xfc0, ['unsigned __int64']], \
    'reserved3' : [ 0xfc8, ['array', 56,['unsigned char']]], \
} ], \
## These types are from Andreas Schuster's driverscan
    '_DRIVER_OBJECT' : [ 0xa8, {
        'Type' : [ 0x0, ['unsigned short']],
        'Size' : [ 0x2, ['unsigned short']],
        'DeviceObject' : [ 0x4, ['pointer', ['_DEVICE_OBJECT']]],
        'Flags' : [ 0x8, ['unsigned long']],
        'DriverStart' : [ 0xc, ['pointer', ['void']]],
        'DriverSize' : [ 0x10, ['unsigned long']],
        'DriverSection' : [ 0x14, ['pointer', ['void']]],
        'DriverExtension' : [ 0x18, ['pointer', ['_DRIVER_EXTENSION']]],
        'DriverName' : [ 0x1c, ['_UNICODE_STRING']],
        'HardwareDatabase' : [ 0x24, ['pointer', ['_UNICODE_STRING']]],
        'FastIoDispatch' : [ 0x28, ['pointer', ['_FAST_IO_DISPATCH']]],
        'DriverInit' : [ 0x2c, ['pointer', ['void']]],
        'DriverStartIo' : [ 0x30, ['pointer', ['void']]],
        'DriverUnload' : [ 0x34, ['pointer', ['void']]],
        'MajorFunction' : [ 0x38, ['array', 28, ['pointer', ['void']]]],
    } ],
    '_DRIVER_EXTENSION' : [ 0x1c, {
        'DriverObject' : [ 0x0, ['pointer', ['_DRIVER_OBJECT']]],
        'AddDevice' : [ 0x4, ['pointer', ['void']]],
        'Count' : [ 0x8, ['unsigned long']],
        'ServiceKeyName' : [ 0xc, ['_UNICODE_STRING']],
        'ClientDriverExtension' : [ 0x14, ['pointer', ['_IO_CLIENT_EXTENSION']]],
        'FsFilterCallbacks' : [ 0x18, ['pointer', ['_FS_FILTER_CALLBACKS']]],
    } ],
    '_OBJECT_NAME_INFO' : [ 0xc, {
        'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
        'Name' : [ 0x04, ['_UNICODE_STRING']],
    } ],
    '_KMUTANT' : [ 0x20, {
        'Header' : [ 0x0, ['_DISPATCHER_HEADER']],
        'MutantListEntry' : [ 0x10, ['_LIST_ENTRY']],
		'OwnerThread' : [ 0x18, ['pointer', ['_KTHREAD']]],
		'Abandoned' : [ 0x1c, ['unsigned char']],
		'ApcDisable' : [ 0x1d, ['unsigned char']]
    } ],

}

# Standard vtypes are usually autogenerated by scanning through header
# files, collecting debugging symbol data etc. This file defines
# fixups and improvements to the standard types.
xpsp2overlays = {
    'VOLATILITY_CONSTANTS' : [None, { \
    'DTBSignature' : [ 0x0, ['VolatilityConstant', dict(value="\x03\x00\x1b\x00")]]
    }],
    
    '_EPROCESS' : [ None, { \
    'CreateTime' : [ None, ['WinTimeStamp', {}]],
    'ExitTime' : [ None, ['WinTimeStamp', {}]], 
    'InheritedFromUniqueProcessId' : [ None, ['unsigned int']],
    'ImageFileName' : [ None, ['String', dict(length=16)]],
    'UniqueProcessId' : [ None, ['unsigned int']], \
    'VadRoot': [ None, ['pointer', ['_MMVAD']]], \
    }],

    '_KUSER_SHARED_DATA' : [ None, { \
    'SystemTime' : [ None, ['WinTimeStamp', {}]], \
    'TimeZoneBias' : [ None, ['WinTimeStamp', {}]], \
    }],

    '_ADDRESS_OBJECT' : [ None, { \
    'LocalPort': [ None, ['unsigned be short']], \
    'CreateTime' : [ None, ['WinTimeStamp', {}]], \
    }],

    '_OBJECT_HEADER' : [ None, {
    'Body' : [ None, ['unsigned int']],
    }],

    '_KDDEBUGGER_DATA64' : [ None, { 
    'PsActiveProcessHead' : [ None, ['pointer', ['unsigned long']]], \
    }],
    
    '_DBGKD_GET_VERSION64' : [  None, {
    'DebuggerDataList' : [ None, ['pointer', ['unsigned long']]], \
    }],
    
    '_DMP_HEADER' : [ None, {
    'PsActiveProcessHead' : [ None, ['pointer' ,['unsigned long']]], \
    }],

    '_CM_KEY_NODE' : [ None, {
    'Signature' : [ None, ['String', dict(length=2)]],
    'LastWriteTime' : [ None, ['WinTimeStamp', {}]],
    'Name' : [ None, ['String', dict(length=lambda x: x.NameLength)]],
    }],

    '_CHILD_LIST' : [ None, {
    'List' : [ None, ['pointer', ['array', lambda x: x.Count,
                                 ['pointer', ['_CM_KEY_VALUE']]]]],
    }],

    '_CM_KEY_VALUE' : [ None, {
    'Signature' : [ None, ['String', dict(length=2)]],
    'Name' : [ None, ['String', dict(length=lambda x: x.NameLength)]],
    } ],

    '_CM_KEY_INDEX' : [ None, {
    'Signature' : [ None, ['String', dict(length=2)]],
    'List' : [ None, ['array', lambda x: x.Count.v() * 2, ['pointer', ['_CM_KEY_NODE']]]],
    } ],
    
    '_IMAGE_HIBER_HEADER' : [ None, { \
    'Signature':   [ None, ['String', dict(length=4)]],
    'SystemTime' : [ None, ['WinTimeStamp', {}]], \
    } ], \

    '_PHYSICAL_MEMORY_DESCRIPTOR' : [ None, { \
    'Run' : [ None, ['array', lambda x: x.NumberOfRuns, ['_PHYSICAL_MEMORY_RUN']]], \
    } ], \

    ## This is different between Windows 2000 and WinXP. This overlay
    ## is for xp.
    '_POOL_HEADER' : [ None, { \
    'PoolIndex': [ 0x0, ['BitField', dict(start_bit = 9, end_bit = 16)]], 
    'BlockSize': [ 0x2, ['BitField', dict(start_bit = 0, end_bit = 9)]], 
    'PoolType': [ 0x2, [ 'BitField', dict(start_bit = 9, end_bit = 16)]],
    } ],\

    '_TCPT_OBJECT': [ None, {
    'RemotePort': [ None, [ 'unsigned be short']],
    'LocalPort': [ None, [ 'unsigned be short']],
    } ],
    '_CLIENT_ID': [ None, {
    'UniqueProcess' : [ None, ['unsigned int']], \
    'UniqueThread' : [ None, ['unsigned int']], \
    } ],

    '_CONTROL_AREA': [ None, {
    'Flags': [ None, ['Flags',
                      {'bitmap': {
    'BeingDeleted' : 0x0,
    'BeingCreated' : 0x1,
    'BeingPurged'  : 0x2,
    'NoModifiedWriting' :  0x3,
    'FailAllIo' : 0x4,
    'Image' : 0x5,
    'Based' : 0x6,
    'File'  : 0x7, 
    'Networked' : 0x8,
    'NoCache' : 0x9,
    'PhysicalMemory' : 0xa,
    'CopyOnWrite' : 0xb,
    'Reserve' : 0xc,
    'Commit' : 0xd,
    'FloppyMedia' : 0xe,
    'WasPurged' : 0xf,
    'UserReference' : 0x10,
    'GlobalMemory' : 0x11,
    'DeleteOnClose' : 0x12,
    'FilePointerNull' : 0x13,
    'DebugSymbolsLoaded' : 0x14,
    'SetMappedFileIoComplete' : 0x15,
    'CollidedFlush' : 0x16, 
    'NoChange' : 0x17, 
    'HadUserReference' : 0x18,
    'ImageMappedInSystemSpace' : 0x19,
    'UserWritable' : 0x1a,
    'Accessed' : 0x1b, 
    'GlobalOnlyPerSession' : 0x1c,
    'Rom' : 0x1d,
    },
                       }
                      ]
               ],
    } ]
}


xpsp2overlays['_MMVAD_SHORT'] = [ None, {
    'Flags': [ None, ['Flags',
  {'bitmap': {
    'PhysicalMapping': 0x13,
    'ImageMap': 0x14,
    'UserPhysicalPages': 0x15,
    'NoChange': 0x16,
    'WriteWatch': 0x17,
    'LargePages': 0x1D,
    'MemCommit': 0x1E,
    'PrivateMemory': 0x1f,
    },
  'maskmap': {
    'CommitCharge' : [0x0, 0x13], 
    'Protection' : [0x18, 0x5],
    }
  } ] ],
    } ]

xpsp2overlays['_MMVAD_LONG'] = [ None, {
    'Flags': xpsp2overlays['_MMVAD_SHORT'][1]['Flags'],
    
    'Flags2': [ None, ['Flags',
  {'bitmap': {
    'SecNoChange' : 0x18,
    'OneSecured' : 0x19,
    'MultipleSecured' : 0x1a,
    'ReadOnly' : 0x1b,
    'LongVad' : 0x1c,
    'ExtendableFile' : 0x1d,
    'Inherit' : 0x1e,
    'CopyOnWrite' : 0x1f,
    },
  'maskmap': {
    'FileOffset' : [0x0, 0x18], 
    }
  } ] ],
    } ]
