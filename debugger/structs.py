from ctypes import *

# Let's map the Microsoft types to ctypes for clarity
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_uint32
DWORD64   = c_uint64
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
ULONG_PTR  = POINTER(c_uint32)
SIZE_T    = c_uint32

# Constants
DEBUG_PROCESS         = 0x00000001
CREATE_NEW_CONSOLE    = 0x00000010
#PROCESS_ALL_ACCESS    = 0x001F0FFF # This constant changed in Vista
PROCESS_ALL_ACCESS      = 0x001FFFF
INFINITE              = 0xFFFFFFFF
DBG_CONTINUE          = 0x00010002


# Debug event constants
EXCEPTION_DEBUG_EVENT      =    0x1
CREATE_THREAD_DEBUG_EVENT  =    0x2
CREATE_PROCESS_DEBUG_EVENT =    0x3
EXIT_THREAD_DEBUG_EVENT    =    0x4
EXIT_PROCESS_DEBUG_EVENT   =    0x5
LOAD_DLL_DEBUG_EVENT       =    0x6
UNLOAD_DLL_DEBUG_EVENT     =    0x7
OUTPUT_DEBUG_STRING_EVENT  =    0x8
RIP_EVENT                  =    0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004


# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS   = 0x001F03FF

#
# Context flags for GetThreadContext()
#

# Processor mode ( which CONTEXT struct to return )
CONTEXT_x86                = 0x00010000
CONTEXT_AMD_64             = 0x00100000


# Which parts of the Context struct to show
CONTEXT_CONTROL             = 0x1
CONTEXT_INTEGER             = 0x2
CONTEXT_SEGMENTS            = 0x4
CONTEXT_FLOATING_POINT      = 0x8
CONTEXT_DEBUG_REGISTERS     = 0x10

CONTEXT_FULL_64             = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
CONTEXT_ALL_64              = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | \
                                CONTEXT_DEBUG_REGISTERS)


# x86/WOW64-specific
CONTEXT_XSTATE_32           = 0x40
CONTEXT_EXTENDED_REGISTERS  = 0x20 

CONTEXT_FULL_32 = (CONTEXT_CONTROL | CONTEXT_INTEGER |\
                   CONTEXT_SEGMENTS)

CONTEXT_ALL_32  = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                   CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                   CONTEXT_EXTENDED_REGISTERS)

# AMD_64-specific  
CONTEXT_XSTATE_64           = 0x20
CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
CONTEXT_SERVICE_ACTIVE      = 0x10000000
CONTEXT_EXCEPTION_REQUEST   = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000

# Memory permissions
PAGE_EXECUTE_READWRITE         = 0x00000040

# Hardware breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS                  = 0x00000001
PAGE_READONLY                  = 0x00000002
PAGE_READWRITE                 = 0x00000004
PAGE_WRITECOPY                 = 0x00000008
PAGE_EXECUTE                   = 0x00000010
PAGE_EXECUTE_READ              = 0x00000020
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE_WRITECOPY         = 0x00000080
PAGE_GUARD                     = 0x00000100
PAGE_NOCACHE                   = 0x00000200
PAGE_WRITECOMBINE              = 0x00000400


# Structures for CreateProcessA() function
# STARTUPINFO describes how to spawn the process
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]

# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]

# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",        DWORD),
    ("ExceptionFlags",       DWORD),
    ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",     PVOID),
    ("NumberParameters",     DWORD),
    ("ExceptionInformation", ULONG_PTR * 15),
    ]

# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]

# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
# Don't care about these for now, define later
#        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
#        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
#        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
#        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
#        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
#        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
#        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
#        ("RipInfo",           RIP_INFO),
        ]   
    
    
DEBUG_EVENT_CODE_NAMES = [
    'Undefined',
    'EXCEPTION_DEBUG_EVENT',
    'CREATE_THREAD_DEBUG_EVENT',
    'EXCEPTION_DEBUG_EVENT',
    'EXIT_THREAD_DEBUG_EVENT',
    'EXIT_PROCESS_DEBUG_EVENT',
    'LOAD_DLL_DEBUG_EVENT',
    'UNLOAD_DLL_DEBUG_EVENT',
    'OUTPUT_DEBUG_STRING_EVENT',
    'RIP_EVENT',
]

# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",                DEBUG_EVENT_UNION),
        ]

# Used by the CONTEXT structure
class FLOATING_SAVE_AREA(Structure):
   _fields_ = [
   
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]

# The CONTEXT structure which holds all of the 
# register values after a GetThreadContext() call
# THIS IS THE 32-bit version of the struct. The 64-bit version is below
# See winNT.h.
class CONTEXT(Structure):
    _fields_ = [
    
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
	]
    
class M128A(Structure):
    _fields_ = [
        ("High", DWORD64),
        ("Low", DWORD64)
	]

#     
class XMM_SAVE_AREA32(Structure):
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8)
	]

# Alternative 
class XMM_SAVE_AREA_STRUCT(Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0"  , M128A), 
        ("Xmm1"  , M128A),  
        ("Xmm2"  , M128A),  
        ("Xmm3"  , M128A),  
        ("Xmm4"  , M128A),  
        ("Xmm5"  , M128A),  
        ("Xmm6"  , M128A),  
        ("Xmm7"  , M128A),  
        ("Xmm8"  , M128A),  
        ("Xmm9"  , M128A),   
        ("Xmm10" , M128A), 
        ("Xmm11" , M128A),
        ("Xmm12" , M128A),
        ("Xmm13" , M128A),
        ("Xmm14" , M128A),
        ("Xmm15" , M128A),   
    ]
    


# Union representing the two ways of representing floating-point register state
class FLOAT_UNION(Union):
    _fields_ = [
        ("FltSave", XMM_SAVE_AREA32),
        ("DUMMYSTRUCTNAME", XMM_SAVE_AREA_STRUCT)
    ]


class CONTEXT_AMD64(Structure):
    _fields_ = [
	# Convenience fields

	("P1Home",  DWORD64),
	("P2Home",  DWORD64),      
    ("P3Home",  DWORD64),
    ("P4Home",  DWORD64),
    ("P5Home",  DWORD64), 
    ("P6Home",  DWORD64),

    # Control flags. These are set to indicate to GetThreadContext what should be filled
    ("ContextFlags", DWORD),
    ("MxCsr", DWORD),

	# Segment registers and flags

	("SegCs", WORD), 
	("SegDs", WORD),
	("SegEs", WORD),
	("SegFs", WORD),
	("SegGs", WORD),
	("SegSs", WORD),
	("EFlags", DWORD),

	# Debug registers
	("Dr0", DWORD64), 
    ("Dr1", DWORD64),
    ("Dr2", DWORD64),
    ("Dr3", DWORD64),
    ("Dr6", DWORD64),
	("Dr7", DWORD64),

	# Integer registers

	("Rax", DWORD64), 
    ("Rcx", DWORD64),
    ("Rdx", DWORD64),
    ("Rbx", DWORD64),
    ("Rsp", DWORD64),
    ("Rbp", DWORD64),
    ("Rsi", DWORD64),
    ("Rdi", DWORD64),
    ("R8;", DWORD64),
    ("R9;", DWORD64),
    ("R10", DWORD64),
    ("R11", DWORD64),
    ("R12", DWORD64),
    ("R13", DWORD64),
    ("R14", DWORD64),
	("R15", DWORD64),

	# Instruction pointer
	("Rip", DWORD64),

	# Floating point state
    ("DUMMYUNIONNAME", FLOAT_UNION),

    
    # Vector registers
    ("VectorRegister", M128A * 27),
    ("VectorControl", DWORD64),

    # Special Debug Control registers

    ("DebugControl"        , DWORD64),           
    ("LastBranchToRip"     , DWORD64), 
    ("LastBranchFromRip"   , DWORD64),
    ("LastExceptionToRip"  , DWORD64),
    ("LastExceptionFromRip", DWORD64),
	]



# THREADENTRY32 contains information about a thread
# we use this for enumerating all of the system threads

class THREADENTRY32(Structure):
    
    def __init__(self):
        Structure.__init__(self)
        self.dwSize = sizeof(self)
        
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]

# Supporting struct for the SYSTEM_INFO_UNION union
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture",    WORD),
        ("wReserved",                 WORD),
]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId",    DWORD),
        ("sProcStruc", PROC_STRUCT),
]
# SYSTEM_INFO structure is populated when a call to 
# kernel32.GetSystemInfo() is made. We use the dwPageSize
# member for size calculations when setting memory breakpoints
class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
]

# MEMORY_BASIC_INFORMATION contains information about a 
# particular region of memory. A call to kernel32.VirtualQuery()
# populates this structure.
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
]
    
