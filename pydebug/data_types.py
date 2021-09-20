import ctypes
from ctypes.wintypes import *
from enum import Enum


def as_dict(obj):
    field_dict = dict((f, getattr(obj, f)) for f, _ in obj._fields_)
    for key in field_dict:
        item = field_dict[key]
        if hasattr(item, 'as_dict'):
            field_dict[key] = field_dict[key].as_dict()
        if hasattr(item, '__getitem__'):
            field_dict[key] = list(field_dict[key])
    return field_dict


def from_dict(field_dict):
    return field_dict


class DebugStructure(ctypes.Structure):
    def as_dict(self):
        return as_dict(self)

    @classmethod
    def from_dict(cls, field_dict):
        for key in field_dict:
            item = field_dict[key]
            if hasattr(item, '_fields_'):
                raise Exception('Structure from field not implemented')
            if hasattr(item, '__getitem__'):
                raise Exception('Structure from array not implemented')
        debug_struct = cls(**field_dict)
        return debug_struct


class DebugUnion(ctypes.Union):
    def as_dict(self):
        return as_dict(self)


class CONTEXT(Enum):
    CONTEXT_I386 = 0x00010000
    CONTEXT_I386_CONTROL = CONTEXT_I386 | 0x0001
    CONTEXT_I386_INTEGER = CONTEXT_I386 | 0x0002
    CONTEXT_I386_SEGMENTS = CONTEXT_I386 | 0x0004
    CONTEXT_I386_FLOATING_POINT = CONTEXT_I386 | 0x0008
    CONTEXT_I386_DEBUG_REGISTERS = CONTEXT_I386 | 0x0010
    CONTEXT_I386_EXTENDED_REGISTERS = CONTEXT_I386 | 0x0020
    CONTEXT_I386_XSTATE = CONTEXT_I386 | 0x0040
    CONTEXT_I386_FULL = CONTEXT_I386_CONTROL | CONTEXT_I386_INTEGER | CONTEXT_I386_SEGMENTS
    CONTEXT_I386_ALL = CONTEXT_I386_FULL | CONTEXT_I386_FLOATING_POINT | CONTEXT_I386_DEBUG_REGISTERS | CONTEXT_I386_EXTENDED_REGISTERS


# Process creation flags
class PROCESS_CREATION(Enum):
    DEBUG_PROCESS = 0x1
    DEBUG_ONLY_THIS_PROCESS = 0x2
    CREATE_SUSPENDED = 0x4
    DETACHED_PROCESS = 0x8
    CREATE_NEW_CONSOLE = 0x10
    NORMAL_PRIORITY_CLASS = 0x20
    IDLE_PRIORITY_CLASS = 0x40
    HIGH_PRIORITY_CLASS = 0x80
    REALTIME_PRIORITY_CLASS = 0x100
    CREATE_NEW_PROCESS_GROUP = 0x200
    CREATE_UNICODE_ENVIRONMENT = 0x400
    CREATE_SEPARATE_WOW_VDM = 0x800
    CREATE_SHARED_WOW_VDM = 0x1000
    CREATE_FORCEDOS = 0x2000
    CREATE_DEFAULT_ERROR_MODE = 0x4000000
    CREATE_NO_WINDOW = 0x8000000


class DEBUG_SIGNAL(Enum):
    DBG_CONTINUE = 0x10002
    DBG_TERMINATE_THREAD = 0x40010003
    DBG_TERMINATE_PROCESS = 0x40010004
    DBG_CONTROL_C = 0x40010005
    DBG_CONTROL_BREAK = 0x40010008
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001


class DEBUG_EVENT(Enum):
    CREATE_PROCESS_DEBUG_EVENT = 3
    CREATE_THREAD_DEBUG_EVENT = 2
    EXCEPTION_DEBUG_EVENT = 1
    EXIT_PROCESS_DEBUG_EVENT = 5
    EXIT_THREAD_DEBUG_EVENT = 4
    LOAD_DLL_DEBUG_EVENT = 6
    OUTPUT_DEBUG_STRING_EVENT = 8
    RIP_EVENT = 9
    UNLOAD_DLL_DEBUG_EVENT = 7


class EXCEPTION_FLAGS(Enum):
    EXCEPTION_CONTINUABLE = 0
    EXCEPTION_NONCONTINUABLE = 1


class EXCEPTION_CODES(Enum):
    EXCEPTION_GUARD_PAGE_VIOLATION = 0x80000001
    EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002
    EXCEPTION_BREAKPOINT = 0x80000003
    EXCEPTION_SINGLE_STEP = 0x80000004
    EXCEPTION_ACCESS_VIOLATION = 0xC0000005
    EXCEPTION_IN_PAGE_ERROR = 0xC0000006
    EXCEPTION_INVALID_HANDLE = 0xC0000008
    EXCEPTION_NO_MEMORY = 0xC0000017
    EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
    EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025
    EXCEPTION_INVALID_DISPOSITION = 0xC0000026
    EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
    EXCEPTION_FLOAT_DENORMAL_OPERAND = 0xC000008D
    EXCEPTION_FLOAT_DIVIDE_BY_ZERO = 0xC000008E
    EXCEPTION_FLOAT_INEXACT_RESULT = 0xC000008F
    EXCEPTION_FLOAT_INVALID_OPERATION = 0xC0000090
    EXCEPTION_FLOAT_OVERFLOW = 0xC0000091
    EXCEPTION_FLOAT_STACK_CHECK = 0xC0000092
    EXCEPTION_FLOAT_UNDERFLOW = 0xC0000093
    EXCEPTION_INTEGER_DIVIDE_BY_ZERO = 0xC0000094
    EXCEPTION_INTEGER_OVERFLOW = 0xC0000095
    EXCEPTION_PRIVILEGED_INSTRUCTION = 0xC0000096
    EXCEPTION_STACK_OVERFLOW = 0xC00000FD
    EXCEPTION_CONTROL_C_EXIT = 0xC000013A


# TODO: FIX LONG and INT types
class CreateThreadInfo(DebugStructure):
    _fields_ = [
        ("debugEventCode", DWORD),
        ("processId", DWORD),
        ("threadId", DWORD),
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
    ]


class CreateProcessInfo(DebugStructure):
    _fields_ = [
        ("hfile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("debugInfoFileOffset", DWORD),
        ("nDebugInfoSize", LONG),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
        ("lpImageName", LPVOID),
        ("fUnicode", INT),
    ]


class ExceptionInfo(DebugStructure):
    _fields_ = [
        ("ExceptionCode", LONG),
        ("ExceptionFlags", LONG),
        ("pExceptionRecord", LONG),
        ("ExceptionAddress", LONG),
        ("NumberParameters", LONG),
        ("ExceptionInformation", LONG),
        ("firstChance", DWORD),
    ]


class ExitThreadInfo(DebugStructure):
    _fields_ = [
        ("exitCode", DWORD),
    ]


class ExitProcessInfo(DebugStructure):
    _fields_ = [
        ("exitCode", DWORD),
    ]


class LoadDLLInfo(DebugStructure):
    _fields_ = [
        ("hfile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("debugInfoFileOffset", DWORD),
        ("nDebugInfoSize", LONG),
        ("lpImageName", LPVOID),
        ("fUnicode", INT),
    ]


class UnloadDLLInfo(DebugStructure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
    ]


class RipInfo(DebugStructure):
    _fields_ = [
        ("error", DWORD),
        ("type", DWORD),
    ]


class DebugEventInfo(DebugUnion):
    _fields_ = [
        ("createThread", CreateThreadInfo),
        ("createProcess", CreateProcessInfo),
        ("exitThread", ExitThreadInfo),
        ("exitProcess", ExitProcessInfo),
        ("exception", ExceptionInfo),
        ("loadDll", LoadDLLInfo),
        ("unloadDll", UnloadDLLInfo),
        ("rip", RipInfo),
    ]


class DebugEvent(DebugStructure):
    _fields_ = [
        ("debugEventCode", DWORD),
        ("processId", DWORD),
        ("threadId", DWORD),
        ("info", DebugEventInfo),
    ]


class FltSave(DebugStructure):
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
        ("FloatRegisters", ctypes.c_uint64 * (2 * 8)),
        ("XmmRegisters", ctypes.c_uint64 * (2 * 16)),
        ("Reserved4", BYTE * 96),
    ]


class CpuContext(DebugStructure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", FltSave),
        ("VectorRegister", ctypes.c_uint64 * (2 * 26)),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]
