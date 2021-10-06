from ReadWriteMemory import ReadWriteMemory
from .data_types import *
import ctypes
import subprocess
import time
import logging
from typing import Dict, Any
import signal
import traceback
import pdb

logger = logging.getLogger()
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)


def get_filename_from_handle(dll_handle: int) -> str:
    buffer = ctypes.create_string_buffer(0x100)
    size = ctypes.windll.kernel32.GetFinalPathNameByHandleA(dll_handle, buffer, 0x100, 0x0)
    file_name = buffer.raw[:size].decode()
    del buffer
    return file_name


class Debugger:
    file_name: str
    breakpoints: Dict[int, Dict[str, Any]]
    debug: bool
    print_reg: bool
    process_id: int
    thread_id: int
    thread_handle: int
    dlls: Dict[int, str] = {}
    cpu_context = CpuContext()
    debug_event = DebugEvent(0, 0, 0)
    single_step: bool = False

    def __init__(self, file_name: str, breakpoints: Dict[int, Dict[str, Any]] = None,
                 debug: bool = False, print_context: bool = False):
        self.file_name = file_name
        if breakpoints:
            self.breakpoints = breakpoints
        else:
            self.breakpoints = {}
        self.debug = debug
        self.print_reg = print_context

    def exception_event(self) -> None:
        logger.debug(
            f"Exception event: pid {self.debug_event.processId}, tid {self.debug_event.threadId} - {self.debug_event.info.exception.ExceptionCode}")
        self.read_thread_context()
        rip = self.cpu_context.Rip - 1
        if rip in self.breakpoints:
            self.get_stack()
            self.breakpoints[rip]["hit"] += 1
            self.breakpoints[rip]["handle"](*self.breakpoints[rip]["args"], debugee=self)
            self.continue_break_point(rip)
            if self.breakpoints[rip]['recurring']:
                logger.debug(f"Single step: {self.toggle_single_step()}")
            else:
                del self.breakpoints[rip]
                logger.debug(self.breakpoints)
            if not ctypes.windll.kernel32.ContinueDebugEvent(self.debug_event.processId, self.debug_event.threadId,
                                                             DEBUG_SIGNAL.DBG_CONTINUE.value):
                logger.warning('Continue event failed')
        elif self.single_step:
            logger.debug(f'Continuing program from 0x{rip:x}')
            for address in self.breakpoints:
                self.add_break_point(address)
            self.single_step = False
            if not ctypes.windll.kernel32.ContinueDebugEvent(self.debug_event.processId, self.debug_event.threadId,
                                                             DEBUG_SIGNAL.DBG_CONTINUE.value):
                logger.warning('Continue event failed')
        else:
            if not ctypes.windll.kernel32.ContinueDebugEvent(self.debug_event.processId, self.debug_event.threadId,
                                                             DEBUG_SIGNAL.DBG_EXCEPTION_NOT_HANDLED.value):
                logger.warning('Continue event failed')

    def create_process_event(self) -> None:
        logger.debug(f"Process created: pid {self.debug_event.processId}, tid {self.debug_event.threadId}")
        self.process_id = self.debug_event.processId
        self.thread_id = self.debug_event.threadId
        file_handle = self.debug_event.info.createProcess.hfile
        self.thread_handle = self.debug_event.info.createProcess.hThread
        file_name = get_filename_from_handle(file_handle)
        logger.debug(file_name)
        for address in self.breakpoints:
            self.add_break_point(address)
            logger.debug(f'set breakpoint {address}:{self.breakpoints[address]}')

    def create_thread_event(self) -> None:
        logger.debug(f"Thread created: pid {self.debug_event.processId}, tid {self.debug_event.threadId}")

    def load_dll_event(self) -> None:
        logger.debug(f"DLL loaded: pid {self.debug_event.processId}, tid {self.debug_event.threadId}")
        dll_handle = self.debug_event.info.loadDll.hfile
        file_name = get_filename_from_handle(dll_handle)
        self.dlls[self.debug_event.info.loadDll.lpBaseOfDll] = file_name
        logger.debug(file_name)

    def unload_dll_event(self) -> None:
        logger.debug(f"DLL unloaded: pid {self.debug_event.processId}, tid {self.debug_event.threadId}")
        logger.debug(self.dlls[self.debug_event.info.unloadDll.lpBaseOfDll])

    def exit_thread_event(self) -> None:
        logger.debug(f"Thread exited: pid {self.debug_event.processId}, tid {self.debug_event.threadId}")
        logger.debug(f'Exit code: {self.debug_event.info.exitThread.exitCode}')

    def exit_program_event(self) -> None:
        logger.debug(f'Process exit event received. Exit code: {self.debug_event.info.exitProcess.exitCode}')

    def run(self) -> int:
        sp = subprocess.Popen(self.file_name, creationflags=PROCESS_CREATION.DEBUG_ONLY_THIS_PROCESS.value)
        while True:
            if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.pointer(self.debug_event), 0x500):
                self.print_context()
                debug_event = DEBUG_EVENT(self.debug_event.debugEventCode)
                logger.debug(debug_event)
                if debug_event == DEBUG_EVENT.EXIT_PROCESS_DEBUG_EVENT:
                    self.exit_program_event()
                    break
                if debug_event == DEBUG_EVENT.EXCEPTION_DEBUG_EVENT:
                    self.exception_event()
                    continue
                elif debug_event == DEBUG_EVENT.CREATE_PROCESS_DEBUG_EVENT:
                    self.create_process_event()
                elif debug_event == DEBUG_EVENT.CREATE_THREAD_DEBUG_EVENT:
                    self.create_thread_event()
                elif debug_event == DEBUG_EVENT.LOAD_DLL_DEBUG_EVENT:
                    self.load_dll_event()
                elif debug_event == DEBUG_EVENT.EXIT_THREAD_DEBUG_EVENT:
                    self.exit_thread_event()
                elif debug_event == DEBUG_EVENT.UNLOAD_DLL_DEBUG_EVENT:
                    self.unload_dll_event()
                if not ctypes.windll.kernel32.ContinueDebugEvent(self.debug_event.processId, self.debug_event.threadId,
                                                                 DEBUG_SIGNAL.DBG_CONTINUE.value):
                    logger.warning('Continue event failed')
                    continue
            else:
                if self.debug and False:
                    breakpoint()
                else:
                    time.sleep(50 / 1000)
        if ctypes.windll.kernel32.DebugActiveProcessStop(sp.pid):
            logger.debug("active process debugging stopped")
        return self.debug_event.info.exitProcess.exitCode

    def print_context(self, show: bool = False) -> None:
        '''
        :param show:
        :return:
        '''
        if self.print_reg or show:
            success = self.read_thread_context()
            context = self.cpu_context.as_dict()
            print(
                f"\nEAX = {context['Rax']:16x}  EBX = {context['Rbx']:16x}    ECX = {context['Rcx']:16x}\n",
                f"EDX = {context['Rdx']:16x}  ESI = {context['Rsi']:16x}    EDI = {context['Rdi']:16x}\n",
                f"EIP = {context['Rip']:16x}  ESP = {context['Rsp']:16x}    EBP = {context['Rbp']:16x}\n",
                f"EFL = {context['EFlags']:16X}")

    def read_thread_context(self) -> bool:
        self.cpu_context = CpuContext()
        self.cpu_context.ContextFlags = CONTEXT.CONTEXT_I386_ALL.value
        success = ctypes.windll.kernel32.GetThreadContext(self.thread_handle, ctypes.byref(self.cpu_context))
        return success

    def write_thread_context(self) -> bool:
        self.cpu_context.ContextFlags = CONTEXT.CONTEXT_I386_ALL.value
        success = ctypes.windll.kernel32.SetThreadContext(self.thread_handle, ctypes.byref(self.cpu_context))
        return success

    def toggle_single_step(self) -> bool:
        success = self.read_thread_context()
        if success:
            self.cpu_context.EFlags |= 0x100
            success = self.write_thread_context()
            self.single_step = True
        # not elif: success can change in the previous condition, so this will catch either fails
        if not success:
            logger.warning(f'failed to set single step in program {self.process_id}')
        return success

    def add_break_point(self, address: int) -> None:
        '''
        :param address:
        :return:
        Don't use single byte instructions because continue is broken.
        HOnestly, don't do it, double check, triple check. You have done it THREE times now!
        '''
        buffer, success = self.read_memory(address, 1)
        if success and buffer != b'\xCC':
            self.breakpoints[address]['instruction'] = buffer
            buffer = ctypes.create_string_buffer(b'\xCC')
            success = self.write_memory(address, buffer, instruction=True)
            del buffer
        # not elif: success can change in the previous condition, so this will catch either fails
        if not success:
            logger.warning(f'failed to add breakpoint to address: {address} in program {self.process_id}')

    def remove_break_point(self, address: int) -> None:
        '''
        :param address:
        :return:
        '''
        self.print_context()
        buffer = ctypes.create_string_buffer(self.breakpoints[address]['instruction'])
        success = self.write_memory(address, buffer, instruction=True)
        if success:
            logger.info(f"breakpoint {address:x} removed: instruction 0x{self.breakpoints[address]['instruction']} updated")
        del buffer
        del self.breakpoints[address]

    def continue_break_point(self, address: int) -> None:
        '''
        :param address:
        :return:
        I don't think this works for single byte instructions
        '''
        buffer = ctypes.create_string_buffer(self.breakpoints[address]['instruction'])
        success = self.write_memory(address, buffer, instruction=True)
        del buffer
        if success:
            success = self.read_thread_context()
            if success:
                self.cpu_context.Rip -= 1
                success = self.write_thread_context()
        # not elif: success can change in the previous condition, so this will catch either fails
        if not success:
            logger.warning(f'failed to resume breakpoint to address: {address} in program {self.process_id}')

    def read_memory(self, address: int, read_length: int) -> (bytes, bool):
        rwm = ReadWriteMemory()
        p = rwm.get_process_by_id(self.process_id)
        p.open()
        bytes_read = ctypes.c_ulong(0)
        buffer = ctypes.create_string_buffer(read_length)
        success = ctypes.windll.kernel32.ReadProcessMemory(p.handle, address, buffer, read_length,
                                                           ctypes.byref(bytes_read))
        p.close()
        mem_copy = buffer.raw
        del buffer
        return mem_copy, success

    # TODO: change to take in bytes instead of char array
    def write_memory(self, address: int, buffer: ctypes.c_char, instruction: bool = False) -> bool:
        rwm = ReadWriteMemory()
        p = rwm.get_process_by_id(self.process_id)
        p.open()
        bytes_read = ctypes.c_ulong(0)
        # buffer = ctypes.create_string_buffer(b'\xCC') int3 instruction
        # buffer is null terminated so take one from its length
        success = ctypes.windll.kernel32.WriteProcessMemory(p.handle, address, buffer, len(buffer) - 1,
                                                            ctypes.byref(bytes_read))
        if instruction and success:
            success = ctypes.windll.kernel32.FlushInstructionCache(p.handle, None, None)
        p.close()
        del buffer
        return success

    def get_stack(self) -> None:
        rwm = ReadWriteMemory()
        p = rwm.get_process_by_id(self.process_id)
        p.open()
        success = self.read_thread_context()
        if success:
            context = self.cpu_context
            stack_frame = StackFrame()
            stack_frame.from_context(context)
            success = ctypes.windll.dbghelp.StackWalk64(IMAGE_FILE_MACHINE_I386, p.handle, self.thread_handle,
                                                        ctypes.byref(stack_frame), ctypes.byref(context), None, None,
                                                        None, None)
        p.close()
