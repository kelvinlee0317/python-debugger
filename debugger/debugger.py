'''
Created on Apr 17, 2013

@author: david
'''

from ctypes import *
from structs import *
import sys

kernel32 = windll.kernel32

class Debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.first_breakpoint = True
        self.breakpoints = {}
        self.event_callback = None
        self.bp_callback = None    
        
    def set_event_callback(self, callback):
        """ Set method to be called upon all debugging events """
        self.event_callback = callback
        
    def set_bp_callback(self, callback):
        self.bp_callback = callback
        
    
    def load(self, path_to_exe):
        
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want to see the GUI
        creation_flags = DEBUG_PROCESS
        
        # instantiate the structs
        startup_info = STARTUPINFO()
        process_info = PROCESS_INFORMATION()
        
        startup_info.dwFlags = 0x1
        startup_info.wShowWindow = 0x0
        
        startup_info.cb = sizeof(startup_info)
        
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms682425%28v=vs.85%29.aspx
        if kernel32.CreateProcessA(path_to_exe,
                                  None,
                                  None,
                                  None,
                                  None,
                                  creation_flags,
                                  None,
                                  None,
                                  byref(startup_info),
                                  byref(process_info)):
            print   "[*] Successfully launched process!"
            print   "[*]  PID: %d" % process_info.dwProcessId
            
            # Obtain a handle to the open process
            # self.h_process = self.open_process(process_info.dwProcessId)
            
            self.debugger_active = True
            self.pid = process_info.dwProcessId
            self.h_process = self.open_process(self.pid)

            return process_info.dwProcessId
            
            
        else:
            sys.stderr.write('[*] Error: 0x%08x. \n' % kernel32.GetLastError())
            
    def open_process(self, pid):
        # HANDLE WINAPI OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId)
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        print "Opened pid: {}".format(pid)
        # if h_process == 0:
        #    print "[*] Error opening process: %s" % kernel32.GetLastError()   
        return h_process

    def open_thread(self, thread_id):
        """ Get a handle to the specified thread """
        print "Getting a handle to ", thread_id
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread:
            return h_thread
        else:
            sys.err.write("Could not obtain a thread handle\n")
            return False
    
    def enumerate_threads(self, pid):
        """ Loop through all the threads given by the system, match those with our PID """
        thread_entry = THREADENTRY32()
        thread_list = []
        # Call a general WINAPI system info function.
        # WTF is with your weird function names, Microsoft?
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,
                                                    pid)

        print "Snapshot ", snapshot

        print "Last error: ", self.get_last_error()
        
        if not snapshot:
            sys.stderr.write("Could not access thread information with CreateToolhelp32Snapshot\n")
            return False
        
        else:
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            while success:

                if thread_entry.th32OwnerProcessID == pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))
                
            kernel32.CloseHandle(snapshot)

            print "Found {} threads".format(len(thread_list))
            return thread_list
        
    def get_thread_context(self, thread_id=None, h_thread=None):
        """ Get the thread context struct for a given thread id"""
        context = CONTEXT_AMD64()
        context.ContextFlags = CONTEXT_AMD_64 | CONTEXT_FULL_64 | CONTEXT_DEBUG_REGISTERS | CONTEXT_SEGMENTS
        
        # Obtain a handle to the thread
        if not h_thread:
            h_thread = self.open_thread(thread_id)
            
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            sys.stderr.write("Could not access thread_id {}\n".format(thread_id))
            return False
    
    def attach(self, pid):
        """ Attach to an already running process by given pid """
        
        pid = DWORD(int(pid))
        self.h_process = self.open_process(pid)
        print "h_process: {}".format(self.h_process)
        
        
        # We attempt to attach to the process
        # if this fails we exit the call
        # BOOL WINAPI DebugActiveProcess(dwProcessId)
        success = kernel32.DebugActiveProcess(pid)
        if success:
                self.debugger_active = True
                self.pid = pid
                return pid
                
        else:
            sys.stderr.write("[*] Unable to attach to the process to debug.\n kernel32.DebugActiveProcess:: Return code {}.".format(success)\
                       + " Error Code {}.\n".format(self.get_last_error()) \
                       + " Are you trying to debug a 64-bit process with 32-bit Python?")

            return None
        
    def read_process_memory(self, h_process, address, length):  
        data = ''
        read_buffer = create_string_buffer(length)
        # Bytes read
        count_read = c_ulong(0)
        
        result = kernel32.ReadProcessMemory(h_process, address, read_buffer, length, byref(count_read))
        
        if not result:
            sys.stderr.write('Failed to read {} bytes of memory at address {} for process {}\n'.format(length, hex(address), h_process))
            sys.stderr.write('Error: ' + hex(self.get_last_error()) + '\n')
            return None
        
        else:
            data += read_buffer.raw
            return data
        
    def write_process_memory(self, h_process, address, data):
        count_write = c_ulong(0)
        
        c_data = c_char_p(data)
        
        if not kernel32.WriteProcessMemory(h_process, address, c_data, len(data), byref(count_write)):
            sys.stderr.write('Failed to write {} bytes of memory at address {}\n'.format(len(data), address))
            return False
        
        else:
            return True
        
        
    def breakpoint_set(self, h_process, address):
        if not address in self.breakpoints:
            try:
                # store the original byte
                original = self.read_process_memory(h_process, address, 1)
                
                # write the opcode for INT3, the breakpoint interrupt instruction
                self.write_process_memory(h_process, address, '\xCC')
                
                # put the breakpoint into our dict
                self.breakpoints[address] = original
                
            except Exception as e:
                sys.stderr.write('Something went wrong setting a software breakpoint at address {}: {}\n'.format(address, e))
                
                return False
        return True
        
    def func_resolve(self, dll, function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)
        
        kernel32.CloseHandle(handle)
        
        return address
    
    def exception_handler_breakpoint(self, exception_address, thread_id):
        print "[*] Exception address: 0x%08x" % exception_address
        # check if the breakpoint is one that we set
        if not self.breakpoints.has_key(exception_address):
           
                # if it is the first Windows driven breakpoint
                # then let's just continue on
                if self.first_breakpoint == True:
                   self.first_breakpoint = False
                   print "[*] Hit the first breakpoint."
               
        else:
            print "[*] Hit user defined breakpoint."
            # this is where we handle the breakpoints we set 
            # first put the original byte back
            self.write_process_memory(self.h_process, exception_address, self.breakpoints[exception_address])

            # obtain a fresh context record, reset EIP back to the 
            # original byte and then set the thread's context record
            # with the new EIP value
            context = self.get_thread_context(thread_id=thread_id)
            context.Rip -= 1
            
            if not kernel32.SetThreadContext(self.open_thread(thread_id), byref(context)):
                sys.stderr.write('Error setting EIP, code {}\n'.format(hex(self.get_last_error())))
            
        return DBG_CONTINUE
    
    def single_step(self, thread_id):
        """ Set the processor to interrupt on the next instruction """
        h_thread = self.open_thread(thread_id)

        context = self.get_thread_context(h_thread=h_thread)

        context.EFlags = context.EFlags | 0x100
        if not kernel32.SetThreadContext(self.open_thread(thread_id), byref(context)):
            sys.stderr.write('Error setting flags register, code {}\n'.format(hex(self.get_last_error())))
        
            
    def get_debug_event(self):
        """ Loop, waiting for debugging events.
        
            TODO:  Add callback arg for action on given event type
        """
        
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
                # TODO: Event handlers
                print "Debug event code: {}, Event type: {}\nProcessID: {}\nThreadID: {}".format(debug_event.dwDebugEventCode,
                                                                                  DEBUG_EVENT_CODE_NAMES[debug_event.dwDebugEventCode],
                                                                                  debug_event.dwProcessId,
                                                                                  debug_event.dwThreadId)
                
                debug_thread_context = self.get_thread_context(thread_id=debug_event.dwThreadId)
                
                
                print "Flags: ", hex(debug_thread_context.EFlags)
                # self.dump_thread_contexts()
                
                if DEBUG_EVENT_CODE_NAMES[debug_event.dwDebugEventCode] == 'EXCEPTION_DEBUG_EVENT':
                    print 'Exception Code: ', hex(debug_event.u.Exception.ExceptionRecord.ExceptionCode)
                    exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                    exception_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode

                    continue_status = self.exception_handler_breakpoint(exception_address, debug_event.dwThreadId)
                    
                    if self.bp_callback:
                        self.bp_callback(debug_event)
                        

                if self.event_callback:
                    self.event_callback()
                    
                # Stop debugging once the process exits
                if DEBUG_EVENT_CODE_NAMES[debug_event.dwDebugEventCode] == 'EXIT_PROCESS_DEBUG_EVENT':
                    self.debugger_active = False
                
                # BOOL WINAPI ContinueDebugEvent( dwProcessId, dwThreadId, dwContinueStatus)
                print "Continuing", debug_event.dwProcessId, debug_event.dwThreadId             
                kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)
                
    def detach(self):
        
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting process."
            return True
        
        else:
            sys.stderr.write("Error: Failed to detach from process\n")
            return True
            
    def run(self):
        # Poll the debugee for debugging events
        raw_input("Press enter to begin waiting for debug events...")
        
        while self.debugger_active == True:
            self.get_debug_event()
            
            
    def get_last_error(self):
        return kernel32.GetLastError()

    def dump_thread_contexts(self):        
        threads = self.enumerate_threads(self.pid)

        for thread in threads:
            thread_ctx = self.get_thread_context(thread_id=thread)

            print "ThreadID: {}".format(thread)
            print "Instruction pointer RIP: {:016X}".format(thread_ctx.Rip)
            
