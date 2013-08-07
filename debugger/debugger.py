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
        self.h_process          = None;
        self.pid                = None;
        self.debugger_active    = False;
        
        
    
    def load(self, path_to_exe):
        
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want to see the GUI
        creation_flags = DEBUG_PROCESS
        
        #instantiate the structs
        startup_info = STARTUPINFO()
        process_info = PROCESS_INFORMATION()
        
        startup_info.dwFlags        = 0x1
        startup_info.wShowWindow    = 0x0
        
        startup_info.cb  = sizeof(startup_info)
        
        #http://msdn.microsoft.com/en-us/library/windows/desktop/ms682425%28v=vs.85%29.aspx
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
            #self.h_process = self.open_process(process_info.dwProcessId)
            
            self.debugger_active = True
            return process_info.dwProcessId
            
            
        else:
            print   "[*] Error: 0x%08x." % kernel32.GetLastError()
            
    def open_process(self, pid):
        # HANDLE WINAPI OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId)
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        print "Opened pid: {}".format(pid)
        #if h_process == 0:
        #    print "[*] Error opening process: %s" % kernel32.GetLastError()   
        return h_process
    
    def enumerate_threads(self, pid):
        """ Loop through all the threads given by the system, match those with our PID """
        thread_entry = THREADENTRY32()
        thread_list = []
        # Call a general WINAPI system info function.
        # WTF is with your weird function names, Microsoft?
        # http://msdn.microsoft.com/en-us/library/windows/desktop/ms682489%28v=vs.85%29.aspx
        snapshot= kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,
                                                    pid)
        
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
            return thread_list
        
    def get_thread_context(selfself, thread_id):
        """ Get the thread context struct for a given thread id"""
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        # Obtain a handle to the thread
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
                self.debugger_active    = True
                self.pid                = pid
                
        else:
            print "[*] Unable to attach to the process to debug.\n kernel32.DebugActiveProcess:: Return code {}.".format(success)\
                       + " Error Code {}.\n".format(self.get_last_error()) \
                       + " Are you trying to debug a 64-bit process with 32-bit Python?"
            
    def get_debug_event(self):
        """ Loop, waiting for debugging events.
        
            TODO:  Add callback arg for action on given event type
        """
        
        debug_event     = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
                # TODO: Event handlers
                print "Debug event code: {}\nProcessID: {}\nThreadID: {}".format(debug_event.dwDebugEventCode,
                                                                                  debug_event.dwProcessId,
                                                                                  debug_event.dwThreadId)
                                                                                   
                input = raw_input("Detach? [y to detach] : ")
                if input == "y":
                    self.debugger_active = False
                # BOOL WINAPI ContinueDebugEvent( dwProcessId, dwThreadId, dwContinueStatus)
                kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)
                
    def detach(self):
        
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging. Exiting process."
            return True
        
        else:
            print "Error: Failed to detach from process"
            return True
            
    def run(self):
        # Poll the debugee for debugging events
        
        while self.debugger_active == True:
            self.get_debug_event()
            
            
    def get_last_error(self):
        return kernel32.GetLastError()
            
                
                    
            

if __name__ == '__main__':
    if len(sys.argv) > 1:
        path_to_exe = sys.argv[1]
        debugger = Debugger()
        pid = debugger.load(path_to_exe)
        
        #debugger.attach(pid)
        debugger.run()
        
        debugger.detach()
        
    
        