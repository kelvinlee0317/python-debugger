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
            self.h_process = self.open_process(process_info.dwProcessId)
            
            return process_info.dwProcessId
            
            
        else:
            print   "[*] Error: 0x%08x." % kernel32.GetLastError()
            
    def open_process(self, pid):
        # HANDLE WINAPI OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId)
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False)
        print pid
        #if h_process == 0:
        #    print "[*] Error opening process: %s" % kernel32.GetLastError()   
        return h_process
    
    def attach(self, pid):
        pid = DWORD(int(pid))
        self.h_process = self.open_process(pid)
        print self.h_process
        
        
        # We attempt to attach to the process
        # if this fails we exit the call
        # BOOL WINAPI DebugActiveProcess(dwProcessId)
        if kernel32.DebugActiveProcess(pid):
                self.debugger_active    = True
                self.pid                = pid
                
        else:
            print "[*] Unable to attach to the process to debug. Are you trying to debug a 64-bit process with 32-bit Python?"
            
    def get_debug_event(self):
        
        debug_event     = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
                # TODO: Event handlers
                raw_input("Press a key to continue...")
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
            
                
                    
            

if __name__ == '__main__':
    if len(sys.argv) > 1:
        path_to_exe = sys.argv[1]
        debugger = Debugger()
        debugger.load(path_to_exe)
        