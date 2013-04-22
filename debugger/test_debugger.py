import debugger
import sys

dbgr = debugger.Debugger()

if len(sys.argv) > 1:
    dbgr.attach(sys.argv[1])
    
else:
    pid = raw_input("Enter the PID of the process to attach to: ")
    dbgr.attach(pid)

dbgr.run()

dbgr.detach()

