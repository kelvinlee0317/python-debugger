from debugger.debugger import Debugger
from debugger.shell import Shell

import sys
import argparse
import traceback

# Whether to run the debugger in debug mode (yo dawg)
DEBUG=True

parser = argparse.ArgumentParser(description='The best debugger in the universe.')

parser.add_argument('-r', '--run', dest='exe_path', help='Path to a 64-bit (for now) executable to run')
parser.add_argument('-a', '--attach', dest='pid', type=int, help='PID of a process to attach to')

args = vars(parser.parse_args())

pid = args.get('pid')
exe_path = args.get('exe_path')

if not pid and not exe_path:
    while True:
        try:
            pid = int(raw_input("Enter the PID of the process to attach to: "))
            break
        except:
            print "Invalid integer pid"
 
dbgr = Debugger()
shell = Shell(dbgr)
dbgr.set_bp_callback(shell.prompt)
    
try:
    if pid:    
        print "Attaching to {}".format(pid)
        dbgr.attach(pid)

    else:
        print "Loading {}".format(exe_path)
        dbgr.load(exe_path)


except:
    if DEBUG:
        traceback.print_exc()
    else:
        print "Failed to attach to/load target. Exiting..."

dbgr.run()

dbgr.detach()
