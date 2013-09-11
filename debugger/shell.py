import sys

try:
    from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
except:
    sys.err.write('Cannot load distorm3 disassembly library')

class Shell():
    
    def __init__(self, debugger):
        self.debugger = debugger
    
    def prompt(self, debug_event):
        self.debug_event = debug_event
        
        while True:
            input = raw_input('> ')
            command = input.split()[0] if input.split() else None
            
            f = None
            if command:
                try:
                    f = getattr(self, command[0])
                except:
                    pass
                
            if f:
                if f(command):
                    return
                
            else:
                sys.stderr.write('Bad command. Try q to detach and quit, or n to continue\n')
            
            
    def q(self, command):
        """Quit"""
        print "[*] Detaching"
        self.debugger.debugger_active = False
        
        return True
    
    def n(self, command):
        """Next - Continue execution"""
        return True
    
    def d(self, command):
        try:
            l = Decode(self.debug_event.u.Exception.ExceptionRecord.ExceptionAddress, 
                       self.debugger.read_process_memory(self.debugger.h_process, self.debug_event.u.Exception.ExceptionRecord.ExceptionAddress, 32),
                       Decode64Bits)
            for i in l:
                print "0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2])
        except Exception as e:
            sys.stderr.write('A problem occured in disassembling nearby memory {}\n Do you have distorm3 installed?\n'.format(e))