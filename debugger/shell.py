import sys

class Shell():
    
    def __init__(self, debugger):
        self.debugger = debugger
    
    def prompt(self):
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
                return f(command)
                
            else:
                sys.stderr.write('Bad command. Try q to detach and quit, or n to continue\n')
            
            
    def q(self, command):
        """Quit"""
        print "[*] Detaching"
        self.debugger.debugger_active = False
        
        return True
    
    def n(self, command):
        """Next - Continue execution"""
        return