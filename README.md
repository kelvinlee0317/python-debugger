JEWDBG
---------

A completely inoffensive debugger for Windows written in Python.

To debug 64-bit executables, please use 64-bit Python 2.7
(Only 64-bit executables are currently supported)

From an _Administrator_ shell, try
`python dbg.py -r C:\Windows\System32\calc.exe`

Please install distorm3 to use disassembly

Valid commands in debug shell:
q -- quit
n -- continue
d -- show disassembly at current instruction
s -- single-step


