PE-Injector
===========

Inject shellcode into extra file alignment padding of a PE and change the entry point to point to the shellcode. On execution, the shellcode will be executed, then return control flow to the original entry point of the program. Perhaps a nice way to maintain persistence?