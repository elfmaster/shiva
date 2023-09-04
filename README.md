# shiva v0.01 x86_64
NOTE: Do not confuse this Shiva with Shiva from the AMP program: https://github.com/advanced-microcode-patching/shiva
which was in-fact forked from here, but has evolved into an JIT binary patching engine for the DARPA AMP program.
This particular version of Shiva works for x86_64 and has different goals.

Shiva is a programmable runtime linker (Program interpreter) for ELF x86_64
ELF microprograms (Shiva modules) are linked into the process address space and given
intricate control over program instrumentation via ShivaTrace API, and in-process debugging
and instrumentation API with innovative debugging and hooking features. 

## Target system

Linux.
Currently only supports x86_64 ELF PIE.
