# shiva
Shiva is a programmable runtime linker (Program interpreter) for ELF x64/aarch64 Linux --
ELF microprograms (Shiva modules) are linked into the process address space and given
intricate control over program instrumentation via ShivaTrace API, and in-process debugging
and instrumentation API with innovative debugging and hooking features. 

## Target system

Linux.
Currently only supports x86_64 and aarch64 ELF PIE.
