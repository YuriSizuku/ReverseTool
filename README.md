# ReverseTool

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/yurisizuku/reversetool?color=green&label=ReverseTool)![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/YuriSizuku/ReverseTool/build_wintools.yml?label=build_wintools)  

🍀 Libraries (single header file) for my reverse projects.  
Scripts for localization are moved to [LocalizationTool](https://github.com/YuriSizuku/LocalizationTool).  

Projects based on this repo:  

- [MemoryModule](https://github.com/YuriSizuku/MemoryModule)  
- [MiniVFS](https://github.com/YuriSizuku/MiniVFS)
- [GalgameReverse](https://github.com/YuriSizuku/GalgameReverse)  

## Components

### cross platform libraries  

- `windllin.py`, staticly inject `dll` to a `exe`  
- `wincoff.py`, method for parsing `coff` object file  

### windows platform libraries

In `project`,  `Makefile` for `gcc` (llvm-mingw or mingw-w64), `tcc` (not support inline) and `sln` for `msvc`.  All of them are compatible for `win xp` and above.  

- `winhook.h`,  single header file for dynamic hook functions, such as IAT hook, inline hook  
- `winpe.h`, single header file for parsing windows PE structure, adjust RELOC, ADDRS, or IAT  
- `windyn.h`, single header file for dynamic binding windows system api without IAT.  
- `winloader.c`, start a exe with a `dll` injected, see [Release](https://github.com/YuriSizuku/ReverseUtil/releases)  
