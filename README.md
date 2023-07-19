# ttd2mdmp
Convert TTD traces into MiniDumps ⏲️

https://github.com/airbus-cert/ttd2mdmp/raw/main/assets/demo.mp4

## Installation

This is a classical cmake project. Just run 
```posh
mkdir build 
cd build
cmake ..
cmake --build .
```

You will need to copy the `TTDReplay.dll` and `TTDReplayCPU.dll` DLLs into the same folder as the executable to make it work.
See [the yara-ttd installation process](https://github.com/airbus-cert/yara-ttd#install) if you need more information.

## Usage

```posh
.\ttd2mdmp <path\to\trace.run> <path\to\out.mdmp> <position>
```

The first argument is the trace filename generated by TTD.
The second argument is the output filename. It will be sufixed with a number (to manage multiple MiniDumps generation).
To generate a MiniDump from a TTD trace, you need a third argument to specify a time position. It can be:
- a time cursor (`major:minor` in hex, without `0x`) 
- a `module!function` to hook (will generate as many MiniDumps as functions hooked).

```posh
.\ttd2mdmp .\trace.run .\TestCursor.mdmp "300:A1" 
.\ttd2mdmp .\trace.run .\TestHook.mdmp "ntdll!NtCreateThread"
```

## Collected information

Here is a list of the information currently collected from the trace into the MiniDumps:

🧵 Threads:
- Thread id
- Thread stack range
- Thread stack
- Thread context
- TEB

🧩 Modules:
- Module name
- Module memory range
- Module memory

📑 Heap 
- Heap ranges generated by tracing `ntdll!NtAllocateVirtualMemory` calls
- Heap memory 

⚙️ System Information 
- Processor architecture

## Upcoming work

- [x] Handle freed heap chunks by tracing `ntdll!NtFreeVirtualMemory`
- [ ] Processor architecture bug when recording a trace
- [ ] Multi arch, only x64 supported for now 
- [x] MakeFile + Installation doc
- [ ] Python bindings
