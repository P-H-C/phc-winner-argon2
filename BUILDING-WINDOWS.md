# Building Argon2 on Windows (MSVC)
This document describes how to build the official Argon2 project from source on Windows using Microsoft Visual Studio Build Tools.

---

# Requirements

- Windows 10/11
- Visual Studio 2022 Build Tools
- MSVC C/C++ Compiler
- Windows SDK
- PowerShell or Developer Command Prompt

Verify the compiler:

```cmd
cl
```

Example output:

```
Microsoft (R) C/C++ Optimizing Compiler Version 19.xx
```

Verify the linker:

```cmd
link
```

---

# Clone Repository

```bash
git clone https://github.com/P-H-C/phc-winner-argon2.git
cd phc-winner-argon2
```

---

# Repository Structure

```
phc-winner-argon2
│
├── include/
├── src/
│   ├── argon2.c
│   ├── core.c
│   ├── encoding.c
│   ├── ref.c
│   ├── thread.c
│   ├── run.c
│   ├── bench.c
│   ├── test.c
│   └── blake2/
│       └── blake2b.c
│
├── vs2015/
├── Argon2.sln
└── Makefile
```

---

# Compile Source Files

Open **Developer Command Prompt for Visual Studio**.

Compile each source file:

```cmd
cl /c /Iinclude /Isrc src\argon2.c
cl /c /Iinclude /Isrc src\core.c
cl /c /Iinclude /Isrc src\encoding.c
cl /c /Iinclude /Isrc src\ref.c
cl /c /Iinclude /Isrc src\thread.c
cl /c /Iinclude /Isrc src\blake2\blake2b.c
cl /c /Iinclude /Isrc src\run.c
```

After compilation:

```
argon2.obj
core.obj
encoding.obj
ref.obj
thread.obj
blake2b.obj
run.obj
```

---

# Link Executable

Create the executable:

```cmd
link run.obj ^
     argon2.obj ^
     core.obj ^
     encoding.obj ^
     ref.obj ^
     thread.obj ^
     blake2b.obj ^
     /OUT:argon2.exe
```

Output:

```
argon2.exe
```

---

# Build DLL

Create a dynamic library:

```cmd
link /DLL ^
     argon2.obj ^
     core.obj ^
     encoding.obj ^
     ref.obj ^
     thread.obj ^
     blake2b.obj ^
     /OUT:argon2.dll
```

Output:

```
argon2.dll
argon2.lib
argon2.exp
```

---

# Build Static Library

```cmd
lib /OUT:argon2.lib ^
    argon2.obj ^
    core.obj ^
    encoding.obj ^
    ref.obj ^
    thread.obj ^
    blake2b.obj
```

Output:

```
argon2.lib
```

---

# Verify Build

Run the executable:

```cmd
argon2.exe
```

Example output:

```
Usage:
argon2.exe [-h] salt ...
```

---

# Inspect the Binary

List exported symbols:

```cmd
dumpbin /EXPORTS argon2.dll
```

Inspect object file:

```cmd
dumpbin /SYMBOLS core.obj
```

Disassemble:

```cmd
dumpbin /DISASM argon2.exe
```

---

# Build Using Visual Studio

Instead of compiling manually:

```
Argon2.sln
```

Open the solution.

Choose:

```
Build
→ Build Solution
```

or from the command line:

```cmd
msbuild Argon2.sln /p:Configuration=Release /p:Platform=x64
```

---

# Common Errors

## LNK1561

```
LINK : fatal error LNK1561:
entry point must be defined
```

Cause:

You attempted to build an executable without `run.c` (which provides `main()`).

Solution:

Compile `run.c` and include `run.obj` during linking.

---

## Missing include

```
fatal error C1083
```

Solution:

Verify include paths:

```cmd
/Iinclude
/Isrc
```

---

## Compiler Not Found

```
'cl' is not recognized
```

Solution:

Use the **Developer Command Prompt for Visual Studio** or run:

```cmd
vcvars64.bat
```

---

# Build Flow

```
Source Files (.c)
        │
        ▼
Compiler (cl.exe)
        │
        ▼
Object Files (.obj)
        │
        ▼
Linker (link.exe)
        │
        ├──────────────┐
        ▼              ▼
argon2.exe       argon2.dll
```

---

# Linux Equivalent

| Windows | Linux |
|----------|--------|
| `.obj` | `.o` |
| `.dll` | `.so` |
| `.lib` | `.a` |
| `cl.exe` | `clang` / `gcc` |
| `link.exe` | `ld` (invoked by the compiler) |
| `msbuild` | `make` |

Linux build:

```bash
make CC=clang
```

Windows manual build:

```cmd
cl ... → .obj
link ... → .exe/.dll
```

---

# Notes

- The official Makefile is written for GNU Make and is **not compatible with `nmake`**.
- On Windows, use either:
  - Visual Studio (`Argon2.sln`)
  - `msbuild`
  - Manual `cl.exe` + `link.exe` commands as shown above.
- Manual compilation is useful for understanding how the build process works and for debugging compilation or linker issues.

---
