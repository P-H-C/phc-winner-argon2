This repository stores a modification of the `Argon2` library.

Original files of the source repository are located in the original repository 
and their 'ReadMe' or description is also available there: 
https://github.com/P-H-C/phc-winner-argon2  

The main purpose of this repository is:
- To add support for cross-platform compilation with the help of `CMake` tool;
- To get rid of platform-dependent compilation tools, such as `make`.

# List of changes

First of all, none of the original source code files are modified. This means 
that all the _C_ (`*.c`) and _H_ (`*.h`) files of the library are used in their 
original unmodified state.

Some of the build targets of the original `Makefile` are ignored, e.g. tests 
are not used. If you need original tests, you can use the original repository 
for this purpose.

While the library itself is not modified, all the documentation and auxiliary 
files are removed from this repository.

This repository mainly focuses on a cross-platform compilation, so most of the 
modifications are related to files for `CMake`.

In addition, this repository offers support for `version.rc` files, used for 
adding useful information into _DLL_ files on _Windows_ operating system, 
making _DLL_ files built with the provided configuration look like a normal 
product on the _Windows_ O.S.  

While the original repository uses weird numbers 
for product version, this repository uses an independent approach to version 
numbers.

# License

Information about license can be found in the `License` file.

# Usage

To build the project you need the `CMake` tool of the latest version.
More information about `CMake` can be found on its website: https://cmake.org/

`CMake` tool is able to create project files for various popular IDEs. The most 
convenient way to use `CMake` is to start its GUI and give it a path to your 
code folder.

The `CMakeLists.txt` file provided here is able to configure the project for 
various use cases. Below are described configuration options.  

## Configuration options

### CFG_USE_AVX

This setting allows to enable support for _AVX_ instructions of your CPU.  
Default value is: _False_.  

### CFG_USE_VERSION_RC

This setting allows to enable support for `version.rc` files used on _Microsoft 
Windows_ operating system.  
Default value is: _False_.

# Feedback

Your feedback is always welcome in the `Issues` section of this repository.
