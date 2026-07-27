# Binary Inspector

A Windows PE Binary Inspector written in C using the Win32 API.

## Features

- List files in the current directory
- Display file information
- Hex dump viewer
- Jump to arbitrary file offsets
- Detect binary type using magic numbers
- Parse DOS Header
- Support PE32 and PE32+
- Parse PE Signature
- Parse IMAGE_FILE_HEADER
- Parse IMAGE_OPTIONAL_HEADER
- Parse Section Headers
- Convert RVA to File Offset

## Build

```bash
gcc main.c -o main.c
```

## Example

```
=== DOS Header ===
Magic: MZ
e_lfanew: 0x80

=== IMAGE_FILE_HEADER ===
Machine: x86
Sections: 13

=== IMAGE_OPTIONAL_HEADER ===
Entry Point: 0x12E0
Image Base: 0x400000

=== Section 1 ===
Name: .text
...
```