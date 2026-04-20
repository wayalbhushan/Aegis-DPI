# Aegis DPI - Windows Setup Guide

This guide will walk you through compiling and running the Aegis DPI Engine locally on a Windows platform. Given our strict constraint against external networking dependencies (`libpcap`), Aegis natively operates without external driver requirements making compiling very straightforward.

---

## Prerequisites

You'll need a C++ compiler capable of handling robust **C++17** syntaxes and **CMake (version 3.16+)**.

You have two main options:

1. **Option 1: MSVC (Visual Studio 2022)** - Ideal if you already have VS installed.
2. **Option 2: MinGW-w64 (MSYS2)** - Best for lightweight, native GCC build pipelines.

---

## Option 1: Microsoft Visual Studio (MSVC)

### Step 1: Install Visual Studio & CMake
1. Install **Visual Studio 2022 Community**.
2. Within the Visual Studio Installer, select the **Desktop development with C++** workload. This will automatically install MSVC, CMake, and the native Windows SDK packages.

### Step 2: Build the Code
1. Open up a "x64 Native Tools Command Prompt for VS 2022" (you can search for this in the Windows Start menu).
2. Navigate to your Aegis project root folder:
   ```cmd
   cd C:\Users\Username\Desktop\Aegis-DPI
   ```
3. Generate the build files utilizing CMake:
   ```cmd
   cmake -B build -S .
   ```
4. Build the executable as a high-performance Release binary:
   ```cmd
   cmake --build build --config Release
   ```

You will find the engineered executable compiled natively at `build\Release\aegis_dpi.exe`.

---

## Option 2: MinGW-w64 (GCC / MSYS2)

### Step 1: Install MYSY2 and GCC
1. Download and run the installer from the [MSYS2 Website](https://www.msys2.org/).
2. Open the "MSYS2 MINGW64" terminal from your Start menu sequence.
3. Install GCC and CMake:
   ```bash
   pacman -Syu
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-make
   ```
4. Map the newly installed binaries directory (`C:\msys64\mingw64\bin`) to your Windows environment variables (`PATH`). 

### Step 2: Build the Code
1. Open PowerShell or a standard Command Prompt.
2. Go to the project directory:
   ```cmd
   cd C:\Users\Username\Desktop\Aegis-DPI
   ```
3. Create the CMake Ninja or Makefile topology:
   ```cmd
   cmake -G "MinGW Makefiles" -B build -S .
   ```
4. Trigger the compilation pipeline:
   ```cmd
   cmake --build build --config Release
   ```

You will now find the executable nested inside `build\aegis_dpi.exe`.

---

## Running Aegis

Once compiled, you can benchmark the executable directly inside Powerhsell or CMD. Note that you must provide a legitimate packet capture (`.pcap`) locally stored. 

```cmd
# Navigate to where your executable generated
cd build\Release\

# Process the dump file, block particular IP, and dispatch dynamically
.\aegis_dpi.exe my_capture.pcap clean_output.pcap --block-ip 123.45.67.89 --lbs 4 --fps 4
```

### Acquiring Test Packets
If you need immediate runtime validation:
1. Setup Wireshark locally.
2. Record traffic across your primary interface for ~60 seconds.
3. Stop the capture and `File > Save As` -> formatting strictly as standard `PCAP`.
4. Provide the exact path directly to Aegis inside your execution chain mapping.
