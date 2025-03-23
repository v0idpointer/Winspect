/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Formats.PE.Headers;

// Sources: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
//          winnt.h (version 10.0.22621.0)

[Flags]
public enum Characteristics : ushort {

    None = 0x0000,

    /// <summary>
    /// Relocation information was stripped from the file.
    /// </summary>
    RelocsStripped = 0x0001,

    /// <summary>
    /// File is executable (i.e. no unresolved external references).
    /// </summary>
    ExecutableImage = 0x0002,

    /// <summary>
    /// COFF line numbers have been removed.
    /// </summary>
    LineNumsStripped = 0x0004,

    /// <summary>
    /// COFF symbol table entries for local symbols have been removed.
    /// </summary>
    LocalSymsStripped = 0x0008,
    
    /// <summary>
    /// Aggressively trim the working set.
    /// </summary>
    AggressiveWsTrim = 0x0010,

    /// <summary>
    /// The application can handle addresses larger than 2 GB.
    /// </summary>
    LargeAddressAware = 0x0020,

    /// <summary>
    /// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory.
    /// </summary>
    BytesReversedLo = 0x0080,

    /// <summary>
    /// The machine is based on a 32-bit word architecture.
    /// </summary>
    Bits32Machine = 0x0100,

    /// <summary>
    /// Debugging information is removed from the image file.
    /// </summary>
    DebugStripped = 0x0200,

    /// <summary>
    /// If the image is on removable media, fully load it and copy it to the swap file.
    /// </summary>
    RemovableRunFromSwap = 0x0400,

    /// <summary>
    /// If the image is on network media, fully load it and copy it to the swap file.
    /// </summary>
    NetRunFromSwap = 0x0800,

    /// <summary>
    /// The image file is a system file.
    /// </summary>
    System = 0x1000,

    /// <summary>
    /// The image file is a dynamic-link library (DLL).
    /// </summary>
    Dll = 0x2000,

    /// <summary>
    /// The file should be run only on a uniprocessor machine.
    /// </summary>
    UpSystemOnly = 0x4000,

    /// <summary>
    /// Big endian: the MSB precedes the LSB in memory.
    /// </summary>
    BytesReversedHi = 0x8000,

}