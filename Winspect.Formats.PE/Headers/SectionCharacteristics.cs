/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Formats.PE.Headers;

// Sources: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
//          winnt.h (version 10.0.22621.0)

[Flags]
public enum SectionCharacteristics : uint {

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeReg = 0x00000000,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeDsect = 0x00000001,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeNoLoad = 0x00000002,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeGroup = 0x00000004,

    /// <summary>
    /// The section should not be padded to the next boundary.
    /// </summary>
    TypeNoPad = 0x00000008,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeCopy = 0x00000010,

    /// <summary>
    /// The section contains executable code.
    /// </summary>
    CntCode = 0x00000020,

    /// <summary>
    /// The section contains initialized data.
    /// </summary>
    CntInitializedData = 0x00000040,

    /// <summary>
    /// The section contains uninitialized data.
    /// </summary>
    CntUninitializedData = 0x00000080,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    LnkOther = 0x00000100,

    /// <summary>
    /// The section contains comments or other information. The .drectve section has this type.
    /// </summary>
    LnkInfo = 0x00000200,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    TypeOver = 0x00000400,

    /// <summary>
    /// The section will not become part of the image.
    /// </summary>
    LnkRemove = 0x00000800,

    /// <summary>
    /// The section contains COMDAT data.
    /// </summary>
    LnkComdat = 0x00001000,

    /// <summary>
    /// 
    /// </summary>
    MemProtected = 0x00004000,

    /// <summary>
    /// Reset speculative exceptions handling bits in the TLB entries for this section.
    /// </summary>
    NoDeferSpecExec = 0x00004000,

    /// <summary>
    /// The section contains data referenced through the global pointer (GP).
    /// </summary>
    GpRel = 0x00008000,

    /// <summary>
    /// 
    /// </summary>
    MemFarData = 0x00008000,

    /// <summary>
    /// 
    /// </summary>
    MemSysHeap = 0x00010000,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    MemPurgeable = 0x00020000,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    Mem16Bit = 0x00020000,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    MemLocked = 0x00040000,

    /// <summary>
    /// Reserved for future use.
    /// </summary>
    MemPreload = 0x00080000,

    /// <summary>
    /// Align data on a 1-byte boundary.
    /// </summary>
    Align1Bytes = 0x00100000,

    /// <summary>
    /// Align data on a 2-byte boundary.
    /// </summary>
    Align2Bytes = 0x00200000,

    /// <summary>
    /// Align data on a 4-byte boundary.
    /// </summary>
    Align4Bytes = 0x00300000,

    /// <summary>
    /// Align data on an 8-byte boundary.
    /// </summary>
    Align8Bytes = 0x00400000,

    /// <summary>
    /// Align data on a 16-byte boundary.
    /// </summary>
    Align16Bytes = 0x00500000,

    /// <summary>
    /// Align data on a 32-byte boundary.
    /// </summary>
    Align32Bytes = 0x00600000,

    /// <summary>
    /// Align data on a 64-byte boundary.
    /// </summary>
    Align64Bytes = 0x00700000,

    /// <summary>
    /// Align data on a 128-byte boundary.
    /// </summary>
    Align128Bytes = 0x00800000,

    /// <summary>
    /// Align data on a 256-byte boundary.
    /// </summary>
    Align256Bytes = 0x00900000,

    /// <summary>
    /// Align data on a 512-byte boundary.
    /// </summary>
    Align512Bytes = 0x00A00000,

    /// <summary>
    /// Align data on a 1024-byte boundary.
    /// </summary>
    Align1024Bytes = 0x00B00000,

    /// <summary>
    /// Align data on a 2048-byte boundary.
    /// </summary>
    Align2048Bytes = 0x00C00000,

    /// <summary>
    /// Align data on a 4096-byte boundary.
    /// </summary>
    Align4096Bytes = 0x00D00000,

    /// <summary>
    /// Align data on an 8192-byte boundary.
    /// </summary>
    Align8192Bytes = 0x00E00000,

    /// <summary>
    /// The section contains extended relocations.
    /// </summary>
    LnkNrelocOvfl = 0x01000000,

    /// <summary>
    /// The section can be discarded as needed.
    /// </summary>
    MemDiscardable = 0x02000000,

    /// <summary>
    /// The section cannot be cached.
    /// </summary>
    MemNotCached = 0x04000000,

    /// <summary>
    /// The section is not pageable.
    /// </summary>
    MemNotPaged = 0x08000000,

    /// <summary>
    /// The section can be shared in memory.
    /// </summary>
    MemShared = 0x10000000,

    /// <summary>
    /// The section can be executed as code.
    /// </summary>
    MemExecute = 0x20000000,

    /// <summary>
    /// The section can be read.
    /// </summary>
    MemRead = 0x40000000,

    /// <summary>
    /// The section can be written to.
    /// </summary>
    MemWrite = 0x80000000,

}