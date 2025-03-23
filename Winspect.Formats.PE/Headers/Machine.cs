/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Headers;

// Sources: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
//          winnt.h (version 10.0.22621.0)

public enum Machine : ushort {
    
    /// <summary>
    /// The content of this field is assumed to be applicable to any machine type.
    /// </summary>
    Unknown = 0x0000,

    /// <summary>
    /// Useful for indicating we want to interact with the host and not a WoW guest.
    /// </summary>
    TargetHost = 0x0001,

    /// <summary>
    /// Alpha AXP, 32-bit address space
    /// </summary>
    Alpha = 0x0184,

    /// <summary>
    /// Alpha 64, 64-bit address space
    /// </summary>
    Alpha64 = 0x0284,

    /// <summary>
    /// Matsushita AM33
    /// </summary>
    Am33 = 0x01D3,

    /// <summary>
    /// AMD64 (K8)
    /// </summary>
    Amd64 = 0x8664,

    /// <summary>
    /// ARM little endian
    /// </summary>
    Arm = 0x01C0,

    /// <summary>
    /// ARM64 little endian
    /// </summary>
    Arm64 = 0xAA64,

    /// <summary>
    /// ARM Thumb-2 little endian
    /// </summary>
    ArmNt = 0x01C4,

    /// <summary>
    /// AXP 64 (Same as Alpha 64)
    /// </summary>
    Axp64 = Alpha64,

    /// <summary>
    /// EFI byte code
    /// </summary>
    Ebc = 0xEBC,

    /// <summary>
    /// Intel 386 or later processors and compatible processors
    /// </summary>
    I386 = 0x014C,

    /// <summary>
    /// Intel Itanium processor family
    /// </summary>
    Ia64 = 0x0200,

    /// <summary>
    /// LoongArch 32-bit processor family
    /// </summary>
    LoongArch32 = 0x6232,

    /// <summary>
    /// LoongArch 64-bit processor family
    /// </summary>
    LoongArch64 = 0x6264,

    /// <summary>
    /// Mitsubishi M32R little endian
    /// </summary>
    M32R = 0x9041,

    /// <summary>
    /// MIPS16
    /// </summary>
    Mips16 = 0x0266,

    /// <summary>
    /// MIPS with FPU
    /// </summary>
    MipsFpu = 0x0366,

    /// <summary>
    /// MIPS16 with FPU
    /// </summary>
    MipsFpu16 = 0x0466,

    /// <summary>
    /// Power PC little endian
    /// </summary>
    PowerPc = 0x01F0,

    /// <summary>
    /// Power PC with floating point support
    /// </summary>
    PowerPcFp = 0x01F1,

    /// <summary>
    /// MIPS big endian
    /// </summary>
    R3000BigEndian = 0x0160,

    /// <summary>
    /// MIPS little endian
    /// </summary>
    R3000 = 0x0162,

    /// <summary>
    /// MIPS little endian
    /// </summary>
    R4000 = 0x0166,

    /// <summary>
    /// RISC-V 32-bit address space
    /// </summary>
    RiscV32 = 0x5032,

    /// <summary>
    /// RISC-V 64-bit address space
    /// </summary>
    RiscV64 = 0x5064,

    /// <summary>
    /// RISC-V 128-bit address space
    /// </summary>
    RiscV128 = 0x5128,

    /// <summary>
    /// Hitachi SH3
    /// </summary>
    Sh3 = 0x01A2,

    /// <summary>
    /// Hitachi SH3 DSP
    /// </summary>
    Sh3Dsp = 0x01A3,

    /// <summary>
    /// Hitachi SH4
    /// </summary>
    Sh4 = 0x01A6,

    /// <summary>
    /// Hitachi SH5
    /// </summary>
    Sh5 = 0x01A8,

    /// <summary>
    /// Thumb
    /// </summary>
    Thumb = 0x01C2,

    /// <summary>
    /// MIPS little-endian WCE v2
    /// </summary>
    WceMipsV2 = 0x0169,

}