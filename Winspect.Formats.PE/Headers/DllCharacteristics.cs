/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Formats.PE.Headers;

// Sources: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics
//          winnt.h (version 10.0.22621.0)

[Flags]
public enum DllCharacteristics : ushort {

    None = 0x0000,

    /// <summary>
    /// Reserved.
    /// </summary>
    ProcessInit = 0x0001,

    /// <summary>
    /// Reserved.
    /// </summary>
    ProcessTerm = 0x0002,

    /// <summary>
    /// Reserved.
    /// </summary>
    ThreadInit = 0x0004,

    /// <summary>
    /// Reserved.
    /// </summary>
    ThreadTerm = 0x0008,

    /// <summary>
    /// Image can handle a high entropy 64-bit virtual address space.
    /// </summary>
    HighEntropyVa = 0x0020,

    /// <summary>
    /// DLL can be relocated at load time.
    /// </summary>
    DynamicBase = 0x0040,

    /// <summary>
    /// Code Integrity checks are enforced.
    /// </summary>
    ForceIntegrity = 0x0080,

    /// <summary>
    /// Image is NX compatible.
    /// </summary>
    NxCompat = 0x0100,

    /// <summary>
    /// Isolation aware, but do not isolate the image.
    /// </summary>
    NoIsolation = 0x0200,

    /// <summary>
    /// Does not use structured exception (SE) handling. No SE handler may be called in this image.
    /// </summary>
    NoSeh = 0x0400,

    /// <summary>
    /// Do not bind the image.
    /// </summary>
    NoBind = 0x0800,

    /// <summary>
    /// Image must execute in an AppContainer.
    /// </summary>
    AppContainer = 0x1000,

    /// <summary>
    /// A WDM driver.
    /// </summary>
    WdmDriver = 0x2000,

    /// <summary>
    /// Image supports Control Flow Guard.
    /// </summary>
    GuardCf = 0x4000,

    /// <summary>
    /// Terminal Server aware.
    /// </summary>
    TerminalServerAware = 0x8000,

}