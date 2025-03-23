/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Headers;

// Sources: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
//          winnt.h (version 10.0.22621.0)

public enum Subsystem : ushort {

    /// <summary>
    /// An unknown subsystem
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Device drivers and native Windows processes
    /// </summary>
    Native = 1,

    /// <summary>
    /// The Windows graphical user interface (GUI) subsystem
    /// </summary>
    WindowsGui = 2,

    /// <summary>
    /// The Windows character subsystem
    /// </summary>
    WindowsCui = 3,

    /// <summary>
    /// The OS/2 character subsystem
    /// </summary>
    Os2Cui = 5,

    /// <summary>
    /// The Posix character subsystem
    /// </summary>
    PosixCui = 7,

    /// <summary>
    /// Native Win9x driver
    /// </summary>
    NativeWindows = 8,

    /// <summary>
    /// Windows CE
    /// </summary>
    WindowsCeGui = 9,

    /// <summary>
    /// An Extensible Firmware Interface (EFI) application
    /// </summary>
    EfiApplication = 10,

    /// <summary>
    /// An EFI driver with boot services
    /// </summary>
    EfiBootServiceDriver = 11,

    /// <summary>
    /// An EFI driver with run-time services
    /// </summary>
    EfiRuntimeDriver = 12,

    /// <summary>
    /// An EFI ROM image
    /// </summary>
    EfiRom = 13,

    /// <summary>
    /// XBOX
    /// </summary>
    Xbox = 14,

    /// <summary>
    /// Windows boot application
    /// </summary>
    WindowsBootApplication = 16,

    /// <summary>
    /// 
    /// </summary>
    XboxCodeCatalog = 17,

}