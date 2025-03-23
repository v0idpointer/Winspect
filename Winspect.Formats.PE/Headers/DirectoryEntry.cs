/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Headers;

public enum DirectoryEntry {

    /// <summary>
    /// Export Directory
    /// </summary>
    Export = 0,

    /// <summary>
    /// Import Directory
    /// </summary>
    Import = 1,

    /// <summary>
    /// Resource Directory
    /// </summary>
    Resource = 2,

    /// <summary>
    /// Exception Directory
    /// </summary>
    Exception = 3,

    /// <summary>
    /// Security Directory
    /// </summary>
    Security = 4,

    /// <summary>
    /// Base Relocation Table
    /// </summary>
    BaseReloc = 5,

    /// <summary>
    /// Debug Directory
    /// </summary>
    Debug = 6,

    /// <summary>
    /// Architecture Specific Data
    /// </summary>
    Architecture = 7,

    /// <summary>
    /// RVA of GP
    /// </summary>
    GlobalPtr = 8,

    /// <summary>
    /// TLS Directory
    /// </summary>
    Tls = 9,

    /// <summary>
    /// Load Configuration Directory
    /// </summary>
    LoadConfig = 10,

    /// <summary>
    /// Bound Import Directory in headers
    /// </summary>
    BoundImport = 11,

    /// <summary>
    /// Import Address Table
    /// </summary>
    Iat = 12,

    /// <summary>
    /// Delay Load Import Descriptors
    /// </summary>
    DelayImport = 13,

    /// <summary>
    /// COM Runtime descriptor
    /// </summary>
    ComDescriptor = 14,

    /// <summary>
    /// Reserved.
    /// </summary>
    Reserved = 15,

}