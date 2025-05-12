/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Directories.Resource;

// Source: https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types

/// <summary>
/// Predefined resource types.
/// </summary>
public enum ResourceType : ushort {

    /// <summary>
    /// Hardware-dependent cursor resource.
    /// </summary>
    Cursor = 1,

    /// <summary>
    /// Bitmap resource.
    /// </summary>
    Bitmap = 2,

    /// <summary>
    /// Hardware-dependent icon resource.
    /// </summary>
    Icon = 3,

    /// <summary>
    /// Menu resource.
    /// </summary>
    Menu = 4,

    /// <summary>
    /// Dialog box.
    /// </summary>
    Dialog = 5,

    /// <summary>
    /// String-table entry.
    /// </summary>
    String = 6,

    /// <summary>
    /// Font directory resource.
    /// </summary>
    FontDir = 7,

    /// <summary>
    /// Font resource.
    /// </summary>
    Font = 8,

    /// <summary>
    /// Accelerator table.
    /// </summary>
    Accelerator = 9,

    /// <summary>
    /// Application-defined resource (raw data).
    /// </summary>
    RcData = 10,

    /// <summary>
    /// Message-table entry.
    /// </summary>
    MessageTable = 11,

    /// <summary>
    /// Hardware-independent cursor resource.
    /// </summary>
    GroupCursor = (ResourceType.Cursor + 11),

    /// <summary>
    /// Hardware-independent icon resource.
    /// </summary>
    GroupIcon = (ResourceType.Icon + 11),

    /// <summary>
    /// Version resource.
    /// </summary>
    Version = 16,

    /// <summary>
    /// Allows a resource editing tool to associate a string with an .rc file. 
    /// Typically, the string is the name of the header file that provides symbolic names. 
    /// The resource compiler parses the string but otherwise ignores the value.
    /// </summary>
    DlgInclude = 17,

    /// <summary>
    /// Plug and Play resource.
    /// </summary>
    PlugPlay = 19,

    /// <summary>
    /// VXD
    /// </summary>
    Vxd = 20,

    /// <summary>
    /// Animated cursor.
    /// </summary>
    AniCursor = 21,

    /// <summary>
    /// Animated icon.
    /// </summary>
    AniIcon = 22,

    /// <summary>
    /// HTML resource.
    /// </summary>
    Html = 23,

    /// <summary>
    /// Side-by-Side Assembly Manifest.
    /// </summary>
    Manifest = 24,

}