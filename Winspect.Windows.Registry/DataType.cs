/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Windows.Registry;

/// <summary>
/// Predefined Windows Registry data types.
/// </summary>
public enum DataType : uint {

    /// <summary>
    /// REG_NONE - No value type.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// REG_SZ - Unicode null terminated string.
    /// </summary>
    String = 0x01,

    /// <summary>
    /// REG_EXPAND_SZ - Unicode null terminated string with environment variable references.
    /// </summary>
    ExpandString = 0x02,

    /// <summary>
    /// REG_BINARY - Free form binary.
    /// </summary>
    Binary = 0x03,

    /// <summary>
    /// REG_DWORD - 32-bit number.
    /// </summary>
    Dword = 0x04,

    /// <summary>
    /// REG_DWORD_LITTLE_ENDIAN - 32-bit number (same as REG_DWORD).
    /// </summary>
    Dword_LittleEndian = Dword,

    /// <summary>
    /// REG_DWORD_BIG_ENDIAN - 32-bit number (big endian).
    /// </summary>
    Dword_BigEndian = 0x05,

    /// <summary>
    /// REG_LINK - Symbolic link (unicode).
    /// </summary>
    Link = 0x06,

    /// <summary>
    /// REG_MULTI_SZ - Multiple unicode strings.
    /// </summary>
    MultiString = 0x07,

    /// <summary>
    /// REG_RESOURCE_LIST - Resource list in the resource map.
    /// </summary>
    ResourceList = 0x08,

    /// <summary>
    /// REG_FULL_RESOURCE_DESCRIPTOR - Resource list in the hardware description.
    /// </summary>
    FullResourceDescriptor = 0x09,

    /// <summary>
    /// REG_RESOURCE_REQUIREMENTS_LIST
    /// </summary>
    ResourceRequirementsList = 0x0A,

    /// <summary>
    /// REG_QWORD - 64-bit number.
    /// </summary>
    Qword = 0x0B,

    /// <summary>
    /// REG_QWORD_LITTLE_ENDIAN - 64-bit number (same as REG_QWORD).
    /// </summary>
    Qword_LittleEndian = Qword,

}