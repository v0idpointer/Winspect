/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/
namespace Winspect.Windows.Registry.Formats.Regf.Records;

public enum RecordType {

    /// <summary>
    /// "li" record
    /// </summary>
    IndexLeaf,

    /// <summary>
    /// "lf" record
    /// </summary>
    FastLeaf,

    /// <summary>
    /// "lh" record
    /// </summary>
    HashLeaf,

    /// <summary>
    /// "ri" record
    /// </summary>
    IndexRoot,

    /// <summary>
    /// "nk" record
    /// </summary>
    KeyNode,

    /// <summary>
    /// "vk" record
    /// </summary>
    KeyValue,

    /// <summary>
    /// "sk" record
    /// </summary>
    KeySecurity,

    /// <summary>
    /// "db" record
    /// </summary>
    BigData,

}