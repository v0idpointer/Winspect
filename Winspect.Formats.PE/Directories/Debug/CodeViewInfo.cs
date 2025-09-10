/*
   Windows Inspection Utilities
   Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Formats.PE.Directories.Debug;

/// <summary>
/// Represents the CV_INFO_PDB70 structure.
/// </summary>
public class CodeViewInfo : DebugInfo {

    /// <summary>
    /// RSDS
    /// </summary>
    public static readonly string RsdsSignature = "RSDS";

    public string Signature { get; private set; }
    public Guid Guid { get; private set; }
    public uint Age { get; private set; }
    public string PdbFilename { get; private set; }

    public override DebugType DebugType => DebugType.CodeView;

    public CodeViewInfo(ReadOnlySpan<byte> data) {

        if (data.Length < 24)
            throw new ArgumentException("The specified buffer is too small to contain the CV_INFO_PDB70 structure.", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..4]);
        this.Guid = new Guid(data[4..20]);
        this.Age = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);

        ReadOnlySpan<byte> filenameData = data[24..];
        if (filenameData.IsEmpty) {
            this.PdbFilename = string.Empty;
            return;
        }

        this.PdbFilename = Encoding.ASCII.GetString(filenameData);

    }

}
