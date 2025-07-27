/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf;

public class HiveBinHeader {

    /// <summary>
    /// ASCII string "hbin"
    /// </summary>
    public static readonly string HbinSignature = "hbin";

    public string Signature { get; private set; }
    public uint Offset { get; private set; }
    public uint Size { get; private set; }
    public ulong Reserved { get; private set; }
    public ulong Timestamp { get; private set; }
    public uint Spare { get; private set; }

    public HiveBinHeader(ReadOnlySpan<byte> data) {

        if (data.Length < 32)
            throw new ArgumentException("The specified buffer does not contain a hive bin header (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..4]).Replace("\0", string.Empty).Trim();
        this.Offset = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.Size = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.Reserved = BinaryPrimitives.ReadUInt64LittleEndian(data[12..20]);
        this.Timestamp = BinaryPrimitives.ReadUInt64LittleEndian(data[20..28]);
        this.Spare = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);

    }

}