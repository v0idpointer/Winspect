/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf.Records;

public class FastLeafRecord : Record {

    /// <summary>
    /// ASCII string "lf"
    /// </summary>
    public static readonly string LfSignature = "lf";

    public string Signature { get; private set; }
    public ushort NumberOfElements { get; private set; }
    public (uint Offset, string Hint)[] Elements { get; private set; }

    public override RecordType Type => RecordType.FastLeaf;

    public FastLeafRecord(ReadOnlySpan<byte> data) {

        if (data.Length < 4)
            throw new ArgumentException("The specified buffer does not contain an lf record (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..2]);
        this.NumberOfElements = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);

        if (data.Length < (4 + (8 * this.NumberOfElements)))
            throw new ArgumentException("The specified buffer does not contain an lf record (buffer too small).", nameof(data));

        this.Elements = new (uint Offset, string Hint)[this.NumberOfElements];
        for (ushort i = 0; i < this.NumberOfElements; ++i) {

            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(data[(4 + (i * 8))..(8 + (i * 8))]);
            string hint = Encoding.ASCII.GetString(data[(8 + (i * 8))..(12 + (i * 8))]).Replace("\0", string.Empty).Trim();

            this.Elements[i] = (offset, hint);

        }

    }

}