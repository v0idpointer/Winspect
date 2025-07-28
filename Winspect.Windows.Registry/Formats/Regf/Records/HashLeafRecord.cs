/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf.Records;

public class HashLeafRecord : Record {

    /// <summary>
    /// ASCII string "lh"
    /// </summary>
    public static readonly string LhSignature = "lh";

    public string Signature { get; private set; }
    public ushort NumberOfElements { get; private set; }
    public (uint Offset, uint Hash)[] Elements { get; private set; }

    public override RecordType Type => RecordType.HashLeaf;

    public HashLeafRecord(ReadOnlySpan<byte> data) {

        if (data.Length < 4)
            throw new ArgumentException("The specified buffer does not contain an lh record (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..2]);
        this.NumberOfElements = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);

        if (data.Length < (4 + (8 * this.NumberOfElements)))
            throw new ArgumentException("The specified buffer does not contain an lh record (buffer too small).", nameof(data));

        this.Elements = new (uint Offset, uint Hash)[this.NumberOfElements];
        for (ushort i = 0; i < this.NumberOfElements; ++i) {

            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(data[(4 + (i * 8))..(8 + (i * 8))]);
            uint hash = BinaryPrimitives.ReadUInt32LittleEndian(data[(8 + (i * 8))..(12 + (i * 8))]);

            this.Elements[i] = (offset, hash);

        }

    }

}