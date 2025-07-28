/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf.Records;

public class IndexRootRecord : Record {

    /// <summary>
    /// ASCII string "ri"
    /// </summary>
    public static readonly string RiSignature = "ri";

    public string Signature { get; private set; }
    public ushort NumberOfElements { get; private set; }
    public uint[] Elements { get; private set; }

    public override RecordType Type => RecordType.IndexRoot;

    public IndexRootRecord(ReadOnlySpan<byte> data) {

        if (data.Length < 4)
            throw new ArgumentException("The specified buffer does not contain an ri record (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..2]);
        this.NumberOfElements = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);

        if (data.Length < (4 + (4 * this.NumberOfElements)))
            throw new ArgumentException("The specified buffer does not contain an ri record (buffer too small).", nameof(data));

        this.Elements = new uint[this.NumberOfElements];
        for (ushort i = 0; i < this.NumberOfElements; ++i)
            this.Elements[i] = BinaryPrimitives.ReadUInt32LittleEndian(data[(4 + (i * 4))..(8 + (i * 4))]);

    }

}