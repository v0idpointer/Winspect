/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf.Records;

public class KeyValueRecord : Record {

    public static readonly string VkSignature = "vk";

    public string Signature { get; private set; }
    public ushort NameLength { get; private set; }
    public uint DataSize { get; private set; }
    public uint DataOffset { get; private set; }
    public DataType DataType { get; private set; }
    public ushort Flags { get; private set; }
    public ushort Spare { get; private set; }
    public string? ValueName { get; private set; }

    public bool IsInlineData => ((this.DataSize & 0x80000000) == 0x80000000);
    public uint ActualSize => (this.DataSize & 0x7FFFFFFF);

    public override RecordType Type => RecordType.KeyValue;

    public KeyValueRecord(ReadOnlySpan<byte> data) {

        if (data.Length < 20)
            throw new ArgumentException("The specified buffer does not contain a vk record (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..2]);
        this.NameLength = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);
        this.DataSize = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.DataOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.DataType = (DataType)(BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]));
        this.Flags = BinaryPrimitives.ReadUInt16LittleEndian(data[16..18]);
        this.Spare = BinaryPrimitives.ReadUInt16LittleEndian(data[18..20]);

        if (this.NameLength == 0) this.ValueName = null;
        else {

            if (data.Length < (20 + this.NameLength))
                throw new ArgumentException("The specified buffer does not contain a vk record (buffer too small).", nameof(data));

            ReadOnlySpan<byte> valueName = data[20..(20 + this.NameLength)];
            if ((this.Flags & 1) == 1) this.ValueName = Encoding.ASCII.GetString(valueName);
            else this.ValueName = Encoding.Unicode.GetString(valueName);

        }

    }

}