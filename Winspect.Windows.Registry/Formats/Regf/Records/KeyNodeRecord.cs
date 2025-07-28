/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf.Records;

public class KeyNodeRecord : Record {

    /// <summary>
    /// ASCII string "nk"
    /// </summary>
    public static readonly string NkSignature = "nk";

    public string Signature { get; private set; }
    public ushort Flags { get; private set; }
    public ulong LastWrittenTimestamp { get; private set; }
    public uint AccessBits { get; private set; }
    public uint Parent { get; private set; }
    public uint NumberOfSubkeys { get; private set; }
    public uint NumberOfVolatileSubkeys { get; private set; }
    public uint SubkeysListOffset { get; private set; }
    public uint VolatileSubkeysListOffset { get; private set; }
    public uint NumberOfKeyValues { get; private set; }
    public uint KeyValuesListOffset { get; private set; }
    public uint KeySecurityOffset { get; private set; }
    public uint ClassNameOffset { get; private set; }
    public uint LargestSubkeyNameLength { get; private set; }
    public uint LargestSubkeyClassNameLength { get; private set; }
    public uint LargestValueNameLength { get; private set; }
    public uint LargestValueDataSize { get; private set; }
    public uint WorkVar { get; private set; }
    public ushort KeyNameLength { get; private set; }
    public ushort ClassNameLength { get; private set; }
    public string KeyNameString { get; private set; }

    public override RecordType Type => RecordType.KeyNode;

    public KeyNodeRecord(ReadOnlySpan<byte> data) {

        if (data.Length < 76)
            throw new ArgumentException("The specified buffer does not contain an nk record (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..2]);
        this.Flags = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);
        this.LastWrittenTimestamp = BinaryPrimitives.ReadUInt64LittleEndian(data[4..12]);
        this.AccessBits = BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]);
        this.Parent = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);
        this.NumberOfSubkeys = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);
        this.NumberOfVolatileSubkeys = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);
        this.SubkeysListOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);
        this.VolatileSubkeysListOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[32..36]);
        this.NumberOfKeyValues = BinaryPrimitives.ReadUInt32LittleEndian(data[36..40]);
        this.KeyValuesListOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[40..44]);
        this.KeySecurityOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[44..48]);
        this.ClassNameOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[48..52]);
        this.LargestSubkeyNameLength = BinaryPrimitives.ReadUInt32LittleEndian(data[52..56]);
        this.LargestSubkeyClassNameLength = BinaryPrimitives.ReadUInt32LittleEndian(data[56..60]);
        this.LargestValueNameLength = BinaryPrimitives.ReadUInt32LittleEndian(data[60..64]);
        this.LargestValueDataSize = BinaryPrimitives.ReadUInt32LittleEndian(data[64..68]);
        this.WorkVar = BinaryPrimitives.ReadUInt32LittleEndian(data[68..72]);
        this.KeyNameLength = BinaryPrimitives.ReadUInt16LittleEndian(data[72..74]);
        this.ClassNameLength = BinaryPrimitives.ReadUInt16LittleEndian(data[74..76]);

        if (data.Length < (76 + this.KeyNameLength))
            throw new ArgumentException("The specified buffer does not contain an nk record (buffer too small).", nameof(data));

        ReadOnlySpan<byte> keyName = data[76..(76 + this.KeyNameLength)];
        if ((this.Flags & 0x20) == 0x20) this.KeyNameString = Encoding.ASCII.GetString(keyName);
        else this.KeyNameString = Encoding.Unicode.GetString(keyName);

    }

}