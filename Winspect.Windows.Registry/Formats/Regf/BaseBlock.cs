/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Windows.Registry.Formats.Regf;

public class BaseBlock {

    /// <summary>
    /// ASCII string "regf"
    /// </summary>
    public static readonly string RegfSignature = "regf";

    public string Signature { get; private set; }
    public uint PrimarySequenceNumber { get; private set; }
    public uint SecondarySequenceNumber { get; private set; }
    public ulong LastWrittenTimestamp { get; private set; }
    public uint MajorVersion { get; private set; }
    public uint MinorVersion { get; private set; }
    public uint FileType { get; private set; }
    public uint FileFormat { get; private set; }
    public uint RootCellOffset { get; private set; }
    public uint HiveBinsDataSize { get; private set; }
    public uint ClusteringFactor { get; private set; }
    public string FileName { get; private set; }
    public uint Checksum { get; private set; }
    public uint BootType { get; private set; }
    public uint BootRecover { get; private set; }

    public BaseBlock(ReadOnlySpan<byte> data) {

        if (data.Length < 4096)
            throw new ArgumentException("The specified buffer does not contain a REGF base block (buffer too small).", nameof(data));

        this.Signature = Encoding.ASCII.GetString(data[0..4]).Replace("\0", string.Empty).Trim();
        this.PrimarySequenceNumber = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.SecondarySequenceNumber = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.LastWrittenTimestamp = BinaryPrimitives.ReadUInt64LittleEndian(data[12..20]);
        this.MajorVersion = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);
        this.MinorVersion = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);
        this.FileType = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);
        this.FileFormat = BinaryPrimitives.ReadUInt32LittleEndian(data[32..36]);
        this.RootCellOffset = BinaryPrimitives.ReadUInt32LittleEndian(data[36..40]);
        this.HiveBinsDataSize = BinaryPrimitives.ReadUInt32LittleEndian(data[40..44]);
        this.ClusteringFactor = BinaryPrimitives.ReadUInt32LittleEndian(data[44..48]);
        this.FileName = Encoding.Unicode.GetString(data[48..112]).Replace("\0", string.Empty).Trim();
        this.Checksum = BinaryPrimitives.ReadUInt32LittleEndian(data[508..512]);
        this.BootType = BinaryPrimitives.ReadUInt32LittleEndian(data[4088..4092]);
        this.BootRecover = BinaryPrimitives.ReadUInt32LittleEndian(data[4092..4096]);

    }

}