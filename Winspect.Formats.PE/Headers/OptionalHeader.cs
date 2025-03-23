/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Winspect.Formats.PE.Headers;

/// <summary>
/// Represents either the IMAGE_OPTIONAL_HEADER32 or the IMAGE_OPTIONAL_HEADER64 structure.
/// </summary>
public class OptionalHeader {

    /// <summary>
    /// PE32 (0x10B)
    /// </summary>
    public static readonly ushort Pe32Signature = 0x010B;

    /// <summary>
    /// PE32+ (0x20B)
    /// </summary>
    public static readonly ushort Pe32PlusSignature = 0x020B;

        /* Standard fields */

    public ushort Magic { get; private set; }
    public byte MajorLinkerVersion { get; private set; }
    public byte MinorLinkerVersion { get; private set; }
    public uint SizeOfCode { get; private set; }
    public uint SizeOfInitializedData { get; private set; }
    public uint SizeOfUninitializedData { get; private set; }
    public uint AddressOfEntryPoint { get; private set; }
    public uint BaseOfCode { get; private set; }
    public uint? BaseOfData { get; private set; }

        /* NT additional fields */

    public ulong ImageBase { get; private set; }
    public uint SectionAlignment { get; private set; }
    public uint FileAlignment { get; private set; }
    public ushort MajorOperatingSystemVersion { get; private set; }
    public ushort MinorOperatingSystemVersion { get; private set; }
    public ushort MajorImageVersion { get; private set; }
    public ushort MinorImageVersion { get; private set; }
    public ushort MajorSubsystemVersion { get; private set; }
    public ushort MinorSubsystemVersion { get; private set; }
    public uint Win32VersionValue { get; private set; }
    public uint SizeOfImage { get; private set; }
    public uint SizeOfHeaders { get; private set; }
    public uint CheckSum { get; private set; }
    public Subsystem Subsystem { get; private set; }
    public DllCharacteristics DllCharacteristics { get; private set; }
    public ulong SizeOfStackReserve { get; private set; }
    public ulong SizeOfStackCommit { get; private set; }
    public ulong SizeOfHeapReserve { get; private set; }
    public ulong SizeOfHeapCommit { get; private set; }
    public uint LoaderFlags { get; private set; }
    public uint NumberOfRvaAndSizes { get; private set; }

    public Dictionary<DirectoryEntry, DataDirectory> DataDirectories { get; private set; }

    public OptionalHeader(ReadOnlySpan<byte> data) {

        this.Magic = BinaryPrimitives.ReadUInt16LittleEndian(data[0..2]);
        this.MajorLinkerVersion = data[2];
        this.MinorLinkerVersion = data[3];
        this.SizeOfCode = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.SizeOfInitializedData = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.SizeOfUninitializedData = BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]);
        this.AddressOfEntryPoint = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);
        this.BaseOfCode = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);

        if (this.Magic == OptionalHeader.Pe32Signature) {
            this.BaseOfData = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);
            this.ImageBase = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);
        }

        if (this.Magic == OptionalHeader.Pe32PlusSignature) {
            this.BaseOfData = null;
            this.ImageBase = BinaryPrimitives.ReadUInt64LittleEndian(data[24..32]);
        }

        this.SectionAlignment = BinaryPrimitives.ReadUInt32LittleEndian(data[32..36]);
        this.FileAlignment = BinaryPrimitives.ReadUInt32LittleEndian(data[36..40]);
        this.MajorOperatingSystemVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[40..42]);
        this.MinorOperatingSystemVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[42..44]);
        this.MajorImageVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[44..46]);
        this.MinorImageVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[46..48]);
        this.MajorSubsystemVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[48..50]);
        this.MinorSubsystemVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[50..52]);
        this.Win32VersionValue = BinaryPrimitives.ReadUInt32LittleEndian(data[52..56]);
        this.SizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(data[56..60]);
        this.SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(data[60..64]);
        this.CheckSum = BinaryPrimitives.ReadUInt32LittleEndian(data[64..68]);
        this.Subsystem = (Subsystem)(BinaryPrimitives.ReadUInt16LittleEndian(data[68..70]));
        this.DllCharacteristics = (DllCharacteristics)(BinaryPrimitives.ReadUInt16LittleEndian(data[70..72]));

        if (this.Magic == OptionalHeader.Pe32Signature) {
            this.SizeOfStackReserve = BinaryPrimitives.ReadUInt32LittleEndian(data[72..76]);
            this.SizeOfStackCommit = BinaryPrimitives.ReadUInt32LittleEndian(data[76..80]);
            this.SizeOfHeapReserve = BinaryPrimitives.ReadUInt32LittleEndian(data[80..84]);
            this.SizeOfHeapCommit = BinaryPrimitives.ReadUInt32LittleEndian(data[84..88]);
            this.LoaderFlags = BinaryPrimitives.ReadUInt32LittleEndian(data[88..92]);
            this.NumberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(data[92..96]);
        }

        if (this.Magic == OptionalHeader.Pe32PlusSignature) {
            this.SizeOfStackReserve = BinaryPrimitives.ReadUInt64LittleEndian(data[72..80]);
            this.SizeOfStackCommit = BinaryPrimitives.ReadUInt64LittleEndian(data[80..88]);
            this.SizeOfHeapReserve = BinaryPrimitives.ReadUInt64LittleEndian(data[88..96]);
            this.SizeOfHeapCommit = BinaryPrimitives.ReadUInt64LittleEndian(data[96..104]);
            this.LoaderFlags = BinaryPrimitives.ReadUInt32LittleEndian(data[104..108]);
            this.NumberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(data[108..112]);
        }

        this.DataDirectories = new Dictionary<DirectoryEntry, DataDirectory>();
        for (int i = 0; i < 16; ++i) {
            int offset = (((this.Magic == OptionalHeader.Pe32PlusSignature) ? 112 : 96) + (i * 8));
            this.DataDirectories.Add((DirectoryEntry)(i), new DataDirectory(data[offset..(offset + 8)]));
        }
        
    }

}