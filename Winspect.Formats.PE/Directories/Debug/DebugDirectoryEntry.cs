/*
   Windows Inspection Utilities
   Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;

namespace Winspect.Formats.PE.Directories.Debug;

public class DebugDirectoryEntry {

    public uint Characteristics { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public ushort MajorVersion { get; private set; }
    public ushort MinorVersion { get; private set; }
    public DebugType Type { get; private set; }
    public uint SizeOfData { get; private set; }
    public uint AddressOfRawData { get; private set; }
    public uint PointerToRawData { get; private set; }

    public DebugDirectoryEntry(ReadOnlySpan<byte> data) {

        if (data.Length < 28)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_DEBUG_DIRECTORY structure.", nameof(data));

        this.Characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.MajorVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[8..10]);
        this.MinorVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[10..12]);
        this.Type = (DebugType)(BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]));
        this.SizeOfData = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);
        this.AddressOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);
        this.PointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);

    }

}