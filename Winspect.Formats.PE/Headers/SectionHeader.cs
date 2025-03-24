/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Text;

namespace Winspect.Formats.PE.Headers;

/// <summary>
/// Represents the IMAGE_SECTION_HEADER structure.
/// </summary>
public class SectionHeader {

    public string Name { get; private set; }
    public uint PhysicalAddress { get; private set; }
    public uint VirtualSize => this.PhysicalAddress;
    public uint VirtualAddress { get; private set; }
    public uint SizeOfRawData { get; private set; }
    public uint PointerToRawData { get; private set; }
    public uint PointerToRelocations { get; private set; }
    public uint PointerToLinenumbers { get; private set; }
    public ushort NumberOfRelocations { get; private set; }
    public ushort NumberOfLinenumbers { get; private set; }
    public SectionCharacteristics Characteristics { get; private set; }

    public SectionHeader(ReadOnlySpan<byte> data) {
        
        this.Name = Encoding.UTF8.GetString(data[0..8]).Replace("\0", string.Empty).Trim();
        this.PhysicalAddress = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]);
        this.SizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);
        this.PointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);
        this.PointerToRelocations = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);
        this.PointerToLinenumbers = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);
        this.NumberOfRelocations = BinaryPrimitives.ReadUInt16LittleEndian(data[32..34]);
        this.NumberOfLinenumbers = BinaryPrimitives.ReadUInt16LittleEndian(data[34..36]);
        this.Characteristics = (SectionCharacteristics)(BinaryPrimitives.ReadUInt32LittleEndian(data[36..40]));

    }

}