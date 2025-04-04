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
        
        if (data.Length < 40)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_SECTION_HEADER structure.", nameof(data));

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

    /// <summary>
    /// Searches for a section in the provided array of section headers that contains
    /// the specified Relative Virtual Address (RVA).
    /// </summary>
    /// <param name="sections">
    /// An array of <see cref="SectionHeader" /> objects to search through.
    /// </param>
    /// <param name="rva">
    /// A Relative Virtual Address (RVA).
    /// </param>
    /// <returns>
    /// A <see cref="SectionHeader" /> object if a matching section is found; otherwise, <c>null</c>.
    /// </returns>
    public static SectionHeader? FindSection(SectionHeader[] sections, uint rva) {

        foreach (SectionHeader section in sections) {
            
            uint size = ((section.VirtualSize == 0) ? section.SizeOfRawData : section.VirtualSize);
            if ((rva >= section.VirtualAddress) && (rva < (section.VirtualAddress + size)))
                return section;

        }

        return null;
    }

    /// <summary>
    /// Converts a Relative Virtual Address (RVA) to a file offset.
    /// </summary>
    /// <param name="sections">
    /// An array of <see cref="SectionHeader" /> objects.
    /// </param>
    /// <param name="rva">
    /// A Relative Virtual Address (RVA).
    /// </param>
    /// <returns>
    /// A file offset.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// The specified RVA is not a part of any section.
    /// </exception>
    public static uint RVAToFileOffset(SectionHeader[] sections, uint rva) {

        SectionHeader? section = SectionHeader.FindSection(sections, rva);
        if (section == null) 
            throw new ArgumentException("The specified RVA is not a part of any section.", nameof(rva));

        return (rva - section.VirtualAddress + section.PointerToRawData);
    }

}