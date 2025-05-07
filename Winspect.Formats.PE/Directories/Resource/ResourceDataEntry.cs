/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.IO;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Resource;

/// <summary>
/// Represents the IMAGE_RESOURCE_DATA_ENTRY structure.
/// </summary>
public class ResourceDataEntry {

    public ResourceDirectory? Parent { get; private set; }

    public uint OffsetToData { get; private set; }
    public uint Size { get; private set; }
    public uint CodePage { get; private set; }
    public uint Reserved { get; private set; }

    public ResourceDataEntry(ReadOnlySpan<byte> data) {
        
        if (data.Length < 16)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_RESOURCE_DATA_ENTRY structure.", nameof(data));

        this.OffsetToData = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.Size = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.CodePage = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.Reserved = BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]);

    }

    public static ResourceDataEntry LoadEntry(ResourceDirectory parent, PortableExecutable pe, Stream stream, uint rva, uint offset) {

        Span<byte> data = new byte[16].AsSpan();
        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (rva + offset));
        stream.ReadExactly(data);

        ResourceDataEntry dataEntry = new ResourceDataEntry(data);
        dataEntry.Parent = parent;

        return dataEntry;
    }

}