/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Resource;

/// <summary>
/// Represents the IMAGE_RESOURCE_DIRECTORY_ENTRY structure.
/// </summary>
public class ResourceDirectoryEntry {

    public ResourceDirectory? Parent { get; private set; }

    public (uint Offset, ResourceId? Id) Id { get; private set; }
    public uint OffsetToData { get; private set; }

    public ResourceDirectory? Directory { get; private set; }
    public ResourceDataEntry? DataEntry { get; private set; }

    public ResourceDirectoryEntry(ReadOnlySpan<byte> data) {

        if (data.Length < 8)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_RESOURCE_DIRECTORY_ENTRY structure.", nameof(data));

        this.Id = (BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]), null);
        this.OffsetToData = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);

    }

    public static ResourceDirectoryEntry LoadEntry(ResourceDirectory parent, PortableExecutable pe, Stream stream, uint idx) {

        if (!parent.RVA.HasValue)
            throw new InvalidOperationException("Parent resource directory not fully initialized.");

        uint position = (parent.RVA.Value + 16 + (idx * 8));

        Span<byte> data = new byte[8].AsSpan();
        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, position);
        stream.ReadExactly(data);

        ResourceDirectoryEntry directoryEntry = new ResourceDirectoryEntry(data);
        directoryEntry.Parent = parent;

        uint rootDirectoryRVA = parent.GetRootDirectoryRVA();

        uint offset = directoryEntry.Id.Offset;
        if ((offset & ResourceDirectory.ResourceNameIsString) == 0) directoryEntry.Id = (offset, (ushort)(offset & 0xFFFF));
        else {

            offset &= ~ResourceDirectory.ResourceNameIsString;
            offset += rootDirectoryRVA;
            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, offset);

            stream.ReadExactly(data[0..2]);
            ushort len = BinaryPrimitives.ReadUInt16LittleEndian(data[0..2]);

            string name = StreamHelper.ReadString(stream, Encoding.Unicode, len);
            directoryEntry.Id = (
                directoryEntry.Id.Offset,
                name
            );

        }

        offset = directoryEntry.OffsetToData;
        if ((offset & ResourceDirectory.ResourceDataIsDirectory) == 0) { // data entry
            
            ResourceDataEntry dataEntry = ResourceDataEntry.LoadEntry(
                directoryEntry.Parent,
                pe,
                stream,
                rootDirectoryRVA,
                offset
            );

            directoryEntry.Directory = null;
            directoryEntry.DataEntry = dataEntry;

        }
        else { // subdirectory

            offset &= ~ResourceDirectory.ResourceDataIsDirectory;

            ResourceDirectory subdirectory = ResourceDirectory.LoadDirectory(
                directoryEntry.Parent,
                pe, 
                stream,
                rootDirectoryRVA,
                offset
            );

            directoryEntry.Directory = subdirectory;
            directoryEntry.DataEntry = null;

        }

        return directoryEntry;
    }

}