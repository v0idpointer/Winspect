/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Resource;

/// <summary>
/// Represents the IMAGE_RESOURCE_DIRECTORY structure.
/// </summary>
public class ResourceDirectory : IDirectory<ResourceDirectory> {

    public static readonly uint ResourceNameIsString = 0x80000000;
    public static readonly uint ResourceDataIsDirectory = 0x80000000;

    public ResourceDirectory? Parent { get; private set; }
    public uint? RVA { get; private set; }

    public uint Characteristics { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public ushort MajorVersion { get; private set; }
    public ushort MinorVersion { get; private set; }
    public ushort NumberOfNamedEntries { get; private set; }
    public ushort NumberOfIdEntries { get; private set; }

    public Dictionary<ResourceId, ResourceDirectoryEntry>? Entries { get; private set; }

    public static DirectoryEntry DirectoryEntry => DirectoryEntry.Resource;

    public ResourceDirectory(ReadOnlySpan<byte> data) {

        if (data.Length < 16)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_RESOURCE_DIRECTORY structure.", nameof(data));

        this.Characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.MajorVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[8..10]);
        this.MinorVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[10..12]);
        this.NumberOfNamedEntries = BinaryPrimitives.ReadUInt16LittleEndian(data[12..14]);
        this.NumberOfIdEntries = BinaryPrimitives.ReadUInt16LittleEndian(data[14..16]);

    }

    public uint GetRootDirectoryRVA() {

        ResourceDirectory dir = this;

        while (dir.Parent != null)
            dir = dir.Parent;

        if (!dir.RVA.HasValue)
            throw new InvalidOperationException("Root resource directory not fully initialized");

        return dir.RVA.Value;
    }

    public static ResourceDirectory LoadDirectory(ResourceDirectory? parent, PortableExecutable pe, Stream stream, uint rva, uint offset) {
        
        Span<byte> data = new byte[16].AsSpan();
        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (rva + offset));
        stream.ReadExactly(data);

        ResourceDirectory resourceDirectory = new ResourceDirectory(data);
        resourceDirectory.Parent = parent;
        resourceDirectory.RVA = (rva + offset);

        resourceDirectory.Entries = new Dictionary<ResourceId, ResourceDirectoryEntry>();
        for (uint i = 0; i < (resourceDirectory.NumberOfNamedEntries + resourceDirectory.NumberOfIdEntries); ++i) {
            
            ResourceDirectoryEntry entry = ResourceDirectoryEntry.LoadEntry(resourceDirectory, pe, stream, i);
            if (!entry.Id.Id.HasValue)
                throw new InvalidOperationException("Resource directory entry not fully initialized.");

            resourceDirectory.Entries.Add(entry.Id.Id.Value, entry);
            
        }

        return resourceDirectory;
    }

    public static ResourceDirectory LoadDirectory(PortableExecutable pe, Stream stream) {

        DataDirectory directory = pe.OptionalHeader.DataDirectories[ResourceDirectory.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            throw new InvalidOperationException("The resource directory does not exist in the PE image.");

        return ResourceDirectory.LoadDirectory(null, pe, stream, directory.VirtualAddress, 0);
    }

}