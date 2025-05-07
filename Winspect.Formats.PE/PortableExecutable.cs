/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.IO;
using System.Text;
using Winspect.Formats.PE.Directories;
using Winspect.Formats.PE.Directories.Resource;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE;

/// <summary>
/// Represents a Portable Executable (PE) file.
/// </summary>
public class PortableExecutable {

    /// <summary>
    /// PE\0\0
    /// </summary>
    public static readonly string NtSignature = "PE\0\0";

    public Stream? Stream { get; private set; }

    public DosHeader DosHeader { get; private set; }
    public string Signature { get; private set; }
    public FileHeader FileHeader { get; private set; }
    public OptionalHeader OptionalHeader { get; private set; }
    public SectionHeader[] SectionHeaders { get; private set; }

    public ExportDirectory? ExportDirectory { get; private set; }
    public ImportDirectory? ImportDirectory { get; private set; }
    public ResourceDirectory? ResourceDirectory { get; private set; }

    public PortableExecutable(Stream stream, bool takeOwnership) {

        Span<byte> data = new byte[64].AsSpan();
        stream.ReadExactly(data);
        this.DosHeader = new DosHeader(data);

        if (this.DosHeader.Magic != DosHeader.DosSignature)
            throw new BadPortableExecutableException("Bad PE image: invalid DOS signature.");

        stream.Position = this.DosHeader.Lfanew;
        stream.ReadExactly(data[0..4]);
        this.Signature = Encoding.ASCII.GetString(data[0..4]);

        if (this.Signature != PortableExecutable.NtSignature)
            throw new BadPortableExecutableException("Bad PE image: invalid NT signature.");

        stream.ReadExactly(data[0..20]);
        this.FileHeader = new FileHeader(data[0..20]);

        data = new byte[this.FileHeader.SizeOfOptionalHeader].AsSpan();
        stream.ReadExactly(data);
        this.OptionalHeader = new OptionalHeader(data);

        data = new byte[40].AsSpan();

        this.SectionHeaders = new SectionHeader[this.FileHeader.NumberOfSections];
        for (int i = 0; i < this.FileHeader.NumberOfSections; ++i) {
            stream.ReadExactly(data);
            this.SectionHeaders[i] = new SectionHeader(data);
        }

        this.ExportDirectory = this.LoadDataDirectory<ExportDirectory>(stream);
        this.ImportDirectory = this.LoadDataDirectory<ImportDirectory>(stream);
        this.ResourceDirectory = this.LoadDataDirectory<ResourceDirectory>(stream);

        if (takeOwnership) this.Stream = stream;

    }

    public PortableExecutable(string filepath)
        : this(new FileStream(filepath, FileMode.Open, FileAccess.Read), takeOwnership: true) { }

    /// <summary>
    /// Searches the resource directory for a resource with the specified ID, type and language.
    /// </summary>
    /// <param name="id">Resource ID</param>
    /// <param name="type">Resource type</param>
    /// <param name="lang">Language</param>
    /// <returns>
    /// A <see cref="ResourceDataEntry" /> if the resource is found; otherwise, <c>null</c>.
    /// </returns>
    public ResourceDataEntry? FindResource(ResourceId id, ResourceId type, ushort lang) {

        if (this.ResourceDirectory == null) return null;
        if (this.ResourceDirectory.Entries == null) return null;
        if (!this.ResourceDirectory.Entries.ContainsKey(type)) return null;

        ResourceDirectoryEntry entry = this.ResourceDirectory.Entries[type];
        if (entry.Directory == null) return null;

        ResourceDirectory directory = entry.Directory;
        if (directory.Entries == null) return null;
        if (!directory.Entries.ContainsKey(id)) return null;

        entry = directory.Entries[id];
        if (entry.Directory == null) return null;

        directory = entry.Directory;
        if (directory.Entries == null) return null;
        if (!directory.Entries.ContainsKey(lang)) return null;

        entry = directory.Entries[lang];
        if (entry.DataEntry == null) return null;

        return entry.DataEntry;
    }

    /// <summary>
    /// Returns all resource types from the resource directory.
    /// </summary>
    /// <returns>
    /// An array of <see cref="ResourceId" /> objects if successful; otherwise, <c>null</c>.
    /// </returns>
    public ResourceId[]? GetResourceTypes() {

        if (this.ResourceDirectory == null) return null;
        if (this.ResourceDirectory.Entries == null) return null;

        int count = (this.ResourceDirectory.NumberOfIdEntries + this.ResourceDirectory.NumberOfNamedEntries);
        ResourceId[] types = new ResourceId[count];

        int i = 0;
        foreach (ResourceId id in this.ResourceDirectory.Entries.Keys)
            types[i++] = id;

        return types;
    }

    /// <summary>
    /// Returns all resource IDs of the specified type from the resource directory.
    /// </summary>
    /// <param name="type">Resource type</param>
    /// <returns>
    /// An array of <see cref="ResourceId" /> objects if successful; otherwise, <c>null</c>.
    /// </returns>
    public ResourceId[]? GetResourceIds(ResourceId type) {

        if (this.ResourceDirectory == null) return null;
        if (this.ResourceDirectory.Entries == null) return null;
        if (!this.ResourceDirectory.Entries.ContainsKey(type)) return null;

        ResourceDirectoryEntry entry = this.ResourceDirectory.Entries[type];
        if (entry.Directory == null) return null;

        ResourceDirectory directory = entry.Directory;
        if (directory.Entries == null) return null;

        int count = (directory.NumberOfIdEntries + directory.NumberOfNamedEntries);
        ResourceId[] ids = new ResourceId[count];

        int i = 0;
        foreach (ResourceId id in directory.Entries.Keys)
            ids[i++] = id;

        return ids;
    }

    /// <summary>
    /// Returns all available languages for the specified resource from the resource directory.
    /// </summary>
    /// <param name="id">Resource ID</param>
    /// <param name="type">Resource type</param>
    /// <returns>
    /// An array of <see cref="ushort" />s if successful; otherwise, <c>null</c>.
    /// </returns>
    public ushort[]? GetResourceLanguages(ResourceId id, ResourceId type) {

        if (this.ResourceDirectory == null) return null;
        if (this.ResourceDirectory.Entries == null) return null;
        if (!this.ResourceDirectory.Entries.ContainsKey(type)) return null;

        ResourceDirectoryEntry entry = this.ResourceDirectory.Entries[type];
        if (entry.Directory == null) return null;

        ResourceDirectory directory = entry.Directory;
        if (directory.Entries == null) return null;
        if (!directory.Entries.ContainsKey(id)) return null;

        entry = directory.Entries[id];
        if (entry.Directory == null) return null;

        directory = entry.Directory;
        if (directory.Entries == null) return null;

        int count = (directory.NumberOfIdEntries + directory.NumberOfNamedEntries);
        ushort[] languages = new ushort[count];

        int i = 0;
        foreach (ResourceId lang in directory.Entries.Keys)
            if (lang.NumericalId.HasValue)
                languages[i++] = lang.NumericalId.Value;

        return languages;
    }

    private T? LoadDataDirectory<T>(Stream stream) where T : class, IDirectory<T> {

        DataDirectory directory = this.OptionalHeader.DataDirectories[T.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            return null;

        return T.LoadDirectory(this, stream);
    }

}