/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Collections.Generic;
using System.IO;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Import;

public class ImportDirectory : IDirectory<ImportDirectory> {

    public Dictionary<string, ImportedLibrary>? Imports { get; private set; }

    public static DirectoryEntry DirectoryEntry => DirectoryEntry.Import;

    public ImportDirectory() { }

    public static ImportDirectory LoadDirectory(PortableExecutable pe, Stream stream) {
        
        DataDirectory directory = pe.OptionalHeader.DataDirectories[ImportDirectory.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            throw new InvalidOperationException("The import directory does not exist in the PE image.");

        ImportDirectory importDirectory = new ImportDirectory();
        importDirectory.Imports = new Dictionary<string, ImportedLibrary>();

        Span<byte> data = new byte[20].AsSpan();
        for (int i = 0; ; ++i) {

            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (uint)(directory.VirtualAddress + (i * 20)));
            stream.ReadExactly(data);

            ImportedLibrary? importDescriptor = ImportedLibrary.LoadDescriptor(data, pe, stream);
            if (importDescriptor == null) break;

            if (importDescriptor.Name.Name != null)
                importDirectory.Imports.Add(importDescriptor.Name.Name, importDescriptor);

        }

        return importDirectory;
    }

}