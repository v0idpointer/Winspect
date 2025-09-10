/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Collections.Generic;
using System.IO;
using Winspect.Common;
using Winspect.Formats.PE.Directories.Import;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.DelayImport;

public class DelayImportDirectory : IDirectory<DelayImportDirectory>, IDiffable<DelayImportDirectory, ImportsDiff> {

    public Dictionary<string, DelayImportedLibrary>? Imports { get; private set; }

    public static DirectoryEntry DirectoryEntry => DirectoryEntry.DelayImport;

    public static DelayImportDirectory LoadDirectory(PortableExecutable pe, Stream stream) {

        DataDirectory directory = pe.OptionalHeader.DataDirectories[DelayImportDirectory.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            throw new InvalidOperationException("The delay import directory does not exist in the PE image.");
        
        DelayImportDirectory delayImportDirectory = new DelayImportDirectory();
        delayImportDirectory.Imports = new Dictionary<string, DelayImportedLibrary>();

        Span<byte> data = new byte[32].AsSpan();
        for (int i = 0; ; ++i) {

            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (uint)(directory.VirtualAddress + (i * 32)));
            stream.ReadExactly(data);

            DelayImportedLibrary? delayLoadDescriptor = DelayImportedLibrary.LoadDescriptor(data, pe, stream);
            if (delayLoadDescriptor == null) break;

            if (delayLoadDescriptor.DllName.Name != null)
                delayImportDirectory.Imports.Add(delayLoadDescriptor.DllName.Name, delayLoadDescriptor);

        }

        return delayImportDirectory;
    }

    public static ImportsDiff Diff(DelayImportDirectory? a, DelayImportDirectory? b) {
        return new ImportsDiff(a, b);
    }

}