/*
   Windows Inspection Utilities
   Copyright (c) 2025 V0idPointer
*/

using System;
using System.IO;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Debug;

public class DebugDirectory : IDirectory<DebugDirectory> {

    public DebugDirectoryEntry[]? Entries { get; private set; }

    public static DirectoryEntry DirectoryEntry => DirectoryEntry.Debug;

    public DebugDirectory() { }

    public static DebugDirectory LoadDirectory(PortableExecutable pe, Stream stream) {

        DataDirectory directory = pe.OptionalHeader.DataDirectories[DebugDirectory.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            throw new InvalidOperationException("The debug directory does not exist in the PE image.");

        DebugDirectory debugDirectory = new DebugDirectory();
        debugDirectory.Entries = new DebugDirectoryEntry[(directory.Size / 28)];

        Span<byte> data = new byte[28].AsSpan();
        for (int i = 0; i < debugDirectory.Entries.Length; ++i) {

            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (uint)(directory.VirtualAddress + (i * 28)));
            stream.ReadExactly(data);

            debugDirectory.Entries[i] = new DebugDirectoryEntry(data);

        }

        return debugDirectory;
    }

}