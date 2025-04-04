/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System.IO;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories;

public interface IDirectory<T> {

    public static abstract DirectoryEntry DirectoryEntry { get; }
    public static abstract T LoadDirectory(PortableExecutable pe, Stream stream);

}