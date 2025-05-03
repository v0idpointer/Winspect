/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.IO;
using System.Text;
using Winspect.Formats.PE.Directories;
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

    public DosHeader DosHeader { get; private set; }
    public string Signature { get; private set; }
    public FileHeader FileHeader { get; private set; }
    public OptionalHeader OptionalHeader { get; private set; }
    public SectionHeader[] SectionHeaders { get; private set; }

    public ExportDirectory? ExportDirectory { get; private set; }
    public ImportDirectory? ImportDirectory { get; private set; }

    public PortableExecutable(string filepath) {
        
        using (FileStream stream = new FileStream(filepath, FileMode.Open, FileAccess.Read)) {

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

        }

    }

    private T? LoadDataDirectory<T>(Stream stream) where T : class, IDirectory<T> {

        DataDirectory directory = this.OptionalHeader.DataDirectories[T.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            return null;

        return T.LoadDirectory(this, stream);
    }

}