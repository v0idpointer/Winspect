/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Import;

/// <summary>
/// Represents the IMAGE_IMPORT_DESCRIPTOR structure.
/// </summary>
public class ImportedLibrary {

    public uint Characteristics { get; private set; }
    public uint OriginalFirstThunk => this.Characteristics;
    public uint TimeDateStamp { get; private set; }
    public uint ForwarderChain { get; private set; }
    public (uint RVA, string? Name) Name { get; private set; }
    public uint FirstThunk { get; private set; }

    public ImportedFunction[]? Imports { get; private set; }

    public ImportedLibrary(ReadOnlySpan<byte> data) {

        if (data.Length < 20)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_IMPORT_DESCRIPTOR structure.", nameof(data));

        this.Characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.ForwarderChain = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.Name = (BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]), null);
        this.FirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);

    }

    public static ImportedLibrary? LoadDescriptor(ReadOnlySpan<byte> data, PortableExecutable pe, Stream stream) {

        ImportedLibrary importDescriptor = new ImportedLibrary(data);
        
        if (
            (importDescriptor.Characteristics == 0) && 
            (importDescriptor.TimeDateStamp == 0) &&
            (importDescriptor.ForwarderChain == 0) &&
            (importDescriptor.Name.RVA == 0) &&
            (importDescriptor.FirstThunk == 0)
        ) return null;

        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, importDescriptor.Name.RVA);
        importDescriptor.Name = (
            importDescriptor.Name.RVA,
            StreamHelper.ReadString(stream, Encoding.ASCII, null)
        );

        // some old binaries don't have the ILT, so read the IAT since they are the same on disk.
        uint firstThunk = importDescriptor.OriginalFirstThunk;
        if (firstThunk == 0) firstThunk = importDescriptor.FirstThunk;

        Span<byte> d = new byte[(pe.OptionalHeader.Magic == OptionalHeader.Pe32PlusSignature) ? 8 : 4].AsSpan();
        List<ImportedFunction> imports = new List<ImportedFunction>();

        for (int i = 0; ; ++i) {

            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (uint)(firstThunk + (i * d.Length)));
            stream.ReadExactly(d);

            ushort? ordinal = null, hint = null;
            string? name = null;

            ordinal = ImportedLibrary.GetOrdinalOrName(d, pe, stream, out name, out hint);
            if ((ordinal == null) && (name == null) && (hint == null)) break;

            imports.Add(new ImportedFunction(ordinal, name, hint));

        }

        importDescriptor.Imports = imports.ToArray();

        return importDescriptor;
    }

    internal static ushort? GetOrdinalOrName(ReadOnlySpan<byte> data, PortableExecutable pe, Stream stream, out string? name, out ushort? hint) {

        ulong entry;
        if (data.Length == 8) entry = BinaryPrimitives.ReadUInt64LittleEndian(data);
        else entry = BinaryPrimitives.ReadUInt32LittleEndian(data);

        // null terminator for the ILT
        if (entry == 0) {
            name = null;
            hint = null;
            return null;
        }

        bool ordinalFlag;
        if (data.Length == 8) ordinalFlag = ((entry & 0x8000000000000000) > 0);
        else ordinalFlag = ((entry & 0x80000000) > 0);

        if (ordinalFlag) {
            name = null;
            hint = null;
            return (ushort)(entry & 0xFFFF);
        }

        Span<byte> d = new byte[2].AsSpan();
        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, (uint)(entry & 0x7FFFFFFF));

        stream.ReadExactly(d);
        hint = BinaryPrimitives.ReadUInt16LittleEndian(d[0..2]);
        name = StreamHelper.ReadString(stream, Encoding.ASCII, null);

        return null;
    }

}