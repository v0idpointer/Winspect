/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Winspect.Common;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.Export;

/// <summary>
/// Represents the IMAGE_EXPORT_DIRECTORY structure.
/// </summary>
public class ExportDirectory : IDirectory<ExportDirectory>, IDiffable<ExportDirectory, ExportsDiff> {

    public uint Characteristics { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public ushort MajorVersion { get; private set; }
    public ushort MinorVersion { get; private set; }
    public (uint RVA, string? Name) Name { get; private set; }
    public uint Base { get; private set; }
    public uint NumberOfFunctions { get; private set; }
    public uint NumberOfNames { get; private set; }
    public uint AddressOfFunctions { get; private set; }
    public uint AddressOfNames { get; private set; }
    public uint AddressOfNameOrdinals { get; private set; }

    public Dictionary<ushort, ExportedFunction>? Exports { get; private set; }

    public static DirectoryEntry DirectoryEntry => DirectoryEntry.Export;

    public ExportDirectory(ReadOnlySpan<byte> data) {

        if (data.Length < 40)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_EXPORT_DIRECTORY structure.", nameof(data));

        this.Characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.MajorVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[8..10]);
        this.MinorVersion = BinaryPrimitives.ReadUInt16LittleEndian(data[10..12]);
        this.Name = (BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]), null);
        this.Base = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);
        this.NumberOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);
        this.NumberOfNames = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);
        this.AddressOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);
        this.AddressOfNames = BinaryPrimitives.ReadUInt32LittleEndian(data[32..36]);
        this.AddressOfNameOrdinals = BinaryPrimitives.ReadUInt32LittleEndian(data[36..40]);

    }

    public static ExportDirectory LoadDirectory(PortableExecutable pe, Stream stream) {

        DataDirectory directory = pe.OptionalHeader.DataDirectories[ExportDirectory.DirectoryEntry];
        if ((directory.VirtualAddress == 0) && (directory.Size == 0))
            throw new InvalidOperationException("The export directory does not exist in the PE image.");

        Span<byte> data = new byte[40].AsSpan();
        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, directory.VirtualAddress);
        stream.ReadExactly(data);

        ExportDirectory exportDirectory = new ExportDirectory(data);

        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, exportDirectory.Name.RVA);
        exportDirectory.Name = (
            exportDirectory.Name.RVA,
            StreamHelper.ReadString(stream, Encoding.ASCII, null)
        );

        Dictionary<ushort, (uint RVA, string Name)> names = new Dictionary<ushort, (uint RVA, string Value)>();
        Dictionary<ushort, ushort> hints = new Dictionary<ushort, ushort>();

        for (int i = 0; i < exportDirectory.NumberOfNames; ++i) {
            
            uint hint = (uint)(exportDirectory.AddressOfNameOrdinals + (i * 2));
            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, hint);
            stream.ReadExactly(data[0..2]);

            uint name = (uint)(exportDirectory.AddressOfNames + (i * 4));
            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, name);
            stream.ReadExactly(data[2..6]);

            ushort ordinal = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(data[0..2]) + exportDirectory.Base);
            hints.Add(ordinal, (ushort)(i));

            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(data[2..6]);
            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, nameRva);
            names.Add(ordinal, (nameRva, StreamHelper.ReadString(stream, Encoding.ASCII, null)));

        }

        exportDirectory.Exports = new Dictionary<ushort, ExportedFunction>();

        for (int i = 0; i < exportDirectory.NumberOfFunctions; ++i) {
            
            uint function = (uint)(exportDirectory.AddressOfFunctions + (i * 4));
            stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, function);
            stream.ReadExactly(data[0..4]);

            uint rva = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
            ushort ordinal = (ushort)(i + exportDirectory.Base);
            
            string? forwarder = null;
            if ((rva >= directory.VirtualAddress) && (rva < (directory.VirtualAddress + directory.Size))) {
                stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, rva);
                forwarder = StreamHelper.ReadString(stream, Encoding.ASCII, null);
            }

            (uint RVA, string Name)? name = null;
            ushort? hint = null;

            if (names.ContainsKey(ordinal))
                name = names[ordinal];

            if (hints.ContainsKey(ordinal))
                hint = hints[ordinal];

            exportDirectory.Exports.Add(
                ordinal,
                new ExportedFunction(ordinal, rva, name, hint, forwarder)
            );

        }

        return exportDirectory;
    }

    public static ExportsDiff Diff(ExportDirectory? a, ExportDirectory? b) {
        return new ExportsDiff(a, b);
    }

}