/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Winspect.Formats.PE.Directories.Import;
using Winspect.Formats.PE.Headers;

namespace Winspect.Formats.PE.Directories.DelayImport;

/// <summary>
/// Represents the IMAGE_DELAYLOAD_DESCRIPTOR structure.
/// </summary>
public class DelayImportedLibrary {

    public uint AllAttributes { get; private set; }
    public bool RvaBased => ((this.AllAttributes & 1) == 1);
    public (uint RVA, string? Name) DllName { get; private set; }
    public uint ModuleHandleRVA { get; private set; }
    public uint ImportAddressTableRVA { get; private set; }
    public uint ImportNameTableRVA { get; private set; }
    public uint BoundImportAddressTableRVA { get; private set; }
    public uint UnloadInformationTableRVA { get; private set; }
    public uint TimeDateStamp { get; private set; }

    public ImportedFunction[]? Imports { get; private set; }

    public DelayImportedLibrary(ReadOnlySpan<byte> data) {

        if (data.Length < 32)
            throw new ArgumentException("The specified buffer is too small to contain the IMAGE_DELAYLOAD_DESCRIPTOR structure.", nameof(data));

        this.AllAttributes = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.DllName = (BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]), null);
        this.ModuleHandleRVA = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.ImportAddressTableRVA = BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]);
        this.ImportNameTableRVA = BinaryPrimitives.ReadUInt32LittleEndian(data[16..20]);
        this.BoundImportAddressTableRVA = BinaryPrimitives.ReadUInt32LittleEndian(data[20..24]);
        this.UnloadInformationTableRVA = BinaryPrimitives.ReadUInt32LittleEndian(data[24..28]);
        this.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data[28..32]);

    }

    private uint GetRVA(ulong rvaOrVa, PortableExecutable pe) {
        if (this.RvaBased) return (uint)(rvaOrVa & 0xFFFFFFFF);
        else return (uint)(rvaOrVa - pe.OptionalHeader.ImageBase);
    }

    private void GetRVA(Span<byte> rvaOrVa, PortableExecutable pe) {
        
        if (this.RvaBased) return;
        
        ulong va;
        if (rvaOrVa.Length == 8) va = BinaryPrimitives.ReadUInt64LittleEndian(rvaOrVa);
        else va = BinaryPrimitives.ReadUInt32LittleEndian(rvaOrVa[0..4]);

        va = this.GetRVA(va, pe);
        if (rvaOrVa.Length == 8) BinaryPrimitives.WriteUInt64LittleEndian(rvaOrVa, va);
        else BinaryPrimitives.WriteUInt32LittleEndian(rvaOrVa[0..4], (uint)(va));

    }

    public static DelayImportedLibrary? LoadDescriptor(ReadOnlySpan<byte> data, PortableExecutable pe, Stream stream) {

        DelayImportedLibrary delayLoadDescriptor = new DelayImportedLibrary(data);

        if (
            (delayLoadDescriptor.AllAttributes == 0) &&
            (delayLoadDescriptor.DllName.RVA == 0) &&
            (delayLoadDescriptor.ModuleHandleRVA == 0) &&
            (delayLoadDescriptor.ImportAddressTableRVA == 0) &&
            (delayLoadDescriptor.ImportNameTableRVA == 0) &&
            (delayLoadDescriptor.BoundImportAddressTableRVA == 0) &&
            (delayLoadDescriptor.UnloadInformationTableRVA == 0) &&
            (delayLoadDescriptor.TimeDateStamp == 0)
        ) return null;

        stream.Position = SectionHeader.RVAToFileOffset(pe.SectionHeaders, delayLoadDescriptor.DllName.RVA);
        delayLoadDescriptor.DllName = (
            delayLoadDescriptor.GetRVA(delayLoadDescriptor.DllName.RVA, pe),
            StreamHelper.ReadString(stream, Encoding.ASCII, null)
        );

        Span<byte> d = new byte[(pe.OptionalHeader.Magic == OptionalHeader.Pe32PlusSignature) ? 8 : 4].AsSpan();
        List<ImportedFunction> imports = new List<ImportedFunction>();

        for (int i = 0; ; ++i) {

            stream.Position = SectionHeader.RVAToFileOffset(
                pe.SectionHeaders,
                delayLoadDescriptor.GetRVA(
                    (ulong)(delayLoadDescriptor.ImportNameTableRVA + (i * d.Length)), 
                    pe
                )
            );

            stream.ReadExactly(d);
            delayLoadDescriptor.GetRVA(d, pe);

            ushort? ordinal = null, hint = null;
            string? name = null;

            ordinal = ImportedLibrary.GetOrdinalOrName(d, pe, stream, out name, out hint);
            if ((ordinal == null) && (name == null) && (hint == null)) break;

            imports.Add(new ImportedFunction(ordinal, name, hint));

        }

        delayLoadDescriptor.Imports = imports.ToArray();

        return delayLoadDescriptor;
    }

}