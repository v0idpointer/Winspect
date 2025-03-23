/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;

namespace Winspect.Formats.PE.Headers;

/// <summary>
/// Represents the IMAGE_FILE_HEADER structure.
/// </summary>
public class FileHeader {

    public Machine Machine { get; private set; }
    public ushort NumberOfSections { get; private set; }
    public uint TimeDateStamp { get; private set; }
    public uint PointerToSymbolTable { get; private set; }
    public uint NumberOfSymbols { get; private set; }
    public ushort SizeOfOptionalHeader { get; private set; }
    public Characteristics Characteristics { get; private set; }

    public FileHeader(ReadOnlySpan<byte> data) {

        this.Machine = (Machine)(BinaryPrimitives.ReadUInt16LittleEndian(data[0..2]));
        this.NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);
        this.TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);
        this.PointerToSymbolTable = BinaryPrimitives.ReadUInt32LittleEndian(data[8..12]);
        this.NumberOfSymbols = BinaryPrimitives.ReadUInt32LittleEndian(data[12..16]);
        this.SizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(data[16..18]);
        this.Characteristics = (Characteristics)(BinaryPrimitives.ReadUInt16LittleEndian(data[18..20]));

    }

}