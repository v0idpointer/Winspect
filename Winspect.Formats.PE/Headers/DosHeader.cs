/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;

namespace Winspect.Formats.PE.Headers;

/// <summary>
/// Represents the IMAGE_DOS_HEADER structure.
/// </summary>
public class DosHeader {

    /// <summary>
    /// MZ
    /// </summary>
    public static readonly ushort DosSignature = 0x5A4D;

    /// <summary>
    /// Magic number
    /// </summary>
    public ushort Magic { get; private set; }

    /// <summary>
    /// Bytes on last page of file
    /// </summary>
    public ushort Cblp { get; private set; }

    /// <summary>
    /// Pages in file
    /// </summary>
    public ushort Cp { get; private set; }

    /// <summary>
    /// Relocations
    /// </summary>
    public ushort Crlc { get; private set; }

    /// <summary>
    /// Size of header in paragraphs
    /// </summary>
    public ushort Cparhdr { get; private set; }

    /// <summary>
    /// Minimum extra paragraphs needed
    /// </summary>
    public ushort Minalloc { get; private set; }

    /// <summary>
    /// Maximum extra paragraphs needed
    /// </summary>
    public ushort Maxalloc { get; private set; }

    /// <summary>
    /// Initial (relative) SS value
    /// </summary>
    public ushort Ss { get; private set; }

    /// <summary>
    /// Initial SP value
    /// </summary>
    public ushort Sp { get; private set; }

    /// <summary>
    /// Checksum
    /// </summary>
    public ushort Csum { get; private set; }

    /// <summary>
    /// Initial IP value
    /// </summary>
    public ushort Ip { get; private set; }

    /// <summary>
    /// Initial (relative) CS value
    /// </summary>
    public ushort Cs { get; private set; }

    /// <summary>
    /// File address of relocation table
    /// </summary>
    public ushort Lfarlc { get; private set; }

    /// <summary>
    /// Overlay number
    /// </summary>
    public ushort Ovno { get; private set; }    

    /// <summary>
    /// OEM identifier
    /// </summary>
    public ushort Oemid { get; private set; }

    /// <summary>
    /// OEM information
    /// </summary>
    public ushort Oeminfo { get; private set; }

    /// <summary>
    /// File address of new exe header
    /// </summary>
    public uint Lfanew { get; private set; }

    public DosHeader(ReadOnlySpan<byte> data) {

        this.Magic = BinaryPrimitives.ReadUInt16LittleEndian(data[0..2]);
        this.Cblp = BinaryPrimitives.ReadUInt16LittleEndian(data[2..4]);
        this.Cp = BinaryPrimitives.ReadUInt16LittleEndian(data[4..6]);
        this.Crlc = BinaryPrimitives.ReadUInt16LittleEndian(data[6..8]);
        this.Cparhdr = BinaryPrimitives.ReadUInt16LittleEndian(data[8..10]);
        this.Minalloc = BinaryPrimitives.ReadUInt16LittleEndian(data[10..12]);
        this.Maxalloc = BinaryPrimitives.ReadUInt16LittleEndian(data[12..14]);
        this.Ss = BinaryPrimitives.ReadUInt16LittleEndian(data[14..16]);
        this.Sp = BinaryPrimitives.ReadUInt16LittleEndian(data[16..18]);
        this.Csum = BinaryPrimitives.ReadUInt16LittleEndian(data[18..20]);
        this.Ip = BinaryPrimitives.ReadUInt16LittleEndian(data[20..22]);
        this.Cs = BinaryPrimitives.ReadUInt16LittleEndian(data[22..24]);
        this.Lfarlc = BinaryPrimitives.ReadUInt16LittleEndian(data[24..26]);
        this.Ovno = BinaryPrimitives.ReadUInt16LittleEndian(data[26..28]);
        
        this.Oemid = BinaryPrimitives.ReadUInt16LittleEndian(data[36..38]);
        this.Oeminfo = BinaryPrimitives.ReadUInt16LittleEndian(data[38..40]);

        this.Lfanew = BinaryPrimitives.ReadUInt32LittleEndian(data[60..64]);

    }

}