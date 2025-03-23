/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;

namespace Winspect.Formats.PE.Headers;

/// <summary>
/// Represents the IMAGE_DATA_DIRECTORY structure.
/// </summary>
public class DataDirectory {

    public uint VirtualAddress { get; private set; }
    public uint Size { get; private set; }

    public DataDirectory(ReadOnlySpan<byte> data) {
        
        this.VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(data[0..4]);
        this.Size = BinaryPrimitives.ReadUInt32LittleEndian(data[4..8]);

    }

}