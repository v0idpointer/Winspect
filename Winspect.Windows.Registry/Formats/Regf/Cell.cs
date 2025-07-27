/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Windows.Registry.Formats.Regf;

public class Cell {

    public uint Size { get; private set; }
    public byte[] Data { get; private set; }

    public bool IsAllocated => ((this.Size & 0x80000000) == 0x80000000);
    public int ActualSize => (Math.Abs((int)(this.Size)));

    public Cell(uint size, ReadOnlySpan<byte> data) {
        this.Size = size;
        this.Data = data.ToArray();
    }

}