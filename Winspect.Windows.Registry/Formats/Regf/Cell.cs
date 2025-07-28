/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Text;
using Winspect.Windows.Registry.Formats.Regf.Records;

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

    public Record? GetRecord() {

        if (this.Data.Length < 2) return null;

        string signature = Encoding.ASCII.GetString(this.Data[0..2]);
        return signature switch {

            "li" => new IndexLeafRecord(this.Data),
            "lf" => new FastLeafRecord(this.Data),
            "lh" => new HashLeafRecord(this.Data),
            "ri" => new IndexRootRecord(this.Data),
            "nk" => new KeyNodeRecord(this.Data),
            "vk" => new KeyValueRecord(this.Data),
            "sk" => throw new NotImplementedException(),
            "db" => throw new NotImplementedException(),
            _ => null

        };

    }

}