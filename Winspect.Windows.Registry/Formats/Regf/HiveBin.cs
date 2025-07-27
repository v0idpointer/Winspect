/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace Winspect.Windows.Registry.Formats.Regf;

public class HiveBin {

    public HiveBinHeader Header { get; private set; }
    public Dictionary<uint, Cell> Cells { get; private set; }

    public HiveBin(HiveBinHeader header, ReadOnlySpan<byte> cellsData) {

        if (header.Signature != HiveBinHeader.HbinSignature)
            throw new ArgumentException("Bad hive bin: invalid signature.", nameof(header));

        if (cellsData.Length != (header.Size - 32))
            throw new ArgumentException("Data length mismatch.", nameof(cellsData));

        this.Header = header;
        this.Cells = new Dictionary<uint, Cell>();

        uint firstCellOffset = (4096 + header.Offset + 32);
        uint offset = firstCellOffset;
        while (offset < (4096 + header.Offset + header.Size)) {

            offset = (uint)((offset + 7) & ~7);

            int idx = (int)(offset - firstCellOffset);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(cellsData[idx..(idx + 4)]);
            int actualSize = Math.Abs((int)(size));

            Cell cell = new Cell(
                size,
                cellsData[(idx + 4)..(idx + actualSize)]
            );

            this.Cells.Add(offset, cell);
            offset += (uint)(actualSize);

        }

    }

    public HiveBin(ReadOnlySpan<byte> headerData, ReadOnlySpan<byte> cellsData)
        : this(new HiveBinHeader(headerData), cellsData) { }

    public static HiveBin LoadHiveBin(Stream stream, out uint bytesRead) {

        Span<byte> data = new byte[32].AsSpan();
        stream.ReadExactly(data);
        bytesRead = 32;

        HiveBinHeader header = new HiveBinHeader(data);
        data = new byte[header.Size - 32].AsSpan();
        stream.ReadExactly(data);
        
        bytesRead += (uint)(data.Length);
        return new HiveBin(header, data);
    }

    public static HiveBin LoadHiveBin(Stream stream) {
        return HiveBin.LoadHiveBin(stream, out _);
    }

}
