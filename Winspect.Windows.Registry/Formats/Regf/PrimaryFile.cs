/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Collections.Generic;
using System.IO;

namespace Winspect.Windows.Registry.Formats.Regf;

public class PrimaryFile {

    public Stream? Stream { get; private set; }

    public BaseBlock BaseBlock { get; private set; }
    public HiveBin[] HiveBins { get; private set; }

    public PrimaryFile(Stream stream, bool takeOwnership) {

        stream.Position = 0;

        Span<byte> data = new byte[4096].AsSpan();
        stream.ReadExactly(data);
        this.BaseBlock = new BaseBlock(data);

        if (this.BaseBlock.Signature != BaseBlock.RegfSignature)
            throw new BadRegfFileException("Bad REGF file.");

        List<HiveBin> hiveBins = new List<HiveBin>();
        uint bytesLeft = this.BaseBlock.HiveBinsDataSize;

        while (bytesLeft > 0) {

            uint read;
            HiveBin hiveBin;

            try { hiveBin = HiveBin.LoadHiveBin(stream, out read); }
            catch (Exception ex) {
                throw new BadRegfFileException("Bad REGF file: bad hive bin.", ex);
            }

            hiveBins.Add(hiveBin);
            bytesLeft -= read;

        }

        this.HiveBins = hiveBins.ToArray();

        if (takeOwnership) this.Stream = stream;

    }

    public PrimaryFile(string filepath)
        : this(new FileStream(filepath, FileMode.Open, FileAccess.Read), takeOwnership: true) { }

    public Cell? FindCell(uint offset) {

        if (offset == 0xFFFFFFFF)
            return null;

        foreach (HiveBin hiveBin in this.HiveBins)
            if ((offset >= (hiveBin.Header.Offset)) && (offset < (hiveBin.Header.Offset + hiveBin.Header.Size)))
                if (hiveBin.Cells.ContainsKey((4096 + offset)))
                    return hiveBin.Cells[(4096 + offset)];

        return null;
    }

}
