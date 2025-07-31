/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Collections.Generic;
using System.Linq;
using Winspect.Windows.Registry.Formats.Regf;
using Winspect.Windows.Registry.Formats.Regf.Records;

namespace Winspect.Windows.Registry;

public static class WindowsRegistry {

    public static Key LoadFromPrimaryFile(PrimaryFile regf) {

        Cell? rootCell = regf.FindCell(regf.BaseBlock.RootCellOffset);
        if (rootCell == null)
            throw new BadRegfFileException("Bad REGF file: no root cell.");

        Record? record = rootCell.GetRecord();
        if ((record == null) || record is not KeyNodeRecord nk)
            throw new BadRegfFileException("Bad REGF file: no key node record.");

        Key key;
        try { key = WindowsRegistry.LoadKeyFromRecord(regf, nk); }
        catch (Exception ex) {
            throw new BadRegfFileException("Failed to load a registry hive.", ex);
        }

        return key;
    }

    private static uint[] GetSubkeyOffsets(PrimaryFile regf, Record record) {

        if (record is IndexRootRecord ri) {
            
            List<uint> offsets = new List<uint>();

            foreach (uint recordOffset in ri.Elements) {

                Cell? cell = regf.FindCell(recordOffset);
                if (cell == null)
                    throw new BadRegfFileException("Invalid offset.");

                Record? r = cell.GetRecord();
                if (r == null)
                    throw new BadRegfFileException("Bad record.");

                if (r.Type == RecordType.IndexRoot)
                    throw new BadRegfFileException("ri record points to an ri record.");

                offsets.AddRange(WindowsRegistry.GetSubkeyOffsets(regf, r));

            }

            return offsets.ToArray();
        }

        if (record is IndexLeafRecord li)
            return li.Elements;

        if (record is FastLeafRecord lf)
            return lf.Elements.Select(x => x.Offset).ToArray();

        if (record is HashLeafRecord lh)
            return lh.Elements.Select(x => x.Offset).ToArray();

        throw new ArgumentException("The specified record does not contain subkey offsets.", nameof(record));
    }

    private static uint[] GetSubkeyOffsets(PrimaryFile regf, KeyNodeRecord nk) {

        if (nk.SubkeysListOffset == 0xFFFFFFFF)
            return [];

        Cell? cell = regf.FindCell(nk.SubkeysListOffset);
        if (cell == null)
            throw new BadRegfFileException("Invalid offset.");

        Record? record = cell.GetRecord();
        if (record == null)
            throw new BadRegfFileException("Bad record.");

        return WindowsRegistry.GetSubkeyOffsets(regf, record);
    }

    private static uint[] GetKeyValueOffsets(PrimaryFile regf, KeyNodeRecord nk) {
        throw new NotImplementedException();
    }

    private static Key LoadKeyFromRecord(PrimaryFile regf, KeyNodeRecord nk) {

        Key key = new Key(nk.KeyName);

        uint[] subkeyOffsets = WindowsRegistry.GetSubkeyOffsets(regf, nk);
        foreach (uint offset in subkeyOffsets) {

            Cell? cell = regf.FindCell(offset);
            if (cell == null)
                throw new BadRegfFileException("Invalid offset.");

            Record? record = cell.GetRecord();
            if (record == null)
                throw new BadRegfFileException("Bad record.");

            if (record is not KeyNodeRecord subkeyNode)
                throw new BadRegfFileException("Subkey is not an nk record.");

            key.Subkeys.Add(WindowsRegistry.LoadKeyFromRecord(regf, subkeyNode));

        }

        // TODO: read key values.

        return key;
    }

}