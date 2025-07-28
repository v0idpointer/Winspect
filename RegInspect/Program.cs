using System;
using System.Text;
using Winspect.Windows.Registry.Formats.Regf;
using Winspect.Windows.Registry.Formats.Regf.Records;

Console.WriteLine("Windows Registry Inspection Utility");
Console.WriteLine("Copyright (c) 2025 V0idPointer\r\n");

if (args.Length != 1) {
    Console.WriteLine("Usage: reginspect <path to regf file>");
    return;
}

PrimaryFile regf = new PrimaryFile(args[0]);
Console.WriteLine("{0} hive bins in hive bins data.", regf.HiveBins.Length);

Cell? rootCell = regf.FindCell(regf.BaseBlock.RootCellOffset);
if (rootCell == null) {
    Console.WriteLine("rootCell == null");
    return;
}

Console.WriteLine("Root cell size: {0:X8} ({1}), Allocated? {2}", rootCell.Size, rootCell.ActualSize, rootCell.IsAllocated ? "Yes" : "No");
Console.WriteLine("Record type: '{0}'", Encoding.ASCII.GetString(rootCell.Data[0..2]));

KeyNodeRecord nk = new KeyNodeRecord(rootCell.Data);
if (nk.Signature != KeyNodeRecord.NkSignature) {
    Console.WriteLine("Bad nk record.");
    return;
}

Console.WriteLine("Key name: '{0}'", nk.KeyNameString);
Console.WriteLine("Is this a root key? {0}", ((nk.Flags & 0x04) == 0x04) ? "Yes" : "No");
