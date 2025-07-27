using System;
using Winspect.Windows.Registry.Formats.Regf;

Console.WriteLine("Windows Registry Inspection Utility");
Console.WriteLine("Copyright (c) 2025 V0idPointer\r\n");

if (args.Length != 1) {
    Console.WriteLine("Usage: reginspect <path to regf file>");
    return;
}

PrimaryFile regf = new PrimaryFile(args[0]);
Console.WriteLine("{0} hive bins in hive bins data.", regf.HiveBins.Length);