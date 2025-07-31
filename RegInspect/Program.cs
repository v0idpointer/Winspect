using System;
using Winspect.Windows.Registry;
using Winspect.Windows.Registry.Formats.Regf;

Console.WriteLine("Windows Registry Inspection Utility");
Console.WriteLine("Copyright (c) 2025 V0idPointer\r\n");

if (args.Length != 1) {
    Console.WriteLine("Usage: reginspect <path to regf file>");
    return;
}

PrimaryFile regf = new PrimaryFile(args[0]);

void PrintIndented(string text, int indent) {
    for (int i = 0; i < indent; i++) Console.Write("  ");
    Console.WriteLine(text);
}

void PrintKey(Key key, int indent) {

    PrintIndented(key.Name, indent);
    foreach (Key subkey in key.Subkeys)
        PrintKey(subkey, indent + 1);

}

Key hive = WindowsRegistry.LoadFromPrimaryFile(regf);
PrintKey(hive, 0);