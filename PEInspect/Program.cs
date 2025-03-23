using System;
using Winspect.Formats.PE;
using Winspect.Formats.PE.Headers;

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

if (args.Length != 1) {
    Console.WriteLine("*** usage: PEInspect <path>");
    return;
}

PortableExecutable pe = new PortableExecutable(args[0]);

Console.WriteLine("\n\t*** DOS header ***");
Console.WriteLine("e_magic: {0:X} ({1})", pe.DosHeader.Magic, (pe.DosHeader.Magic == DosHeader.DosSignature ? "Valid" : "Invalid"));
Console.WriteLine("e_cblp: {0:X}", pe.DosHeader.Cblp);
Console.WriteLine("e_cp: {0:X}", pe.DosHeader.Cp);
Console.WriteLine("e_crlc: {0:X}", pe.DosHeader.Crlc);
Console.WriteLine("e_cparhdr: {0:X}", pe.DosHeader.Cparhdr);
Console.WriteLine("e_minalloc: {0:X}", pe.DosHeader.Minalloc);
Console.WriteLine("e_maxalloc: {0:X}", pe.DosHeader.Maxalloc);
Console.WriteLine("e_ss: {0:X}", pe.DosHeader.Ss);
Console.WriteLine("e_sp: {0:X}", pe.DosHeader.Sp);
Console.WriteLine("e_csum: {0:X}", pe.DosHeader.Csum);
Console.WriteLine("e_ip: {0:X}", pe.DosHeader.Ip);
Console.WriteLine("e_cs: {0:X}", pe.DosHeader.Cs);
Console.WriteLine("e_lfarlc: {0:X}", pe.DosHeader.Lfarlc);
Console.WriteLine("e_ovno: {0:X}", pe.DosHeader.Ovno);
Console.WriteLine("e_oemid: {0:X}", pe.DosHeader.Oemid);
Console.WriteLine("e_oeminfo: {0:X}", pe.DosHeader.Oeminfo);
Console.WriteLine("e_lfanew: {0:X}", pe.DosHeader.Lfanew);

Console.WriteLine("\n\t*** NT signature ***");
Console.WriteLine(pe.Signature);

Console.WriteLine("\n\t*** File header ***");
Console.WriteLine("Machine: {0}", pe.FileHeader.Machine);
Console.WriteLine("NumberOfSections: {0:X}", pe.FileHeader.NumberOfSections);
Console.WriteLine("TimeDateStamp: {0:X}", pe.FileHeader.TimeDateStamp);
Console.WriteLine("PointerToSymbolTable: {0:X}", pe.FileHeader.PointerToSymbolTable);
Console.WriteLine("NumberOfSymbols: {0:X}", pe.FileHeader.NumberOfSymbols);
Console.WriteLine("SizeOfOptionalHeader: {0:X}", pe.FileHeader.SizeOfOptionalHeader);
Console.WriteLine("Characteristics: {0}", pe.FileHeader.Characteristics);

Console.WriteLine("\n\t*** Optional header ***");
Console.WriteLine("Magic: {0:X}", pe.OptionalHeader.Magic);
Console.WriteLine("MajorLinkerVersion: {0:X}", pe.OptionalHeader.MajorLinkerVersion);
Console.WriteLine("MinorLinkerVersion: {0:X}", pe.OptionalHeader.MinorLinkerVersion);
Console.WriteLine("SizeOfCode: {0:X}", pe.OptionalHeader.SizeOfCode);
Console.WriteLine("SizeOfInitializedData: {0:X}", pe.OptionalHeader.SizeOfInitializedData);
Console.WriteLine("SizeOfUninitializedData: {0:X}", pe.OptionalHeader.SizeOfUninitializedData);
Console.WriteLine("AddressOfEntryPoint: {0:X}", pe.OptionalHeader.AddressOfEntryPoint);
Console.WriteLine("BaseOfCode: {0:X}", pe.OptionalHeader.BaseOfCode);
Console.WriteLine("BaseOfData: {0:X}", pe.OptionalHeader.BaseOfData);
Console.WriteLine("ImageBase: {0:X}", pe.OptionalHeader.ImageBase);
Console.WriteLine("SectionAlignment: {0:X}", pe.OptionalHeader.SectionAlignment);
Console.WriteLine("FileAlignment: {0:X}", pe.OptionalHeader.FileAlignment);
Console.WriteLine("MajorOperatingSystemVersion: {0:X}", pe.OptionalHeader.MajorOperatingSystemVersion);
Console.WriteLine("MinorOperatingSystemVersion: {0:X}", pe.OptionalHeader.MinorOperatingSystemVersion);
Console.WriteLine("MajorImageVersion: {0:X}", pe.OptionalHeader.MajorImageVersion);
Console.WriteLine("MinorImageVersion: {0:X}", pe.OptionalHeader.MinorImageVersion);
Console.WriteLine("MajorSubsystemVersion: {0:X}", pe.OptionalHeader.MajorSubsystemVersion);
Console.WriteLine("MinorSubsystemVersion: {0:X}", pe.OptionalHeader.MinorSubsystemVersion);
Console.WriteLine("Win32VersionValue: {0:X}", pe.OptionalHeader.Win32VersionValue);
Console.WriteLine("SizeOfImage: {0:X}", pe.OptionalHeader.SizeOfImage);
Console.WriteLine("SizeOfHeaders: {0:X}", pe.OptionalHeader.SizeOfHeaders);
Console.WriteLine("CheckSum: {0:X}", pe.OptionalHeader.CheckSum);
Console.WriteLine("Subsystem: {0}", pe.OptionalHeader.Subsystem);
Console.WriteLine("DllCharacteristics: {0}", pe.OptionalHeader.DllCharacteristics);
Console.WriteLine("SizeOfStackReserve: {0:X}", pe.OptionalHeader.SizeOfStackReserve);
Console.WriteLine("SizeOfStackCommit: {0:X}", pe.OptionalHeader.SizeOfStackCommit);
Console.WriteLine("SizeOfHeapReserve: {0:X}", pe.OptionalHeader.SizeOfHeapReserve);
Console.WriteLine("SizeOfHeapCommit: {0:X}", pe.OptionalHeader.SizeOfHeapCommit);
Console.WriteLine("LoaderFlags: {0:X}", pe.OptionalHeader.LoaderFlags);
Console.WriteLine("NumberOfRvaAndSizes: {0:X}", pe.OptionalHeader.NumberOfRvaAndSizes);
Console.WriteLine();

foreach (DirectoryEntry entry in pe.OptionalHeader.DataDirectories.Keys) {
    DataDirectory directory = pe.OptionalHeader.DataDirectories[entry];
    Console.WriteLine("{0}: RVA: {1:X}, Size: {2:X}", entry, directory.VirtualAddress, directory.Size);
}