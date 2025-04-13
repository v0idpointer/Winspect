using System;
using Winspect.Formats.PE;
using Winspect.Formats.PE.Directories.Export;
using Winspect.Formats.PE.Directories.Import;
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

Console.WriteLine("\n\t*** Section headers ***");
foreach (SectionHeader header in pe.SectionHeaders) {

    Console.WriteLine("Name: {0}", header.Name);
    Console.WriteLine("PhysicalAddress/VirtualSize: {0:X}", header.VirtualSize);
    Console.WriteLine("VirtualAddress: {0:X}", header.VirtualAddress);
    Console.WriteLine("SizeOfRawData: {0:X}", header.SizeOfRawData);
    Console.WriteLine("PointerToRawData: {0:X}", header.PointerToRawData);
    Console.WriteLine("PointerToRelocations: {0:X}", header.PointerToRelocations);
    Console.WriteLine("PointerToLinenumbers: {0:X}", header.PointerToLinenumbers);
    Console.WriteLine("NumberOfRelocations: {0:X}", header.NumberOfRelocations);
    Console.WriteLine("NumberOfLinenumbers: {0:X}", header.NumberOfLinenumbers);
    Console.WriteLine("Characteristics: {0}", header.Characteristics);
    Console.WriteLine();

}

if (pe.ExportDirectory != null) {

    Console.WriteLine("\n\t*** Export directory ***");

    Console.WriteLine("Characteristics: {0:X}", pe.ExportDirectory.Characteristics);
    Console.WriteLine("TimeDateStamp: {0:X}", pe.ExportDirectory.TimeDateStamp);
    Console.WriteLine("MajorVersion: {0:X}", pe.ExportDirectory.MajorVersion);
    Console.WriteLine("MinorVersion: {0:X}", pe.ExportDirectory.MinorVersion);
    Console.WriteLine("Name: {0:X} ({1})", pe.ExportDirectory.Name.RVA, pe.ExportDirectory.Name.Name);
    Console.WriteLine("Base: {0:X}", pe.ExportDirectory.Base);
    Console.WriteLine("NumberOfFunctions: {0:X}", pe.ExportDirectory.NumberOfFunctions);
    Console.WriteLine("NumberOfNames: {0:X}", pe.ExportDirectory.NumberOfNames);
    Console.WriteLine("AddressOfFunctions: {0:X}", pe.ExportDirectory.AddressOfFunctions);
    Console.WriteLine("AddressOfNames: {0:X}", pe.ExportDirectory.AddressOfNames);
    Console.WriteLine("AddressOfNameOrdinals: {0:X}", pe.ExportDirectory.AddressOfNameOrdinals);

    if (pe.ExportDirectory.Exports != null) {

        Console.WriteLine("\nOrdinal RVA Name (RVA) Hint Forwarder");

        foreach (ExportedFunction export in pe.ExportDirectory.Exports.Values) {
        
            Console.Write("{0:X} {1:X} ", export.Ordinal, export.FunctionRVA);

            if (export.Name.HasValue) Console.Write("{0} ({1:X}) ", export.Name.Value.Name, export.Name.Value.RVA);
            else Console.Write("/ (/) ");

            if (export.Hint.HasValue) Console.Write("{0} ", export.Hint.Value);
            else Console.Write("/ ");
            
            if (export.Forwarder != null) Console.Write("{0}", export.Forwarder);
            else Console.Write("/");

            Console.WriteLine();

        }

    }

}

if (pe.ImportDirectory != null) {

    Console.WriteLine("\n\t*** Import Directory ***\n");

    if (pe.ImportDirectory.Imports != null) {

        foreach ((string name, ImportedLibrary import) in pe.ImportDirectory.Imports) {

            Console.WriteLine("Characteristics/OriginalFirstThunk: {0:X}", import.Characteristics);
            Console.WriteLine("TimeDateStamp: {0:X}", import.TimeDateStamp);
            Console.WriteLine("ForwarderChain: {0:X}", import.ForwarderChain);
            Console.WriteLine("Name: {0:X} ({1})", import.Name.RVA, import.Name.Name);
            Console.WriteLine("FirstThunk: {0:X}", import.FirstThunk);

            if (import.Imports != null) {

                Console.WriteLine();

                foreach (ImportedFunction fn in import.Imports) {
                    if (fn.Ordinal.HasValue) Console.WriteLine("\tOrdinal {0} ({0:X})", fn.Ordinal);
                    else Console.WriteLine("\t{0} ({1:X})", fn.Name, fn.Hint);
                }

            }

            Console.WriteLine();

        }

    }

}