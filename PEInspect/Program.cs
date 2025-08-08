/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.IO;
using System.Linq;
using System.Text;
using Winspect.Formats.PE;
using Winspect.Formats.PE.Directories.Debug;
using Winspect.Formats.PE.Directories.DelayImport;
using Winspect.Formats.PE.Directories.Export;
using Winspect.Formats.PE.Directories.Import;
using Winspect.Formats.PE.Directories.Resource;
using Winspect.Formats.PE.Headers;

internal class Program {

    static int Main(string[] args) {

        if (!args.Contains("--nologo")) {
            Console.WriteLine("Portable Executable (PE) Inspection Utility");
            Console.WriteLine("Copyright (c) 2025 V0idPointer\r\n");
        }

        RootCommand rootCommand = new RootCommand();
        rootCommand.Name = "PEInspect";
        rootCommand.Description = "Inspects the structure and contents of a Portable Executable (PE) file."; 
        rootCommand.AddArgument(new Argument<FileInfo>("file", "The PE file to inspect"));
        rootCommand.AddOption(new Option<bool>("--headers", "Inspect the PE headers"));
        rootCommand.AddOption(new Option<bool>("--exports", "Inspect the PE exports"));
        rootCommand.AddOption(new Option<bool>("--imports", "Inspect the PE imports"));
        rootCommand.AddOption(new Option<bool>("--resources", "Inspect the embedded resources"));
        rootCommand.AddOption(new Option<bool>("--debug", "Inspects the debug directory"));
        rootCommand.AddOption(new Option<bool>("--nologo", "Suppress the startup logo"));
        rootCommand.Handler = CommandHandler.Create(Program.Handler);

        if (args.Length == 0) args = new string[] { "-?" };
        return rootCommand.Invoke(args);
    }

    private static int Handler(FileInfo file, bool headers, bool exports, bool imports, bool resources, bool debug) {

        PortableExecutable pe;

        try { pe = new PortableExecutable(file.FullName); }
        catch (Exception ex) {
            Console.WriteLine("*** {0}", ex.Message);
            return -1;
        }

        if (headers) {
            Program.Inspect(pe.DosHeader);
            Program.Inspect(pe.Signature);
            Program.Inspect(pe.FileHeader);
            Program.Inspect(pe.OptionalHeader);
            Program.Inspect(pe.SectionHeaders);
        }

        if (exports && (pe.ExportDirectory != null))
            Program.Inspect(pe.ExportDirectory);

        if (imports && (pe.ImportDirectory != null))
            Program.Inspect(pe.ImportDirectory);

        if (imports && (pe.DelayImportDirectory != null))
            Program.Inspect(pe.DelayImportDirectory);

        if (resources && (pe.ResourceDirectory != null)) {
            Program.Inspect(pe.ResourceDirectory);
            Program.InspectResourceDirectoryTree(pe);
        }

        if (debug && (pe.DebugDirectory != null))
            Program.Inspect(pe.DebugDirectory);

        if (!headers && !exports && !imports && !resources && !debug)
            Console.WriteLine("No options provided.");

        return 0;
    }

    private static void Inspect(DosHeader dosHeader) {

        Console.WriteLine("\tDOS header\n");

        string magic = new string([
            (char)(dosHeader.Magic & 0xFF),
            (char)((dosHeader.Magic >> 8) & 0xFF),
        ]);

        Console.WriteLine("{0,-39}{1,-7:X4}{2}", "Magic", dosHeader.Magic, magic);
        Console.WriteLine("{0,-39}{1:X4}", "Bytes on last page of file", dosHeader.Cblp);
        Console.WriteLine("{0,-39}{1:X4}", "Pages in file", dosHeader.Cp);
        Console.WriteLine("{0,-39}{1:X4}", "Relocations", dosHeader.Crlc);
        Console.WriteLine("{0,-39}{1:X4}", "Size of header in paragraphs", dosHeader.Cparhdr);
        Console.WriteLine("{0,-39}{1:X4}", "Minimum extra paragraphs needed", dosHeader.Minalloc);
        Console.WriteLine("{0,-39}{1:X4}", "Maximum extra paragraphs needed", dosHeader.Maxalloc);
        Console.WriteLine("{0,-39}{1:X4}", "Initial (relative) SS value", dosHeader.Ss);
        Console.WriteLine("{0,-39}{1:X4}", "Initial SP value", dosHeader.Sp);
        Console.WriteLine("{0,-39}{1:X4}", "Checksum", dosHeader.Csum);
        Console.WriteLine("{0,-39}{1:X4}", "Initial IP value", dosHeader.Ip);
        Console.WriteLine("{0,-39}{1:X4}", "Initial (relative) CS value", dosHeader.Cs);
        Console.WriteLine("{0,-39}{1:X4}", "File address of relocation table", dosHeader.Lfarlc);
        Console.WriteLine("{0,-39}{1:X4}", "Overlay number", dosHeader.Ovno);
        Console.WriteLine("{0,-39}{1:X4}", "OEM identifier", dosHeader.Oemid);
        Console.WriteLine("{0,-39}{1:X4}", "OEM information", dosHeader.Oeminfo);
        Console.WriteLine("{0,-35}{1:X8}", "File address of new EXE header", dosHeader.Lfanew);
        Console.WriteLine();

    }

    private static void Inspect(string ntSignature) {

        Console.WriteLine("\tNT signature\n");

        byte[] bytes = Encoding.ASCII.GetBytes(ntSignature);
        foreach (byte b in bytes) Console.Write("{0,-3:X2}", b);

        if (ntSignature == PortableExecutable.NtSignature) Console.WriteLine("{0,8}", "PE\\0\\0");
        else Console.WriteLine();

        Console.WriteLine();

    }

    private static Dictionary<Machine, string> s_machines = new Dictionary<Machine, string>() {

        { Machine.Unknown, "Unknown" },
        { Machine.Alpha, "Alpha AXP" },
        { Machine.Alpha64, "Alpha 64" },
        { Machine.Am33, "Matsushita AM33" },
        { Machine.Amd64, "AMD64" },
        { Machine.Arm, "ARM" },
        { Machine.Arm64, "AArch64" },
        { Machine.ArmNt, "ARM Thumb-2" },
        { Machine.Ebc, "EFI byte code" },
        { Machine.I386, "x86" },
        { Machine.Ia64, "Itanium" },
        { Machine.LoongArch32, "32-bit LoongArch" },
        { Machine.LoongArch64, "64-bit LoongArch" },
        { Machine.M32R, "Mitsubishi M32R" },
        { Machine.Mips16, "MIPS16" },
        { Machine.MipsFpu, "MIPS /w FPU" },
        { Machine.MipsFpu16, "MIPS16 /w FPU" },
        { Machine.PowerPc, "PowerPC" },
        { Machine.PowerPcFp, "PowerPC /w FPU" },
        { Machine.R3000BigEndian, "MIPS R3000 (big endian)" },
        { Machine.R3000, "MIPS R3000" },
        { Machine.R4000, "MIPS R4000" },
        { Machine.RiscV32, "32-bit RISC-V" },
        { Machine.RiscV64, "64-bit RISC-V" },
        { Machine.RiscV128, "128-bit RISC-V" },
        { Machine.Sh3, "Hitachi SH3" },
        { Machine.Sh3Dsp, "Hitachi SH3 DSP" },
        { Machine.Sh4, "Hitachi SH4" },
        { Machine.Sh5, "Hitachi SH5" },
        { Machine.Thumb, "ARM Thumb" },
        { Machine.WceMipsV2, "MIPS WCE v2" },

    };

    private static Dictionary<Characteristics, string> s_characteristics = new Dictionary<Characteristics, string>() {
        
        { Characteristics.RelocsStripped, "Relocation information was stripped from the file." },
        { Characteristics.ExecutableImage, "File is executable (i.e. no unresolved external references)." },
        { Characteristics.LineNumsStripped, "COFF line numbers have been removed." },
        { Characteristics.LocalSymsStripped, "COFF symbol table entries for local symbols have been removed." },
        { Characteristics.AggressiveWsTrim, "Aggressively trim the working set." },
        { Characteristics.LargeAddressAware, "The application can handle addresses larger than 2 GB." },
        { Characteristics.BytesReversedLo, "Little endian" },
        { Characteristics.Bits32Machine, "The machine is based on a 32-bit word architecture." },
        { Characteristics.DebugStripped, "Debugging information is removed from the image file." },
        { Characteristics.RemovableRunFromSwap, "If the image is on removable media, fully load it and copy it to the swap file." },
        { Characteristics.NetRunFromSwap, "If the image is on network media, fully load it and copy it to the swap file." },
        { Characteristics.System, "The image file is a system file." },
        { Characteristics.Dll, "The image file is a dynamic-link library (DLL)." },
        { Characteristics.UpSystemOnly, "The file should be run only on a uniprocessor machine." },
        { Characteristics.BytesReversedHi, "Big endian" },

    };

    private static void Inspect(FileHeader fileHeader) {

        Console.WriteLine("\tFile header\n");

        Console.Write("{0,-30}{1,-7:X4}", "Machine", (ushort)(fileHeader.Machine));
        Console.WriteLine("{0}", Program.s_machines.GetValueOrDefault(fileHeader.Machine, string.Empty));

        Console.WriteLine("{0,-30}{1:X4}", "Number of sections", fileHeader.NumberOfSections);
        Console.WriteLine("{0,-26}{1:X8}", "Time date stamp", fileHeader.TimeDateStamp);
        Console.WriteLine("{0,-26}{1:X8}", "Pointer to symbol table", fileHeader.PointerToSymbolTable);
        Console.WriteLine("{0,-26}{1:X8}", "Number of symbols", fileHeader.NumberOfSymbols);
        Console.WriteLine("{0,-30}{1:X4}", "Size of optional header", fileHeader.SizeOfOptionalHeader);

        bool firstTime = true;
        Console.Write("{0,-30}{1,-7:X4}", "Characteristics", (ushort)(fileHeader.Characteristics));
        foreach (Characteristics flag in Enum.GetValues<Characteristics>()) { 
            if ((fileHeader.Characteristics & flag) == 0) continue;
            if (!firstTime) Console.Write("\n{0,-37}", string.Empty);
            Console.Write("- {0,-7:X4}{1}", (ushort)(flag), Program.s_characteristics.GetValueOrDefault(flag, string.Empty));
            firstTime = false;
        }

        Console.WriteLine("\n");

    }

    private static Dictionary<Subsystem, string> s_subsystems = new Dictionary<Subsystem, string>() {

        { Subsystem.Unknown, "Unknown" },
        { Subsystem.Native, "Native" },
        { Subsystem.WindowsGui, "Windows GUI" },
        { Subsystem.WindowsCui, "Windows console" },
        { Subsystem.Os2Cui, "OS/2 console" },
        { Subsystem.PosixCui, "POSIX console" },
        { Subsystem.NativeWindows, "Native Win9x driver" },
        { Subsystem.WindowsCeGui, "Windows CE" },
        { Subsystem.EfiApplication, "EFI application" },
        { Subsystem.EfiBootServiceDriver, "EFI driver /w boot services" },
        { Subsystem.EfiRuntimeDriver, "EFI driver /w runtime services" },
        { Subsystem.EfiRom, "EFI ROM image" },
        { Subsystem.Xbox, "Xbox" },
        { Subsystem.WindowsBootApplication, "Windows boot application" },
        { Subsystem.XboxCodeCatalog, "Xbox code catalog" },

    };

    private static Dictionary<uint, string> s_windowsVersions = new Dictionary<uint, string>() {

        { 0x000A0000, "Windows 10 (Server 2016/2019/2022) or Windows 11 (Server 2025)" },
        { 0x00060003, "Windows 8.1 (Server 2012 R2)" },
        { 0x00060002, "Windows 8 (Server 2012)" },
        { 0x00060001, "Windows 7 (Server 2008 R2)" },
        { 0x00060000, "Windows Vista (Server 2008)" },
        { 0x00050002, "Windows Server 2003" },
        { 0x00050001, "Windows XP" },
        { 0x00050000, "Windows 2000" },
        { 0x00040000, "Windows NT 4.0" },
        { 0x00030033, "Windows NT 3.51" },
        { 0x00010000, "Windows NT 3.1 or Windows NT 3.5" },

    };

    private static string GetVersion(ushort major, ushort minor, Dictionary<uint, string>? names) {
        
        uint version = (((uint)(major) << 16) | minor);
        string str = string.Format("{0}.{1}", major, minor);

        if (names != null) return names.GetValueOrDefault(version, str);
        else return str;
    }

    private static Dictionary<DllCharacteristics, string> s_dllCharacteristics = new Dictionary<DllCharacteristics, string>() {

        { DllCharacteristics.HighEntropyVa, "Image can handle a high entropy 64-bit virtual address space." },
        { DllCharacteristics.DynamicBase, "DLL can be relocated at load time." },
        { DllCharacteristics.ForceIntegrity, "Code Integrity checks are enforced." },
        { DllCharacteristics.NxCompat, "Image is NX compatible." },
        { DllCharacteristics.NoIsolation, "Isolation aware, but do not isolate the image." },
        { DllCharacteristics.NoSeh, "Does not use structured exception (SE) handling." },
        { DllCharacteristics.NoBind, "Do not bind the image." },
        { DllCharacteristics.AppContainer, "Image must execute in an AppContainer." },
        { DllCharacteristics.WdmDriver, "A WDM driver." },
        { DllCharacteristics.GuardCf, "Image supports Control Flow Guard." },
        { DllCharacteristics.TerminalServerAware, "Terminal Server aware." },

    };

    private static Dictionary<DirectoryEntry, string> s_dataDirectories = new Dictionary<DirectoryEntry, string>() {

        { DirectoryEntry.Export, "Export directory" },
        { DirectoryEntry.Import, "Import directory" },
        { DirectoryEntry.Resource, "Resource directory" },
        { DirectoryEntry.Exception, "Exception directory" },
        { DirectoryEntry.Security, "Security directory" },
        { DirectoryEntry.BaseReloc, "Base relocation table" },
        { DirectoryEntry.Debug, "Debug directory" },
        { DirectoryEntry.Architecture, "Architecture specific data" },
        { DirectoryEntry.GlobalPtr, "RVA of GlobalPtr" },
        { DirectoryEntry.Tls, "TLS directory" },
        { DirectoryEntry.LoadConfig, "Load configuration directory" },
        { DirectoryEntry.BoundImport, "Bound import directory" },
        { DirectoryEntry.Iat, "Import address table" },
        { DirectoryEntry.DelayImport, "Delay load import descriptors" },
        { DirectoryEntry.ComDescriptor, "COM runtime descriptor" },
        { DirectoryEntry.Reserved, "Reserved" },

    };

    private static void Inspect(OptionalHeader optionalHeader) {

        Console.WriteLine("\tOptional header\n");

        int defaultPad = 33;
        int pad = (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) ? (defaultPad + 8) : defaultPad;

        Console.Write("{0}{1,-7:X4}", "Magic".PadRight(pad + 4), optionalHeader.Magic);
        if (optionalHeader.Magic == OptionalHeader.Pe32Signature) Console.WriteLine("PE32");
        else if (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) Console.WriteLine("PE32+");
        else Console.WriteLine();

        Console.WriteLine("{0}{1:X2}", "Major linker version".PadRight(pad + 6), optionalHeader.MajorLinkerVersion);
        Console.WriteLine("{0}{1:X2}", "Minor linker version".PadRight(pad + 6), optionalHeader.MinorLinkerVersion);
        Console.WriteLine("{0}{1:X8}", "Size of code".PadRight(pad), optionalHeader.SizeOfCode);
        Console.WriteLine("{0}{1:X8}", "Size of initialized data".PadRight(pad), optionalHeader.SizeOfInitializedData);
        Console.WriteLine("{0}{1:X8}", "Size of uninitialized data".PadRight(pad), optionalHeader.SizeOfUninitializedData);
        Console.WriteLine("{0}{1:X8}", "Address of entry point".PadRight(pad), optionalHeader.AddressOfEntryPoint);
        Console.WriteLine("{0}{1:X8}", "Base of code".PadRight(pad), optionalHeader.BaseOfCode);
        Console.WriteLine("{0}{1:X8}", "Base of data".PadRight(pad), optionalHeader.BaseOfData.HasValue ? optionalHeader.BaseOfData : string.Empty);
        
        Console.Write("Image base".PadRight(defaultPad));
        if (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) Console.WriteLine("{0:X16}", optionalHeader.ImageBase);
        else Console.WriteLine("{0:X8}", (uint)(optionalHeader.ImageBase));

        Console.WriteLine("{0}{1:X8}", "Section alignment".PadRight(pad), optionalHeader.SectionAlignment);
        Console.WriteLine("{0}{1:X8}", "File alignment".PadRight(pad), optionalHeader.FileAlignment);
        
        Console.Write("{0}{1,-7:X4}", "Major operating system version".PadRight(pad + 4), optionalHeader.MajorOperatingSystemVersion);
        Console.WriteLine(Program.GetVersion(optionalHeader.MajorOperatingSystemVersion, optionalHeader.MinorOperatingSystemVersion, s_windowsVersions));
        Console.WriteLine("{0}{1:X4}", "Minor operating system version".PadRight(pad + 4), optionalHeader.MinorOperatingSystemVersion);
        
        Console.Write("{0}{1,-7:X4}", "Major image version".PadRight(pad + 4), optionalHeader.MajorImageVersion);
        Console.WriteLine(Program.GetVersion(optionalHeader.MajorImageVersion, optionalHeader.MinorImageVersion, null));
        Console.WriteLine("{0}{1:X4}", "Minor image version".PadRight(pad + 4), optionalHeader.MinorImageVersion);
        
        Console.Write("{0}{1,-7:X4}", "Major subsystem version".PadRight(pad + 4), optionalHeader.MajorSubsystemVersion);
        Console.WriteLine(Program.GetVersion(optionalHeader.MajorSubsystemVersion, optionalHeader.MinorSubsystemVersion, null));
        Console.WriteLine("{0}{1:X4}", "Minor subsystem version".PadRight(pad + 4), optionalHeader.MinorSubsystemVersion);
        
        Console.WriteLine("{0}{1:X8}", "Win32 version value".PadRight(pad), optionalHeader.Win32VersionValue);
        Console.WriteLine("{0}{1:X8}", "Size of image".PadRight(pad), optionalHeader.SizeOfImage);
        Console.WriteLine("{0}{1:X8}", "Size of headers".PadRight(pad), optionalHeader.SizeOfHeaders);
        Console.WriteLine("{0}{1:X8}", "Checksum".PadRight(pad), optionalHeader.CheckSum);
        
        Console.Write("{0}{1,-7:X4}", "Subsystem".PadRight(pad + 4), (ushort)(optionalHeader.Subsystem));
        Console.WriteLine("{0}", Program.s_subsystems.GetValueOrDefault(optionalHeader.Subsystem, string.Empty));

        bool firstTime = true;
        Console.Write("{0}{1,-7:X4}", "DLL Characteristics".PadRight(pad + 4), (ushort)(optionalHeader.DllCharacteristics));
        foreach (DllCharacteristics flag in Enum.GetValues<DllCharacteristics>()) {
            if ((optionalHeader.DllCharacteristics & flag) == 0) continue;
            if (!firstTime) Console.Write("\n{0}", string.Empty.PadRight(pad + 11));
            Console.Write("- {0,-7:X4}{1}", (ushort)(flag), Program.s_dllCharacteristics.GetValueOrDefault(flag, string.Empty));
            firstTime = false;
        }
        Console.WriteLine();

        Console.Write("Size of stack reserve".PadRight(defaultPad));
        if (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) Console.WriteLine("{0:X16}", optionalHeader.SizeOfStackReserve);
        else Console.WriteLine("{0:X8}", (uint)(optionalHeader.SizeOfStackReserve));

        Console.Write("Size of stack commit".PadRight(defaultPad));
        if (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) Console.WriteLine("{0:X16}", optionalHeader.SizeOfStackCommit);
        else Console.WriteLine("{0:X8}", (uint)(optionalHeader.SizeOfStackCommit));

        Console.Write("Size of heap reserve".PadRight(defaultPad));
        if (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) Console.WriteLine("{0:X16}", optionalHeader.SizeOfHeapReserve);
        else Console.WriteLine("{0:X8}", (uint)(optionalHeader.SizeOfHeapReserve));

        Console.Write("Size of heap commit".PadRight(defaultPad));
        if (optionalHeader.Magic == OptionalHeader.Pe32PlusSignature) Console.WriteLine("{0:X16}", optionalHeader.SizeOfHeapCommit);
        else Console.WriteLine("{0:X8}", (uint)(optionalHeader.SizeOfHeapCommit));

        Console.WriteLine("{0}{1:X8}", "Loader flags".PadRight(pad), optionalHeader.LoaderFlags);
        Console.WriteLine("{0}{1:X8}", "Number of RVA and sizes".PadRight(pad), optionalHeader.NumberOfRvaAndSizes);
        Console.WriteLine();

        int longestName = 0;
        foreach (DirectoryEntry entry in optionalHeader.DataDirectories.Keys)
            if (Program.s_dataDirectories[entry].Length > longestName)
                longestName = Program.s_dataDirectories[entry].Length;

        Console.Write("Name".PadRight(longestName + 3));
        Console.WriteLine("{0,-11}{1}\n", "RVA", "Size");

        foreach ((DirectoryEntry entry, DataDirectory directory) in optionalHeader.DataDirectories) {
            Console.Write(string.Format("{0}", Program.s_dataDirectories[entry]).PadRight(longestName + 3));
            Console.WriteLine("{0,-11:X8}{1:X8}", directory.VirtualAddress, directory.Size);
        }

        Console.WriteLine();

    }

    private static Dictionary<SectionCharacteristics, string> s_sectionCharacteristics = new Dictionary<SectionCharacteristics, string>() {

        { SectionCharacteristics.TypeNoPad, "The section should not be padded to the next boundary." },
        { SectionCharacteristics.CntCode, "The section contains executable code." },
        { SectionCharacteristics.CntInitializedData, "The section contains initialized data." },
        { SectionCharacteristics.CntUninitializedData, "The section contains uninitialized data." },
        { SectionCharacteristics.LnkInfo, "The section contains comments or other information." },
        { SectionCharacteristics.LnkRemove, "The section will not become part of the image." },
        { SectionCharacteristics.LnkComdat, "The section contains COMDAT data." },
        { SectionCharacteristics.NoDeferSpecExec, "Reset speculative exceptions handling bits in the TLB entries for this section." },
        { SectionCharacteristics.GpRel, "The section contains data referenced through the global pointer" },

        { SectionCharacteristics.Align1Bytes, "Align data on a 1-byte boundary." },
        { SectionCharacteristics.Align2Bytes, "Align data on a 2-byte boundary." },
        { SectionCharacteristics.Align4Bytes, "Align data on a 4-byte boundary." },
        { SectionCharacteristics.Align8Bytes, "Align data on a 8-byte boundary." },
        { SectionCharacteristics.Align16Bytes, "Align data on a 16-byte boundary." },
        { SectionCharacteristics.Align32Bytes, "Align data on a 32-byte boundary." },
        { SectionCharacteristics.Align64Bytes, "Align data on a 64-byte boundary." },
        { SectionCharacteristics.Align128Bytes, "Align data on a 128-byte boundary." },
        { SectionCharacteristics.Align256Bytes, "Align data on a 256-byte boundary." },
        { SectionCharacteristics.Align512Bytes, "Align data on a 512-byte boundary." },
        { SectionCharacteristics.Align1024Bytes, "Align data on a 1024-byte boundary." },
        { SectionCharacteristics.Align2048Bytes, "Align data on a 2048-byte boundary." },
        { SectionCharacteristics.Align4096Bytes, "Align data on a 4096-byte boundary." },
        { SectionCharacteristics.Align8192Bytes, "Align data on a 8192-byte boundary." },

        { SectionCharacteristics.LnkNrelocOvfl, "The section contains extended relocations." },
        { SectionCharacteristics.MemDiscardable, "The section can be discarded as needed." },
        { SectionCharacteristics.MemNotCached, "The section cannot be cached." },
        { SectionCharacteristics.MemNotPaged, "The section is not pageable." },
        { SectionCharacteristics.MemShared, "The section can be shared in memory." },
        { SectionCharacteristics.MemExecute, "The section can be executed as code." },
        { SectionCharacteristics.MemRead, "The section can be read." },
        { SectionCharacteristics.MemWrite, "The section can be written to." },

    };

    private static void Inspect(SectionHeader[] sections) {

        Console.WriteLine("\tSection headers\n");
        
        foreach (SectionHeader section in sections) {

            Console.WriteLine("   {0,-34}{1}", "Name", section.Name);
            Console.WriteLine("   {0,-34}{1:X8}", "Physical address / virtual size", section.VirtualSize);
            Console.WriteLine("   {0,-34}{1:X8}", "Virtual address", section.VirtualAddress);
            Console.WriteLine("   {0,-34}{1:X8}", "Size of raw data", section.SizeOfRawData);
            Console.WriteLine("   {0,-34}{1:X8}", "Pointer to raw data", section.PointerToRawData);
            Console.WriteLine("   {0,-34}{1:X8}", "Pointer to relocations", section.PointerToRelocations);
            Console.WriteLine("   {0,-34}{1:X8}", "Pointer to linenumbers", section.PointerToLinenumbers);
            Console.WriteLine("   {0,-38}{1:X4}", "Number of relocations", section.NumberOfRelocations);
            Console.WriteLine("   {0,-38}{1:X4}", "Number of linenumbers", section.NumberOfLinenumbers);
            
            bool firstTime = true;
            Console.Write("   {0,-34}{1,-11:X8}", "Characteristics", (uint)(section.Characteristics));
            foreach (SectionCharacteristics flag in Enum.GetValues<SectionCharacteristics>()) {
                if ((section.Characteristics & flag) == 0) continue;
                if (!firstTime) Console.Write("\n{0}", string.Empty.PadRight(48));
                Console.Write("- {0,-11:X8}{1}", (uint)(flag), Program.s_sectionCharacteristics.GetValueOrDefault(flag, string.Empty));
                firstTime = false;
            }

            Console.WriteLine("\n");

        }

    }

    private static void Inspect(ExportDirectory exportDirectory) {

        Console.WriteLine("\tExport directory\n");

        Console.WriteLine("{0,-27}{1:X8}", "Characteristics", exportDirectory.Characteristics);
        Console.WriteLine("{0,-27}{1:X8}", "Time date stamp", exportDirectory.TimeDateStamp);
        Console.WriteLine("{0,-31}{1:X4}", "Major version", exportDirectory.MajorVersion);
        Console.WriteLine("{0,-31}{1:X4}", "Minor version", exportDirectory.MinorVersion);
        Console.WriteLine("{0,-27}{1,-11:X8}{2}", "Name", exportDirectory.Name.RVA, exportDirectory.Name.Name);
        Console.WriteLine("{0,-27}{1:X8}", "Base", exportDirectory.Base);
        Console.WriteLine("{0,-27}{1:X8}", "Number of functions", exportDirectory.NumberOfFunctions);
        Console.WriteLine("{0,-27}{1:X8}", "Number of names", exportDirectory.NumberOfNames);
        Console.WriteLine("{0,-27}{1:X8}", "Address of functions", exportDirectory.AddressOfFunctions);
        Console.WriteLine("{0,-27}{1:X8}", "Address of names", exportDirectory.AddressOfNames);
        Console.WriteLine("{0,-27}{1:X8}", "Address of name ordinals", exportDirectory.AddressOfNameOrdinals);
        Console.WriteLine();

        if (exportDirectory.Exports == null) return;

        int longestName = 0;
        foreach (ExportedFunction export in exportDirectory.Exports.Values)
            if (export.Name.HasValue && export.Name.Value.Name.Length > longestName)
                longestName = export.Name.Value.Name.Length;

        Console.Write("   Ord.   Fn. RVA    Hint   Name");
        Console.Write("Forwarder".PadLeft(longestName + 19));
        Console.WriteLine("\n");

        foreach ((ushort ordinal, ExportedFunction export) in exportDirectory.Exports) {

            Console.Write("   {0,-7:X4}{1,-11:X8}", ordinal, export.FunctionRVA);
            Console.Write("{0,-7:X4}", (export.Hint.HasValue ? export.Hint : string.Empty));
            Console.Write("{0,-11:X8}", (export.Name.HasValue ? export.Name.Value.RVA : string.Empty));
            Console.Write("{0}", (export.Name.HasValue ? export.Name.Value.Name : string.Empty).PadRight(longestName + 3));
            Console.Write("{0}", export.Forwarder ?? string.Empty);
            Console.WriteLine();

        }

        Console.WriteLine();

    }

    private static void Inspect(ImportDirectory importDirectory) {

        Console.WriteLine("\tImport directory\n");
        
        if (importDirectory.Imports == null) return;

        foreach ((string _, ImportedLibrary import) in importDirectory.Imports) {

            Console.WriteLine("   {0,-41}{1:X8}", "Characteristics / Original first thunk", import.Characteristics);
            Console.WriteLine("   {0,-41}{1:X8}", "Time date stamp", import.TimeDateStamp);
            Console.WriteLine("   {0,-41}{1:X8}", "Forwarder chain", import.ForwarderChain);
            Console.WriteLine("   {0,-41}{1,-11:X8}{2}", "Name", import.Name.RVA, import.Name.Name ?? string.Empty);
            Console.WriteLine("   {0,-41}{1:X8}", "First thunk", import.FirstThunk);
            Console.WriteLine();

            if (import.Imports == null) continue;

            Console.WriteLine("      Ord.   Hint   Name\n");

            foreach (ImportedFunction fn in import.Imports) {

                Console.Write("      {0,-7:X4}", fn.Ordinal.HasValue ? fn.Ordinal.Value : string.Empty);
                Console.Write("{0,-7:X4}", fn.Hint.HasValue ? fn.Hint.Value : string.Empty);
                Console.WriteLine(fn.Name ?? string.Empty);

            }

            Console.WriteLine();

        }

    }

    private static void Inspect(ResourceDirectory resourceDirectory) {

        Console.WriteLine("\tResource directory\n");

        Console.WriteLine("{0,-26}{1:X8}", "Characteristics", resourceDirectory.Characteristics);
        Console.WriteLine("{0,-26}{1:X8}", "Time date stamp", resourceDirectory.TimeDateStamp);
        Console.WriteLine("{0,-30}{1:X4}", "Major version", resourceDirectory.MajorVersion);
        Console.WriteLine("{0,-30}{1:X4}", "Minor version", resourceDirectory.MinorVersion);
        Console.WriteLine("{0,-26}{1:X8}", "Number of named entries", resourceDirectory.NumberOfNamedEntries);
        Console.WriteLine("{0,-26}{1:X8}", "Number of ID entries", resourceDirectory.NumberOfIdEntries);
        Console.WriteLine();

    }

    private static Dictionary<ResourceId, string> s_resourceTypes = new Dictionary<ResourceId, string>() {

        { ResourceType.Cursor, "RT_CURSOR" },
        { ResourceType.Bitmap, "RT_BITMAP" },
        { ResourceType.Icon, "RT_ICON" },
        { ResourceType.Menu, "RT_MENU" },
        { ResourceType.Dialog, "RT_DIALOG" },
        { ResourceType.String, "RT_STRING" },
        { ResourceType.FontDir, "RT_FONTDIR" },
        { ResourceType.Font, "RT_FONT" },
        { ResourceType.Accelerator, "RT_ACCELERATOR" },
        { ResourceType.RcData, "RT_RCDATA" },
        { ResourceType.MessageTable, "RT_MESSAGETABLE" },
        { ResourceType.GroupCursor, "RT_GROUP_CURSOR" },
        { ResourceType.GroupIcon, "RT_GROUP_ICON" },
        { ResourceType.Version, "RT_VERSION" },
        { ResourceType.DlgInclude, "RT_DLGINCLUDE" },
        { ResourceType.PlugPlay, "RT_PLUGPLAY" },
        { ResourceType.Vxd, "RT_VXD" },
        { ResourceType.AniCursor, "RT_ANICURSOR" },
        { ResourceType.AniIcon, "RT_ANIICON" },
        { ResourceType.Html, "RT_HTML" },
        { ResourceType.Manifest, "RT_MANIFEST" },

    };

    // horrible.
    private static void InspectResourceDirectoryTree(PortableExecutable pe) {
        
        ResourceId[]? types = pe.GetResourceTypes();
        if (types == null) return;

        Console.WriteLine("   Root");

        for (int i = 0; i < types.Length; ++i) {

            if (i == (types.Length - 1)) Console.Write("   └── ");
            else Console.Write("   ├── ");

            ResourceId type = types[i];
            string str = Program.s_resourceTypes.GetValueOrDefault(
                type, 
                (type.NumericalId.HasValue ? string.Format("{0:X4}", type.NumericalId.Value) : string.Format("\"{0}\"", type))
            );

            Console.WriteLine("{0}", str);

            ResourceId[]? ids = pe.GetResourceIds(types[i]);
            if (ids == null) continue;

            for (int j = 0; j < ids.Length; ++j) {

                if (j == (ids.Length - 1)) {
                    if (i == (types.Length - 1)) Console.Write("       └── ");
                    else Console.Write("   │   └── ");
                }
                else if (i == (types.Length - 1)) Console.Write("       ├── ");
                else Console.Write("   │   ├── ");

                ResourceId id = ids[j];
                str = (id.NumericalId.HasValue ? string.Format("{0:X4}", id.NumericalId.Value) : string.Format("\"{0}\"", id));
                Console.WriteLine("{0}", str);

                ushort[]? languages = pe.GetResourceLanguages(ids[j], types[i]);
                if (languages == null) continue;

                for (int k = 0; k < languages.Length; ++k) {

                    if (k == (languages.Length - 1)) {
                        if (i == (types.Length - 1)) {
                            if (j != (ids.Length - 1)) Console.Write("       │   └── ");
                            else Console.Write("           └── ");
                        }
                        else if (j == (ids.Length - 1)) Console.Write("   │       └── ");
                        else Console.Write("   │   │   └── ");
                    }
                    else if (i == (types.Length - 1)) Console.Write("           ├── ");
                    else if (j == (ids.Length - 1)) Console.Write("   |       ├── ");
                    else Console.Write("   │   │   ├── ");

                    Console.WriteLine("{0:X4}", languages[k]);

                }

            }

        }

    }

    private static void Inspect(DebugDirectory debug) {

        Console.WriteLine("\tDebug directory\n");

        if (debug.Entries == null) return;

        foreach (DebugDirectoryEntry entry in debug.Entries) {

            Console.WriteLine("   {0,-22}{1:X8}", "Characteristics", entry.Characteristics);
            Console.WriteLine("   {0,-22}{1:X8}", "Time date stamp", entry.TimeDateStamp);
            Console.WriteLine("   {0,-26}{1:X4}", "Major version", entry.MajorVersion);
            Console.WriteLine("   {0,-26}{1:X4}", "Minor version", entry.MinorVersion);
            Console.WriteLine("   {0,-22}{1:X8}", "Type", (int)(entry.Type));
            Console.WriteLine("   {0,-22}{1:X8}", "Size of data", entry.SizeOfData);
            Console.WriteLine("   {0,-22}{1:X8}", "Address of raw data", entry.AddressOfRawData);
            Console.WriteLine("   {0,-22}{1:X8}", "Pointer to raw data", entry.PointerToRawData);
            Console.WriteLine();

        }

        Console.WriteLine();

    }

    private static void Inspect(DelayImportDirectory delayImportDirectory) {

        Console.WriteLine("\tDelay load import directory\n");

        if (delayImportDirectory.Imports == null) return;

        foreach ((string _, DelayImportedLibrary import) in delayImportDirectory.Imports) {

            Console.WriteLine("   {0,-29}{1:X8}", "Attributes", import.AllAttributes);
            Console.WriteLine("   {0,-29}{1,-11:X8}{2}", "DLL name", import.DllName.RVA, import.DllName.Name);
            Console.WriteLine("   {0,-29}{1:X8}", "Module handle", import.ModuleHandleRVA);
            Console.WriteLine("   {0,-29}{1:X8}", "Import address table", import.ImportAddressTableRVA);
            Console.WriteLine("   {0,-29}{1:X8}", "Import name table", import.ImportNameTableRVA);
            Console.WriteLine("   {0,-29}{1:X8}", "Bound import address table", import.BoundImportAddressTableRVA);
            Console.WriteLine("   {0,-29}{1:X8}", "Unload information table", import.UnloadInformationTableRVA);
            Console.WriteLine("   {0,-29}{1:X8}", "Time date stamp", import.TimeDateStamp);
            Console.WriteLine();

            if (import.Imports == null) continue;

            Console.WriteLine("      Ord.   Hint   Name\n");

            foreach (ImportedFunction fn in import.Imports) {

                Console.Write("      {0,-7:X4}", fn.Ordinal.HasValue ? fn.Ordinal.Value : string.Empty);
                Console.Write("{0,-7:X4}", fn.Hint.HasValue ? fn.Hint.Value : string.Empty);
                Console.WriteLine(fn.Name ?? string.Empty);

            }

            Console.WriteLine();

        }

    }

}