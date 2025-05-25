/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.IO;
using System.Linq;
using Winspect.Common;
using Winspect.Formats.PE;
using Winspect.Formats.PE.Directories.Export;

internal class Program {

    static int Main(string[] args) {

        if (!args.Contains("--nologo")) {
            Console.WriteLine("Portable Executable (PE) Comparison Utility");
            Console.WriteLine("Copyright (c) 2025 V0idPointer\r\n");
        }

        RootCommand rootCommand = new RootCommand();
        rootCommand.Name = "PEDiff";
        rootCommand.Description = "Compares the differences between two Portable Executable (PE) files.";
        rootCommand.AddArgument(new Argument<FileInfo>("old", "The previous version of the PE file"));
        rootCommand.AddArgument(new Argument<FileInfo>("new", "The updated version of the PE file"));
        rootCommand.AddOption(new Option<bool>("--exports", "Compares the exported symbols between the two PE files"));
        rootCommand.AddOption(new Option<bool>("--nologo", "Suppress the startup logo"));
        rootCommand.Handler = CommandHandler.Create(Program.Handler);

        if (args.Length == 0) args = new string[] { "-?" };
        return rootCommand.Invoke(args);
    }

    private static int Handler(FileInfo old, FileInfo @new, bool exports) {

        PortableExecutable oldPe;
        try { oldPe = new PortableExecutable(old.FullName); }
        catch (Exception ex) {
            Console.WriteLine("*** {0}", ex.Message);
            return 1;
        }

        PortableExecutable newPe;
        try { newPe = new PortableExecutable(@new.FullName); }
        catch (Exception ex) {
            Console.WriteLine("*** {0}", ex.Message);
            return 2;
        }

        if (exports)
            Program.DiffExports(oldPe.ExportDirectory, newPe.ExportDirectory);

        return 0;
    }

    private static void DiffExports(ExportDirectory? old, ExportDirectory? @new) {

        Console.WriteLine("\tExports diff\n");

        ExportsDiff diff = ExportDirectory.Diff(old, @new);

        if (!diff.HasChanges) Console.WriteLine("   No changes.");
        else {

            Console.WriteLine("   S   Ord.   Name\n");
            foreach ((ExportName name, DiffStatus status) in diff.Changes) {

                if (status == DiffStatus.Unchanged) continue;

                char symbol = status switch {
                    DiffStatus.Added => '+',
                    DiffStatus.Removed => '-',
                    DiffStatus.Modified => '*',
                    _ => ' ',
                };

                Console.WriteLine("   {0,-4}{1,-7:X4}{2}", symbol, name.Ordinal, name.Name);

            }

        }

        Console.WriteLine();

    }

}