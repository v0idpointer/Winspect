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
using Winspect.Common;
using Winspect.Formats.PE;
using Winspect.Formats.PE.Directories.Export;
using Winspect.Formats.PE.Directories.Import;
using Winspect.Formats.PE.Directories.Resource;

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
        rootCommand.AddOption(new Option<bool>("--imports", "Compares the imported symbols between the two PE files"));
        rootCommand.AddOption(new Option<bool>("--resources", "Compares the embedded resources between the two PE files"));
        rootCommand.AddOption(new Option<bool>("--nologo", "Suppress the startup logo"));
        rootCommand.Handler = CommandHandler.Create(Program.Handler);

        if (args.Length == 0) args = new string[] { "-?" };
        return rootCommand.Invoke(args);
    }

    private static int Handler(FileInfo old, FileInfo @new, bool exports, bool imports, bool resources) {

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

        if (imports)
            Program.DiffImports(oldPe.ImportDirectory, newPe.ImportDirectory);

        if (resources)
            Program.DiffResources(oldPe.ResourceDirectory, newPe.ResourceDirectory);

        if (!exports && !imports && !resources) {
            Console.WriteLine("No options provided. A diff summary should be shown here.");
            // TODO: implement.
        }

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

    private static void DiffImports(ImportDirectory? old, ImportDirectory? @new) {

        Console.WriteLine("\tImports diff\n");

        ImportsDiff diff = ImportDirectory.Diff(old, @new);
        if (!diff.HasChanges) Console.WriteLine("   No changes.");
        else {

            Dictionary<string, DiffStatus> libraries = diff.GetLibraries();
            foreach ((string library, DiffStatus status) in libraries) {

                if (status == DiffStatus.Unchanged) continue;

                char symbol = status switch {
                    DiffStatus.Added => '+',
                    DiffStatus.Removed => '-',
                    DiffStatus.Modified => '*',
                    _ => ' ',
                };

                Console.WriteLine("   {0,-4}{1}", symbol, library);
                Console.WriteLine("\n      S   Ord.   Name\n");

                IEnumerable<ExportName> imports = diff.Changes.Keys.Where(x => (x.Library == library)).Select(x => x.Name);
                foreach (ExportName import in imports) {

                    DiffStatus s = diff.Changes[(library, import)];
                    if (s == DiffStatus.Unchanged) continue;

                    symbol = s switch {
                        DiffStatus.Added => '+',
                        DiffStatus.Removed => '-',
                        _ => ' ',
                    };

                    Console.WriteLine("      {0,-4}{1,-7:X4}{2}", symbol, import.Ordinal, import.Name);

                }

                if (libraries.Last().Key != library)
                    Console.WriteLine();

            }

        }

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

    private static void DiffResources(ResourceDirectory? old, ResourceDirectory? @new) {

        Console.WriteLine("\tResources diff\n");

        ResourcesDiff diff = ResourceDirectory.Diff(old, @new);
        if (!diff.HasChanges) Console.WriteLine("   No changes.");
        else {
            
            // this is just a modified InspectResourceDirectoryTree from PEInspect.
            // it still sucks and i hate it

            Console.WriteLine("   Root");

            Dictionary<ResourceId, DiffStatus> types = diff.GetResourceTypes();
            int typesCount = types.Values.Where(x => (x != DiffStatus.Unchanged)).Count();

            foreach ((ResourceId type, DiffStatus typeStatus) in types) {
                
                if (typeStatus == DiffStatus.Unchanged) continue;
                --typesCount;
                
                if (typesCount == 0) Console.Write("   └── ");
                else Console.Write("   ├── ");

                string str = Program.s_resourceTypes.GetValueOrDefault(
                    type,
                    (type.NumericalId.HasValue ? string.Format("{0:X4}", type.NumericalId.Value) : string.Format("\"{0}\"", type))
                );

                char symbol = typeStatus switch {
                    DiffStatus.Added => '+',
                    DiffStatus.Removed => '-',
                    DiffStatus.Modified => '*',
                    _ => ' ',
                };

                Console.WriteLine("{0} {1}", symbol, str);

                Dictionary<ResourceId, DiffStatus> ids = diff.GetResourceIds(type);
                int idsCount = ids.Values.Where(x => (x != DiffStatus.Unchanged)).Count();

                foreach ((ResourceId id, DiffStatus idStatus) in ids) {

                    if (idStatus == DiffStatus.Unchanged) continue;
                    --idsCount;

                    if (idsCount == 0) {
                        if (typesCount == 0) Console.Write("       └── ");
                        else Console.Write("   │   └── ");
                    }
                    else if (typesCount == 0) Console.Write("       ├── ");
                    else Console.Write("   │   ├── ");

                    str = (id.NumericalId.HasValue ? string.Format("{0:X4}", id.NumericalId.Value) : string.Format("\"{0}\"", id));
                    symbol = typeStatus switch {
                        DiffStatus.Added => '+',
                        DiffStatus.Removed => '-',
                        DiffStatus.Modified => '*',
                        _ => ' ',
                    };

                    Console.WriteLine("{0} {1}", symbol, str);

                    Dictionary<ResourceId, DiffStatus> languages = diff.GetResourceLanguages(type, id);
                    int languagesCount = languages.Values.Where(x => (x != DiffStatus.Unchanged)).Count();

                    foreach ((ResourceId lang, DiffStatus langStatus) in languages) {

                        if (langStatus == DiffStatus.Unchanged) continue;
                        --languagesCount;

                        if (languagesCount == 0) {
                            if (typesCount == 0) {
                                if (idsCount != 0) Console.Write("       │   └── ");
                                else Console.Write("           └── ");
                            }
                            else if (idsCount == 0) Console.Write("   │       └── ");
                            else Console.Write("   │   │   └── ");
                        }
                        else if (typesCount == 0) Console.Write("           ├── ");
                        else if (idsCount == 0) Console.Write("   |       ├── ");
                        else Console.Write("   │   │   ├── ");

                        symbol = typeStatus switch {
                            DiffStatus.Added => '+',
                            DiffStatus.Removed => '-',
                            DiffStatus.Modified => '*',
                            _ => ' ',
                        };

                        Console.WriteLine("{0} {1:X4}", symbol, lang.NumericalId);

                    }

                }

            }

        }

        Console.WriteLine();

    }

}