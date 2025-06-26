/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System.Collections.Generic;
using System.Linq;
using Winspect.Common;
using Winspect.Formats.PE.Directories.DelayImport;
using Winspect.Formats.PE.Directories.Export;

namespace Winspect.Formats.PE.Directories.Import;

public class ImportsDiff {

    public Dictionary<(string Library, ExportName Name), DiffStatus> Changes { get; private set; }

    public bool HasChanges {

        get {

            foreach (((string Library, ExportName Name) _, DiffStatus status) in this.Changes)
                if (status != DiffStatus.Unchanged)
                    return true;

            return false;
        }

    }

    public ImportsDiff(ImportDirectory? a, ImportDirectory? b) {
        
        this.Changes = new Dictionary<(string Library, ExportName Name), DiffStatus>();

        if ((a != null) && (a.Imports != null)) {
            foreach ((string libName, ImportedLibrary library) in a.Imports) {

                if (library.Imports == null) continue; // this should never probably happen.
                foreach (ImportedFunction import in library.Imports) {
                    
                    ExportName name = ExportName.GetExportName(import);
                    this.Changes.Add((libName, name), DiffStatus.Removed);

                }

            }
        }

        if ((b != null) && (b.Imports != null)) {
            foreach ((string libName, ImportedLibrary library) in b.Imports) {

                if (library.Imports == null) continue;
                foreach (ImportedFunction import in library.Imports) {
                    
                    ExportName name = ExportName.GetExportName(import);
                    if (this.Changes.ContainsKey((libName, name))) 
                        this.Changes[(libName, name)] = DiffStatus.Unchanged;
                    else this.Changes.Add((libName, name), DiffStatus.Added);
                    
                }

            }
        }

    }

    public ImportsDiff(DelayImportDirectory? a, DelayImportDirectory? b) {
        
        this.Changes = new Dictionary<(string Library, ExportName Name), DiffStatus>();

        if ((a != null) && (a.Imports != null)) {
            foreach ((string libName, DelayImportedLibrary library) in a.Imports) {

                if (library.Imports == null) continue;
                foreach (ImportedFunction import in library.Imports) {
                    
                    ExportName name = ExportName.GetExportName(import);
                    this.Changes.Add((libName, name), DiffStatus.Removed);

                }

            }
        }

        if ((b != null) && (b.Imports != null)) {
            foreach ((string libName, DelayImportedLibrary library) in b.Imports) {

                if (library.Imports == null) continue;
                foreach (ImportedFunction import in library.Imports) {
                    
                    ExportName name = ExportName.GetExportName(import);
                    if (this.Changes.ContainsKey((libName, name))) 
                        this.Changes[(libName, name)] = DiffStatus.Unchanged;
                    else this.Changes.Add((libName, name), DiffStatus.Added);
                    
                }

            }
        }

    }

    public Dictionary<string, DiffStatus> GetLibraries() {
        
        Dictionary<string, DiffStatus> libraries = new Dictionary<string, DiffStatus>();

        foreach (string library in this.Changes.Keys.Select(x => x.Library).Distinct()) {
            
            IEnumerable<DiffStatus> values = this.Changes.Where(x => (x.Key.Library == library)).Select(x => x.Value);
            DiffStatus status = DiffStatus.Modified;

            if (values.All(x => (x == DiffStatus.Unchanged)))
                status = DiffStatus.Unchanged;
            else if (values.All(x => (x == DiffStatus.Added)))
                status = DiffStatus.Added;
            else if (values.All(x => (x == DiffStatus.Removed)))
                status = DiffStatus.Removed;

            libraries.Add(library, status);

        }

        return libraries;
    }

    public Dictionary<ExportName, DiffStatus> GetImports(string library) {
    
        Dictionary<ExportName, DiffStatus> imports = new Dictionary<ExportName, DiffStatus>();

        foreach (ExportName import in this.Changes.Keys.Where(x => (x.Library == library)).Select(x => x.Name))
            imports.Add(import, this.Changes[(library, import)]);

        return imports;
    }

    public static ImportsDiff Diff((ImportDirectory? Imports, DelayImportDirectory? DelayLoad) old, (ImportDirectory? Imports, DelayImportDirectory? DelayLoad) @new) {
        
        ImportsDiff importsDiff = new ImportsDiff(old.Imports, @new.Imports);
        ImportsDiff delayLoadDiff = new ImportsDiff(old.DelayLoad, @new.DelayLoad);

        foreach ((string, ExportName) import in delayLoadDiff.Changes.Keys) {
            if (!importsDiff.Changes.ContainsKey(import)) importsDiff.Changes[import] = delayLoadDiff.Changes[import];
            else importsDiff.Changes[import] = DiffStatus.Modified;
        }

        return importsDiff;
    }

}