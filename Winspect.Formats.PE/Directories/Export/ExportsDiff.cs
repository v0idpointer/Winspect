/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System.Collections.Generic;
using Winspect.Common;

namespace Winspect.Formats.PE.Directories.Export;

/// <summary>
/// Represents a comparison of export symbols from two PE files.
/// </summary>
public class ExportsDiff {

    public Dictionary<ExportName, DiffStatus> Changes { get; private set; }

    public bool HasChanges {
        
        get {

            foreach ((ExportName _, DiffStatus status) in this.Changes)
                if (status != DiffStatus.Unchanged) 
                    return true;

            return false;
        }

    }

    public ExportsDiff(ExportDirectory? a, ExportDirectory? b) {

        this.Changes = new Dictionary<ExportName, DiffStatus>();

        if ((a != null) && (a.Exports != null)) {
            foreach ((ushort _, ExportedFunction export) in a.Exports) {
                
                ExportName name = ExportName.GetExportName(export);
                this.Changes.Add(name, DiffStatus.Removed);

            }
        }

        if ((b != null) && (b.Exports != null)) {
            foreach ((ushort _, ExportedFunction export) in b.Exports) {
                
                ExportName name = ExportName.GetExportName(export);
                if (this.Changes.ContainsKey(name)) this.Changes[name] = DiffStatus.Unchanged;
                else this.Changes.Add(name, DiffStatus.Added);

            }
        }

    }

}