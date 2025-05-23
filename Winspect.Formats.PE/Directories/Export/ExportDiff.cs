/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System.Collections.Generic;
using Winspect.Common;

namespace Winspect.Formats.PE.Directories.Export;

public class ExportDiff {

    private class MyEqualityComparer : IEqualityComparer<ExportName> {

        public bool Equals(ExportName x, ExportName y) {
            return (x.Equals(y));
        }

        public int GetHashCode(ExportName obj) {
            return obj.GetHashCode();
        }

    }

    public Dictionary<ExportName, DiffStatus> Changes { get; private set; }

    public ExportDiff(ExportDirectory? a, ExportDirectory? b) {

        this.Changes = new Dictionary<ExportName, DiffStatus>(new MyEqualityComparer());

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