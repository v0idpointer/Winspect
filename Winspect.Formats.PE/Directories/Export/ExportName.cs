/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using Winspect.Formats.PE.Directories.Import;

namespace Winspect.Formats.PE.Directories.Export;

public struct ExportName {

    public string? Name { get; private set; }
    public ushort? Ordinal { get; private set; }

    public ExportName(string name) {
        this.Name = name;
        this.Ordinal = null;
    }

    public ExportName(ushort ordinal) {
        this.Name = null;
        this.Ordinal = ordinal;
    }

    public override int GetHashCode() {
        return HashCode.Combine(this.Name, this.Ordinal);
    }

    public override bool Equals(object? obj) {

        if (obj == null) return false;
        if (obj is not ExportName name) return false;

        return ((this.Name == name.Name) && (this.Ordinal == name.Ordinal));
    }

    public static implicit operator ExportName(string name) => new ExportName(name);
    public static implicit operator ExportName(ushort ordinal) => new ExportName(ordinal);

    public static ExportName GetExportName(ExportedFunction export) {
        if (export.Name.HasValue) return export.Name.Value.Name;
        else return export.Ordinal;
    }

    public static ExportName GetExportName(ImportedFunction import) {
        if (import.Name != null) return import.Name;
        else if (import.Ordinal.HasValue) return import.Ordinal.Value;
        else throw new ArgumentException("Bad import.", nameof(import));
    }

}