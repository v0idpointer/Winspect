/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Directories.Import;

public class ImportedFunction {

    public ushort? Ordinal { get; private set; }
    public string? Name { get; private set; }
    public ushort? Hint { get; private set; }

    public ImportedFunction(ushort? ordinal, string? name, ushort? hint) {
        this.Ordinal = ordinal;
        this.Name = name;
        this.Hint = hint;
    }

}