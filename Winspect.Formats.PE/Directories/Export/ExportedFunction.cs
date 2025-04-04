/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Directories.Export;

public class ExportedFunction {

    public ushort Ordinal { get; private set; }
    public uint FunctionRVA { get; private set; }
    public (uint RVA, string Name)? Name { get; private set; }
    public ushort? Hint { get; private set; }
    public string? Forwarder { get; private set; }

    public ExportedFunction(ushort ordinal, uint rva, (uint RVA, string Name)? name, ushort? hint, string? forwarder) {
        this.Ordinal = ordinal;
        this.FunctionRVA = rva;
        this.Name = name;
        this.Hint = hint;
        this.Forwarder = forwarder;
    }

}