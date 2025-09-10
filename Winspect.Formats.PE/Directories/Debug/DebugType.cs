/*
   Windows Inspection Utilities
   Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Formats.PE.Directories.Debug;

public enum DebugType : uint {

    Unknown = 0,
    COFF = 1,
    CodeView = 2,
    FPO = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    OmapToSrc = 7,
    OmapFromSrc = 8,
    Borland = 9,
    Reserved10 = 10,
    BBT = Reserved10,
    Clsid = 11,
    VcFeature = 12,
    Pogo = 13,
    Iltcg = 14,
    Mpx = 15,
    Repro = 16,
    Spgo = 18,
    ExtendedDllCharacteristics = 20,

}