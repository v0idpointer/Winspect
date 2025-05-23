/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

namespace Winspect.Common;

public interface IDiffable<TType, TDiffResult> {

    public static abstract TDiffResult Diff(TType? a, TType? b);

}