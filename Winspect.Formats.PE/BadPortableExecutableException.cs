/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Formats.PE;

public class BadPortableExecutableException : Exception {

    public BadPortableExecutableException(string message)
        : base(message) { }

    public BadPortableExecutableException(string message, Exception innerException)
        : base(message, innerException) { }

}