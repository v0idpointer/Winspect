/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Windows.Registry.Formats.Regf;

public class BadRegfFileException : Exception {

    public BadRegfFileException(string message)
        : base(message) { }

    public BadRegfFileException(string message, Exception innerException)
        : base(message, innerException) { }

}