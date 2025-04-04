/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System.IO;
using System.Text;

namespace Winspect.Formats.PE;

internal static class StreamHelper {

    public static string ReadString(Stream stream, Encoding encoding, int? length) {
        
        using (BinaryReader reader = new BinaryReader(stream, encoding, leaveOpen: true)) {

            if (length.HasValue)
                return new string(reader.ReadChars(length.Value));

            StringBuilder builder = new StringBuilder();

            char ch;
            while ((ch = reader.ReadChar()) != '\0')
                builder.Append(ch);

            return builder.ToString();
        }

    }

}