/*
    Windows Inspection Utilities
    Copyright (c) 2025 V0idPointer
*/

using System.Collections.Generic;

namespace Winspect.Windows.Registry;

/// <summary>
/// Represents a registry key.
/// </summary>
public class Key {
    
    public string Name { get; set; }
    public List<Key> Subkeys { get; private set; }

    public Key(string name) {
        this.Name = name;
        this.Subkeys = new List<Key>();
    }

}