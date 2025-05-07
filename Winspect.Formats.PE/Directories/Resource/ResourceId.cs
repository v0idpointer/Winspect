/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;

namespace Winspect.Formats.PE.Directories.Resource;

/// <summary>
/// Represents either a 16-bit numerical or a string resource identifier.
/// </summary>
public struct ResourceId {

    public ushort? NumericalId { get; private set; }
    public string? StringId { get; private set; }

    public ResourceId(ushort numericalId) {
        this.NumericalId = numericalId;
        this.StringId = null;
    }

    public ResourceId(string stringId) {
        this.NumericalId = null;
        this.StringId = stringId;
    }

    public override string ToString() {
        if (this.NumericalId.HasValue) return this.NumericalId.Value.ToString();
        else if (this.StringId != null) return this.StringId;
        else return string.Empty;
    }

    public override int GetHashCode() {
        return HashCode.Combine(this.NumericalId, this.StringId);
    }

    public override bool Equals(object? obj) {
        
        if (obj == null) return false;
        if (obj is not ResourceId id) return false;
        
        return ((this.NumericalId == id.NumericalId) && (this.StringId == id.StringId));
    }

    public static implicit operator ResourceId(ushort numericalId) => new ResourceId(numericalId);
    public static implicit operator ResourceId(string stringId) => new ResourceId(stringId);
    public static implicit operator ResourceId(ResourceType type) => new ResourceId((ushort)(type));

}