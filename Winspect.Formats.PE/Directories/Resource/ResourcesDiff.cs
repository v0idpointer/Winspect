/*
    Winspect (Windows Inspect)
    Copyright (c) 2025 V0idPointer
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Winspect.Common;

namespace Winspect.Formats.PE.Directories.Resource;

public class ResourcesDiff {

    public Dictionary<(ResourceId Type, ResourceId Id, ResourceId Lang), DiffStatus> Changes { get; private set; }

    public bool HasChanges {

        get {

            foreach (DiffStatus status in this.Changes.Values)
                if (status != DiffStatus.Unchanged)
                    return true;

            return false;
        }

    }

    public ResourcesDiff(ResourceDirectory? a, ResourceDirectory? b) {

        if ((a != null) && (a.Parent != null))
            throw new ArgumentException("The specified resource directory is not the root directory.", nameof(a));

        if ((b != null) && (b.Parent != null))
            throw new ArgumentException("The specified resource directory is not the root directory.", nameof(b));

        Dictionary<(ResourceId Type, ResourceId Id, ResourceId Lang), string> hashes;

        this.Changes = new Dictionary<(ResourceId Type, ResourceId Id, ResourceId Lang), DiffStatus>();
        hashes = new Dictionary<(ResourceId Type, ResourceId Id, ResourceId Lang), string>();

        if ((a != null) && (a.Entries != null)) {
            
            foreach ((ResourceId type, ResourceDirectoryEntry typeEntry) in a.Entries) {

                if ((typeEntry.Directory == null) || (typeEntry.Directory.Entries == null)) continue;
                foreach ((ResourceId id, ResourceDirectoryEntry idEntry) in typeEntry.Directory.Entries) {

                    if ((idEntry.Directory == null) || (idEntry.Directory.Entries == null)) continue;
                    foreach ((ResourceId lang, ResourceDirectoryEntry langEntry) in idEntry.Directory.Entries) {

                        if (langEntry.DataEntry == null) continue;
                        ResourceDataEntry resource = langEntry.DataEntry;

                        (ResourceId, ResourceId, ResourceId) key = (type, id, lang);

                        this.Changes.Add(key, DiffStatus.Removed);
                        hashes.Add(key, this.GetResourceHash(resource));

                    }

                }

            }

        }

        if ((b != null) && (b.Entries != null)) {
            
            foreach ((ResourceId type, ResourceDirectoryEntry typeEntry) in b.Entries) {

                if ((typeEntry.Directory == null) || (typeEntry.Directory.Entries == null)) continue;
                foreach ((ResourceId id, ResourceDirectoryEntry idEntry) in typeEntry.Directory.Entries) {

                    if ((idEntry.Directory == null) || (idEntry.Directory.Entries == null)) continue;
                    foreach ((ResourceId lang, ResourceDirectoryEntry langEntry) in idEntry.Directory.Entries) {

                        if (langEntry.DataEntry == null) continue;
                        ResourceDataEntry resource = langEntry.DataEntry;

                        (ResourceId, ResourceId, ResourceId) key = (type, id, lang);

                        if (!this.Changes.ContainsKey(key)) this.Changes.Add(key, DiffStatus.Added);
                        else {

                            string hash = this.GetResourceHash(resource);
                            if (hash == hashes[key]) this.Changes[key] = DiffStatus.Unchanged;
                            else this.Changes[key] = DiffStatus.Modified;

                        }

                    }

                }

            }

        }

    }

    private string GetResourceHash(ResourceDataEntry resource) {

        ReadOnlySpan<byte> data;
        try { data = resource.ReadData(); }
        catch (InvalidOperationException) {
            return string.Empty;
        }

        byte[] hash = SHA256.HashData(data);

        return BitConverter.ToString(hash).Replace("-", string.Empty);
    }

    public Dictionary<ResourceId, DiffStatus> GetResourceTypes() {

        Dictionary<ResourceId, DiffStatus> types = new Dictionary<ResourceId, DiffStatus>();

        foreach (ResourceId type in this.Changes.Keys.Select(x => x.Type).Distinct()) {

            IEnumerable<DiffStatus> values = this.Changes.Where(x => x.Key.Type.Equals(type)).Select(x => x.Value);
            DiffStatus status = DiffStatus.Modified;

            if (values.All(x => (x == DiffStatus.Unchanged)))
                status = DiffStatus.Unchanged;
            else if (values.All(x => (x == DiffStatus.Added)))
                status = DiffStatus.Added;
            else if (values.All(x => (x == DiffStatus.Removed)))
                status = DiffStatus.Removed;

            types.Add(type, status);

        }

        return types;
    }

    public Dictionary<ResourceId, DiffStatus> GetResourceIds(ResourceId type) {

        Dictionary<ResourceId, DiffStatus> ids = new Dictionary<ResourceId, DiffStatus>();

        foreach (ResourceId id in this.Changes.Keys.Where(x => x.Type.Equals(type)).Select(x => x.Id).Distinct()) {

            IEnumerable<DiffStatus> values = this.Changes.Where(x => (x.Key.Type.Equals(type) && x.Key.Id.Equals(id))).Select(x => x.Value);
            DiffStatus status = DiffStatus.Modified;

            if (values.All(x => (x == DiffStatus.Unchanged)))
                status = DiffStatus.Unchanged;
            else if (values.All(x => (x == DiffStatus.Added)))
                status = DiffStatus.Added;
            else if (values.All(x => (x == DiffStatus.Removed)))
                status = DiffStatus.Removed;

            ids.Add(id, status);

        }

        return ids;
    }

    public Dictionary<ResourceId, DiffStatus> GetResourceLanguages(ResourceId type, ResourceId id) {

        Dictionary<ResourceId, DiffStatus> languages = new Dictionary<ResourceId, DiffStatus>();

        foreach (ResourceId lang in this.Changes.Keys.Where(x => (x.Type.Equals(type) && x.Id.Equals(id))).Select(x => x.Lang).Distinct())
            languages.Add(lang, this.Changes[(type, id, lang)]);

        return languages;
    }

}