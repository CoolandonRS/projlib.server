using System.Data;
using System.Text.Json.Serialization;

namespace CoolandonRS.projlib.server.generics; 

public class ProjectDetails {
    [JsonInclude] private string ver;
    [JsonInclude] private string author;
    [JsonInclude] private string desc;
    [JsonInclude] private string[] supportedPlatforms;
    public bool Mutable { get; private set; }
    public string Ver {
        get => ver;
        set => Mutate(ref ver, value);
    }
    public string Author {
        get => author;
        set => Mutate(ref author, value);
    }
    public string Desc {
        get => desc;
        set => Mutate(ref desc, value);
    }
    public string[] SupportedPlatforms {
        get => supportedPlatforms;
        set => Mutate(ref supportedPlatforms, value);
    }

    private void Mutate<T>(ref T var, T val) {
        if (!Mutable) throw new ReadOnlyException();
        var = val;
    }

    public void MakeImmutable() => Mutable = false;

    public ProjectDetails(string ver, string author, string desc, string[] supportedPlatforms, bool mutable = false) {
        Mutable = mutable;
        this.ver = ver;
        this.author = author;
        this.desc = desc;
        this.supportedPlatforms = supportedPlatforms;
    }

    /// <summary>
    /// Clones a ProjectDetails, optionally making it mutable
    /// </summary>
    /// <param name="details"></param>
    /// <param name="mutable"></param>
    public ProjectDetails(ProjectDetails details, bool mutable = false) {
        Mutable = mutable;
        ver = details.ver;
        author = details.author;
        desc = details.desc;
        supportedPlatforms = details.supportedPlatforms;
    }
}