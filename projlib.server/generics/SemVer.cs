namespace CoolandonRS.projlib.server.generics;

/// <summary>
/// A container for a Semantic Version consisting of three numbers. <br/><br/>
/// <b>Major</b> - If a SemVer differs here, the versions are incompatible <br/>
/// <b>Minor</b> - If a SemVer differs here, the more recent version has new features <br/>
/// <b>Hotfix</b> - If a SemVer differs here, the more recent version has a miscellaneous improvement/bugfix
/// </summary>
public class SemVer {
    private readonly int[] nums;

    /// <summary>
    /// Used to indicate where two SemVers differ in <see cref="SemVer.CompareTo"/>
    /// </summary>
    public enum Difference {
        Major, Minor, Hotfix, None
    }

    public enum Comparison {
        Beta, Current, Outdated 
    }

    public override string ToString() {
        return string.Join('.', nums.Select(n => n.ToString()));
    }

    /// <summary>
    /// Compares two SemVers to see where they differ, and in which direction
    /// </summary>
    /// <param name="other">SemVer to compare to</param>
    /// <returns>Location of difference</returns>
    public (SemVer.Comparison comp, SemVer.Difference diff) CompareTo(SemVer other) {
        var tNums = this.nums;
        var oNums = other.nums;
        if (tNums[0] < oNums[0]) return (Comparison.Outdated, Difference.Major);
        if (tNums[0] > oNums[0]) return (Comparison.Beta, Difference.Major);
        if (tNums[1] < oNums[1]) return (Comparison.Outdated, Difference.Minor);
        if (tNums[1] > oNums[1]) return (Comparison.Beta, Difference.Minor);
        if (tNums[2] < oNums[2]) return (Comparison.Outdated, Difference.Hotfix);
        if (tNums[2] > oNums[2]) return (Comparison.Beta, Difference.Hotfix);
        return (Comparison.Current, Difference.None);
    }

    /// <summary>
    /// Checks if two SemVers are equal
    /// </summary>
    /// <param name="other">SemVer to compare to</param>
    /// <returns>If they are equal</returns>
    public bool IsEqualTo(SemVer other) {
        return this.nums == other.nums;
    }

    /// <summary>
    /// Checks if two SemVers are compatible
    /// </summary>
    /// <param name="other">SemVer to compare to</param>
    /// <returns>If they are compatible</returns>
    public bool IsCompatibleWith(SemVer other) {
        return this.nums[0] == other.nums[0];
    }

    public bool IsOutdatedComparedTo(SemVer other) {
        return this.CompareTo(other).comp == Comparison.Outdated;
    }

    public bool IsBetaComparedTo(SemVer other) {
        return this.CompareTo(other).comp == Comparison.Beta;
    }

    /// <summary>
    /// Long constructor for SemVer. <br/>
    /// For information on parameters, see <see cref="SemVer"/>
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if a number is negative</exception>
    public SemVer(int major, int minor, int hotfix) : this(new[] { major, minor, hotfix }) {
        
    }

    /// <summary>
    /// Constructs a SemVer out of a string
    /// </summary>
    /// <exception cref="FormatException">Thrown if a string is in an invalid format</exception>
    /// <exception cref="InvalidOperationException">Thrown if there are not exactly 3 positive integers</exception>
    public SemVer(string str) : this(str.Split(".").Select(int.Parse).ToArray()) {
        
    }

    /// <summary>
    /// Shorthand constructor for SemVer. <br/>
    /// For information on parameters, see <see cref="SemVer"/>
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if there are not exactly 3 positive integers</exception>
    public SemVer(int[] nums) {
        if (nums.Length != 3 || nums.All(n => n > 0)) throw new InvalidOperationException("Must consist of three positive integers");
        this.nums = nums;
    }
}