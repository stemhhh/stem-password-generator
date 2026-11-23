using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class PayloadFingerprintTests
{
    [Fact]
    public void SameTree_ProducesTheSameStamp()
    {
        var root = CreateTree("same");
        try
        {
            var first = PayloadFingerprint.FromDirectories("1.9.9", root);
            var second = PayloadFingerprint.FromDirectories("1.9.9", root);
            Assert.Equal(first, second);
            Assert.False(string.IsNullOrWhiteSpace(first));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void VersionOrFileChange_ChangesTheStamp()
    {
        var root = CreateTree("change");
        try
        {
            var baseline = PayloadFingerprint.FromDirectories("1.9.9", root);
            Assert.NotEqual(baseline, PayloadFingerprint.FromDirectories("1.9.10", root));
            File.WriteAllText(Path.Combine(root, "extra.txt"), "payload");
            Assert.NotEqual(baseline, PayloadFingerprint.FromDirectories("1.9.9", root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Matches_OnlyWhenStampFileEqualsFingerprint()
    {
        var folder = Path.Combine(Path.GetTempPath(), "stem-stamp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var stampPath = Path.Combine(folder, PayloadFingerprint.FileName);
        try
        {
            Assert.False(PayloadFingerprint.Matches(stampPath, "ABC"));
            PayloadFingerprint.Write(stampPath, "ABC");
            Assert.True(PayloadFingerprint.Matches(stampPath, "ABC"));
            Assert.False(PayloadFingerprint.Matches(stampPath, "ABD"));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    private static string CreateTree(string tag)
    {
        var root = Path.Combine(Path.GetTempPath(), "stem-payload-" + tag + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "nested"));
        File.WriteAllText(Path.Combine(root, "manifest.json"), "{\"name\":\"stem\"}");
        File.WriteAllText(Path.Combine(root, "nested", "host.txt"), "native");
        return root;
    }
}
