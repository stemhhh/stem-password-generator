using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class BrowserContainerRulesTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("0", "")]
    [InlineData("firefox-default", "")]
    [InlineData("firefox-private", "")]
    [InlineData("firefox-container-1", "firefox-container-1")]
    [InlineData("firefox-container-12", "firefox-container-12")]
    [InlineData("firefox-container-1a", "")]
    [InlineData("chrome-store", "")]
    [InlineData("firefox-container-999999999999999999999999999999999", "")]
    [InlineData("chromium-profile-brave-Default", "chromium-profile-brave-Default")]
    [InlineData("chromium-profile-chrome-Profile 1", "chromium-profile-chrome-Profile 1")]
    [InlineData("chromium-profile-msedge-Profile 12", "chromium-profile-msedge-Profile 12")]
    [InlineData("chromium-profile-brave-Guest Profile", "")]
    [InlineData("chromium-profile-brave-Profile 0", "")]
    [InlineData(@"chromium-profile-brave-C:\Evil", "")]
    public void Normalize_OnlyNamedFirefoxContainersAndChromiumProfiles(string? raw, string expected) =>
        Assert.Equal(expected, BrowserContainerRules.Normalize(raw));

    [Fact]
    public void CanFill_BoundItemStaysInItsContainer()
    {
        Assert.True(BrowserContainerRules.CanFill("", "firefox-container-1"));
        Assert.True(BrowserContainerRules.CanFill("", ""));
        Assert.True(BrowserContainerRules.CanFill("firefox-container-2", "firefox-container-2"));
        Assert.False(BrowserContainerRules.CanFill("firefox-container-2", "firefox-container-1"));
        Assert.False(BrowserContainerRules.CanFill("firefox-container-2", ""));
        Assert.False(BrowserContainerRules.CanFill("firefox-container-2", "firefox-private"));
        Assert.True(BrowserContainerRules.CanFill("chromium-profile-brave-Default", "chromium-profile-brave-Default"));
        Assert.False(BrowserContainerRules.CanFill("chromium-profile-brave-Default", "chromium-profile-brave-Profile 1"));
        Assert.False(BrowserContainerRules.CanFill("chromium-profile-brave-Default", "chromium-profile-chrome-Default"));
        Assert.False(BrowserContainerRules.CanFill("chromium-profile-brave-Default", ""));
        Assert.True(BrowserContainerRules.CanFill("", "chromium-profile-msedge-Profile 1"));
    }

    [Fact]
    public void WarnUnbound_OnlyInNamedContainers()
    {
        Assert.True(BrowserContainerRules.WarnUnbound("", "firefox-container-3"));
        Assert.False(BrowserContainerRules.WarnUnbound("firefox-container-3", "firefox-container-3"));
        Assert.False(BrowserContainerRules.WarnUnbound("", ""));
        Assert.False(BrowserContainerRules.WarnUnbound("", "0"));
        Assert.True(BrowserContainerRules.WarnUnbound("", "chromium-profile-chrome-Default"));
    }

    [Fact]
    public void BindOnSave_IgnoresPrivateAndDefault()
    {
        Assert.Equal("firefox-container-4", BrowserContainerRules.BindOnSave("firefox-container-4"));
        Assert.Equal("", BrowserContainerRules.BindOnSave("firefox-private"));
        Assert.Equal("", BrowserContainerRules.BindOnSave("firefox-default"));
        Assert.True(BrowserContainerRules.IsBound("firefox-container-4"));
        Assert.False(BrowserContainerRules.IsBound("firefox-default"));
        Assert.Equal("4", BrowserContainerRules.NumberLabel("firefox-container-4"));
        Assert.Equal("", BrowserContainerRules.NumberLabel("firefox-private"));
        Assert.Equal("chromium-profile-brave-Profile 2", BrowserContainerRules.BindOnSave("chromium-profile-brave-Profile 2"));
    }

    [Fact]
    public void ChromiumId_UsesParentProcessNotExtensionClaim()
    {
        Assert.Equal(
            "chromium-profile-brave-Default",
            BrowserContainerRules.ChromiumId(@"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe", null));
        Assert.Equal(
            "chromium-profile-chrome-Profile 1",
            BrowserContainerRules.ChromiumId(
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                @"chrome.exe --profile-directory=""Profile 1"""));
        Assert.Equal(
            "chromium-profile-msedge-Default",
            BrowserContainerRules.ChromiumId(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge.exe"));
        Assert.Equal("", BrowserContainerRules.ChromiumId(@"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --incognito"));
        Assert.Equal("", BrowserContainerRules.ChromiumId(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "msedge.exe -inprivate"));
        Assert.Equal(
            "chromium-profile-chrome-Default",
            BrowserContainerRules.ForNativeRequest(
                "firefox-container-9",
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "chrome.exe --profile-directory=Default"));
        Assert.Equal(
            "firefox-container-9",
            BrowserContainerRules.ForNativeRequest("firefox-container-9", @"C:\Program Files\Mozilla Firefox\firefox.exe", null));
        Assert.Equal(
            "",
            BrowserContainerRules.ForNativeRequest(
                "firefox-container-9",
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "chrome.exe",
                incognito: true));
    }

    [Fact]
    public void ParseProfileDirectory_AllowsDefaultAndProfileN()
    {
        Assert.Equal("Default", BrowserContainerRules.ParseProfileDirectory(null));
        Assert.Equal("Default", BrowserContainerRules.ParseProfileDirectory("chrome.exe"));
        Assert.Equal("Profile 3", BrowserContainerRules.ParseProfileDirectory(@"chrome.exe --profile-directory=Profile 3"));
        Assert.Equal("", BrowserContainerRules.ParseProfileDirectory(@"chrome.exe --profile-directory=Guest Profile"));
        Assert.Equal("", BrowserContainerRules.ParseProfileDirectory(@"chrome.exe --incognito"));
        Assert.True(BrowserContainerRules.IsIncognitoCommandLine("msedge.exe --inprivate"));
    }
}
