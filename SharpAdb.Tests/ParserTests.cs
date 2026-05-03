using SharpAdb.Services;

using Xunit;

namespace SharpAdb.Tests;

public class ParserTests
{
    [Fact]
    public void PropertiesParserHandlesStandardFormat()
    {
        const string input = """
            [ro.product.model]: [Pixel 7]
            [ro.product.name]: [panther]
            [persist.sys.locale]: [en-US]
            """;
        var dict = PropertiesParser.Parse(input);
        Assert.Equal("Pixel 7", dict["ro.product.model"]);
        Assert.Equal("panther", dict["ro.product.name"]);
        Assert.Equal("en-US", dict["persist.sys.locale"]);
    }

    [Fact]
    public void PropertiesParserSkipsMalformedLines()
    {
        const string input = """
            garbage line
            [ok]: [value]

            [no closing bracket
            """;
        var dict = PropertiesParser.Parse(input);
        Assert.Single(dict);
        Assert.Equal("value", dict["ok"]);
    }

    [Fact]
    public void PackageParserParsesNamesOnly()
    {
        const string input = "package:com.android.settings\npackage:com.example.app\n";
        var packages = PackageParser.Parse(input);
        Assert.Equal(2, packages.Count);
        Assert.Equal("com.android.settings", packages[0].PackageName);
        Assert.Null(packages[0].Path);
    }

    [Fact]
    public void PackageParserParsesPathFormat()
    {
        const string input = "package:/data/app/com.foo-1/base.apk=com.foo\npackage:/system/priv-app/Settings/Settings.apk=com.android.settings\n";
        var packages = PackageParser.Parse(input);
        Assert.Equal(2, packages.Count);
        Assert.Equal("com.foo", packages[0].PackageName);
        Assert.Equal("/data/app/com.foo-1/base.apk", packages[0].Path);
    }

    [Fact]
    public void ProcessParserHandlesHeaderAndRows()
    {
        const string input = """
            USER         PID  PPID NAME
            root           1     0 init
            shell      12345  1234 com.example.app
            """;
        var processes = ProcessParser.Parse(input);
        Assert.Equal(2, processes.Count);
        Assert.Equal(1, processes[0].Pid);
        Assert.Equal(0, processes[0].Ppid);
        Assert.Equal("init", processes[0].Name);
        Assert.Equal(12345, processes[1].Pid);
        Assert.Equal("com.example.app", processes[1].Name);
    }

    [Fact]
    public void LogcatParserParsesThreadtimeFormat()
    {
        const string line = "01-15 12:34:56.789  1234  5678 I MyTag: Hello, world!";
        Assert.True(LogcatParser.TryParseThreadTime(line, out var entry));
        Assert.Equal(LogcatPriority.Info, entry.Priority);
        Assert.Equal("MyTag", entry.Tag);
        Assert.Equal(1234, entry.Pid);
        Assert.Equal(5678, entry.Tid);
        Assert.Equal("Hello, world!", entry.Message);
    }

    [Theory]
    [InlineData('V', LogcatPriority.Verbose)]
    [InlineData('D', LogcatPriority.Debug)]
    [InlineData('I', LogcatPriority.Info)]
    [InlineData('W', LogcatPriority.Warn)]
    [InlineData('E', LogcatPriority.Error)]
    [InlineData('F', LogcatPriority.Fatal)]
    public void LogcatParserMapsPriorities(char prio, LogcatPriority expected)
    {
        var line = $"01-15 12:34:56.789  1   2 {prio} Tag: msg";
        Assert.True(LogcatParser.TryParseThreadTime(line, out var entry));
        Assert.Equal(expected, entry.Priority);
    }

    [Fact]
    public void LogcatParserRejectsMalformed()
    {
        Assert.False(LogcatParser.TryParseThreadTime("", out _));
        Assert.False(LogcatParser.TryParseThreadTime("not a logcat line", out _));
    }

    [Fact]
    public void ShellEscapeWrapsValueInSingleQuotes()
    {
        Assert.Equal("'simple'", ShellEscape.SingleQuote("simple"));
        Assert.Equal("'with space'", ShellEscape.SingleQuote("with space"));
        Assert.Equal("'it'\\''s'", ShellEscape.SingleQuote("it's"));
    }
}