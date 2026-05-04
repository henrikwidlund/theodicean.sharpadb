using Theodicean.SharpAdb.Services;

namespace Theodicean.SharpAdb.Tests;

public class ParserTests
{
    [Test]
    public async Task PropertiesParserHandlesStandardFormat()
    {
        const string input = """
            [ro.product.model]: [Pixel 7]
            [ro.product.name]: [panther]
            [persist.sys.locale]: [en-US]
            """;
        var dict = PropertiesParser.Parse(input);
        await Assert.That(dict).ContainsKeyWithValue("ro.product.model", "Pixel 7");
        await Assert.That(dict).ContainsKeyWithValue("ro.product.name", "panther");
        await Assert.That(dict).ContainsKeyWithValue("persist.sys.locale", "en-US");
    }

    [Test]
    public async Task PropertiesParserSkipsMalformedLines()
    {
        const string input = """
            garbage line
            [ok]: [value]

            [no closing bracket
            """;
        var dict = PropertiesParser.Parse(input);
        await Assert.That(dict).HasSingleItem();
        await Assert.That(dict).ContainsKeyWithValue("ok", "value");
    }

    [Test]
    public async Task PackageParserParsesNamesOnly()
    {
        const string input = "package:com.android.settings\npackage:com.example.app\n";
        var packages = PackageParser.Parse(input);
        await Assert.That(packages).Count().IsEqualTo(2);
        await Assert.That(packages[0].PackageName).IsEqualTo("com.android.settings");
        await Assert.That(packages[0].Path).IsNull();
    }

    [Test]
    public async Task PackageParserParsesPathFormat()
    {
        const string input = "package:/data/app/com.foo-1/base.apk=com.foo\npackage:/system/priv-app/Settings/Settings.apk=com.android.settings\n";
        var packages = PackageParser.Parse(input);
        await Assert.That(packages).Count().IsEqualTo(2);
        await Assert.That(packages[0].PackageName).IsEqualTo("com.foo");
        await Assert.That(packages[0].Path).IsEqualTo("/data/app/com.foo-1/base.apk");
    }

    [Test]
    public async Task ProcessParserHandlesHeaderAndRows()
    {
        const string input = """
            USER         PID  PPID NAME
            root           1     0 init
            shell      12345  1234 com.example.app
            """;
        var processes = ProcessParser.Parse(input);
        await Assert.That(processes).Count().IsEqualTo(2);
        await Assert.That(processes[0].Pid).IsEqualTo(1);
        await Assert.That(processes[0].Ppid).IsEqualTo(0);
        await Assert.That(processes[0].Name).IsEqualTo("init");
        await Assert.That(processes[1].Pid).IsEqualTo(12345);
        await Assert.That(processes[1].Name).IsEqualTo("com.example.app");
    }

    [Test]
    public async Task LogcatParserParsesThreadtimeFormat()
    {
        const string line = "01-15 12:34:56.789  1234  5678 I MyTag: Hello, world!";
        await Assert.That(LogcatParser.TryParseThreadTime(line, out var entry)).IsTrue();
        await Assert.That(entry.Priority).IsEqualTo(LogcatPriority.Info);
        await Assert.That(entry.Tag).IsEqualTo("MyTag");
        await Assert.That(entry.Pid).IsEqualTo(1234);
        await Assert.That(entry.Tid).IsEqualTo(5678);
        await Assert.That(entry.Message).IsEqualTo("Hello, world!");
    }

    [Test]
    [Arguments('V', LogcatPriority.Verbose)]
    [Arguments('D', LogcatPriority.Debug)]
    [Arguments('I', LogcatPriority.Info)]
    [Arguments('W', LogcatPriority.Warn)]
    [Arguments('E', LogcatPriority.Error)]
    [Arguments('F', LogcatPriority.Fatal)]
    public async Task LogcatParserMapsPriorities(char prio, LogcatPriority expected)
    {
        var line = $"01-15 12:34:56.789  1   2 {prio} Tag: msg";
        await Assert.That(LogcatParser.TryParseThreadTime(line, out var entry)).IsTrue();
        await Assert.That(entry.Priority).IsEqualTo(expected);
    }

    [Test]
    public async Task LogcatParserRejectsMalformed()
    {
        await Assert.That(LogcatParser.TryParseThreadTime("", out _)).IsFalse();
        await Assert.That(LogcatParser.TryParseThreadTime("not a logcat line", out _)).IsFalse();
    }

    [Test]
    public async Task ShellEscapeWrapsValueInSingleQuotes()
    {
        await Assert.That(ShellEscape.SingleQuote("simple")).IsEqualTo("'simple'");
        await Assert.That(ShellEscape.SingleQuote("with space")).IsEqualTo("'with space'");
        await Assert.That(ShellEscape.SingleQuote("it's")).IsEqualTo("'it'\\''s'");
    }

    [Test]
    public async Task ShellEscapeHandlesEmptyString() =>
        await Assert.That(ShellEscape.SingleQuote("")).IsEqualTo("''");

    [Test]
    public async Task PropertiesParserSkipsLineWithMissingClosingBracket()
    {
        const string input = "[key]: [no closing bracket";
        var dict = PropertiesParser.Parse(input);
        await Assert.That(dict).IsEmpty();
    }

    [Test]
    public async Task PropertiesParserHandlesEmptyKey()
    {
        const string input = "[]: [value]";
        var dict = PropertiesParser.Parse(input);
        await Assert.That(dict).ContainsKeyWithValue("", "value");
    }

    [Test]
    public async Task PackageParserHandlesPackageLineWithoutName()
    {
        const string input = "package:\n";
        var packages = PackageParser.Parse(input);
        await Assert.That(packages).Count().IsEqualTo(1);
        await Assert.That(packages[0].PackageName).IsEqualTo("");
        await Assert.That(packages[0].Path).IsNull();
    }

    [Test]
    public async Task PackageParserHandlesPathWithEmptyName()
    {
        const string input = "package:/data/app/foo.apk=\n";
        var packages = PackageParser.Parse(input);
        await Assert.That(packages).Count().IsEqualTo(1);
        await Assert.That(packages[0].PackageName).IsEqualTo("");
        await Assert.That(packages[0].Path).IsEqualTo("/data/app/foo.apk");
    }

    [Test]
    public async Task ProcessParserHandlesNonNumericPpid()
    {
        const string input = """
            USER         PID  PPID NAME
            root           1   xxx init
            """;
        var processes = ProcessParser.Parse(input);
        await Assert.That(processes).Count().IsEqualTo(1);
        await Assert.That(processes[0].Pid).IsEqualTo(1);
        await Assert.That(processes[0].Ppid).IsNull();
        await Assert.That(processes[0].Name).IsEqualTo("init");
    }

    [Test]
    public async Task ProcessParserSkipsRowsWithNonNumericPid()
    {
        const string input = """
            USER         PID  PPID NAME
            root         abc     0 init
            shell          5     1 ok
            """;
        var processes = ProcessParser.Parse(input);
        await Assert.That(processes).Count().IsEqualTo(1);
        await Assert.That(processes[0].Pid).IsEqualTo(5);
    }

    [Test]
    public async Task LogcatParserMapsSilentPriority()
    {
        const string line = "01-15 12:34:56.789  1   2 S Tag: msg";
        await Assert.That(LogcatParser.TryParseThreadTime(line, out var entry)).IsTrue();
        await Assert.That(entry.Priority).IsEqualTo(LogcatPriority.Silent);
    }

    [Test]
    public async Task LogcatParserUnknownPriorityDefaultsToVerbose()
    {
        const string line = "01-15 12:34:56.789  1   2 X Tag: msg";
        await Assert.That(LogcatParser.TryParseThreadTime(line, out var entry)).IsTrue();
        await Assert.That(entry.Priority).IsEqualTo(LogcatPriority.Verbose);
    }
}
