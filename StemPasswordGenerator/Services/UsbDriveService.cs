using System.Diagnostics;
using System.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class UsbDriveService
{
    public static IReadOnlyList<UsbDriveInfo> ListRemovable()
    {
        var drives = new List<UsbDriveInfo>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType != DriveType.Removable || !UsbDriveRules.IsSafeLetter(drive.Name))
                {
                    continue;
                }

                var ready = drive.IsReady;
                var root = drive.RootDirectory.FullName;
                drives.Add(new UsbDriveInfo
                {
                    Letter = UsbDriveRules.NormalizeLetter(drive.Name),
                    Label = ready ? drive.VolumeLabel : string.Empty,
                    FileSystem = ready ? drive.DriveFormat : string.Empty,
                    TotalBytes = ready ? drive.TotalSize : 0,
                    FreeBytes = ready ? drive.AvailableFreeSpace : 0,
                    IsReady = ready,
                    HasStemKey = ready && File.Exists(Path.Combine(root, UsbKeyCryptography.StickFileName))
                });
            }
            catch (Exception)
            {
            }
        }

        drives.Sort(static (left, right) => string.CompareOrdinal(left.Letter, right.Letter));
        return drives;
    }

    public static IReadOnlyList<string> FindKeyFiles()
    {
        var files = new List<string>();
        foreach (var drive in ListRemovable())
        {
            if (!drive.HasStemKey)
            {
                continue;
            }

            files.Add(Path.Combine(drive.Letter + "\\", UsbKeyCryptography.StickFileName));
        }

        return files;
    }

    public static async Task FormatAsync(UsbFormatRequest request)
    {
        UsbDriveRules.EnsureSafe(request);
        var arguments = UsbDriveRules.BuildFormatArguments(request);
        var format = Path.Combine(Environment.SystemDirectory, "format.com");
        if (!File.Exists(format))
        {
            throw new InvalidOperationException("Windows format.com was not found.");
        }

        var start = new ProcessStartInfo
        {
            FileName = format,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start Windows format.");
        try
        {
            await process.StandardInput.WriteLineAsync("Y").ConfigureAwait(false);
            process.StandardInput.Close();
        }
        catch (Exception)
        {
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception)
            {
            }

            throw new TimeoutException("Formatting the USB timed out.");
        }

        if (process.ExitCode != 0)
        {
            var error = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error)
                ? "Windows could not format that USB. Close files on the stick and try again."
                : error.Trim());
        }

        await WaitUntilReadyAsync(UsbDriveRules.NormalizeLetter(request.Letter)).ConfigureAwait(false);
    }

    public static async Task WriteStemKeyAsync(string letter, byte[] blob, bool writeReadme)
    {
        var root = UsbDriveRules.NormalizeLetter(letter) + "\\";
        await WaitUntilReadyAsync(UsbDriveRules.NormalizeLetter(letter)).ConfigureAwait(false);
        var keyPath = Path.Combine(root, UsbKeyCryptography.StickFileName);
        await File.WriteAllBytesAsync(keyPath, blob).ConfigureAwait(false);
        try
        {
            File.SetAttributes(keyPath, File.GetAttributes(keyPath) | FileAttributes.Hidden);
        }
        catch (Exception)
        {
        }

        if (writeReadme)
        {
            await File.WriteAllTextAsync(Path.Combine(root, UsbKeyCryptography.ReadmeFileName), UsbKeyCryptography.ReadmeText()).ConfigureAwait(false);
        }
    }

    public static async Task<byte[]> ReadStemKeyAsync(string path)
    {
        var data = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
        if (data.Length is 0 or > 1024 * 1024 || !UsbKeyCryptography.LooksLikeStick(data))
        {
            CryptographicOperations.ZeroMemory(data);
            throw new CryptographicException("That is not a Stem USB key.");
        }

        return data;
    }

    private static async Task WaitUntilReadyAsync(string letter)
    {
        var root = letter + "\\";
        for (var i = 0; i < 20; i++)
        {
            try
            {
                var drive = new DriveInfo(root);
                if (drive.IsReady)
                {
                    _ = Directory.GetFiles(root);
                    return;
                }
            }
            catch (Exception)
            {
            }

            await Task.Delay(400).ConfigureAwait(false);
        }
    }
}
