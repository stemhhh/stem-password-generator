using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace StemPasswordGenerator.Services;

/// <summary>
/// Best-effort in-process hiding of a short key buffer. Same-user malware that injects
/// into Stem can still recover it; this raises the cost of naive ReadProcessMemory / pagefile copies.
/// </summary>
public static class ProtectedMemory
{
    public const int BlockSize = 16;
    private const uint SameProcess = 0;

    public static bool IsSupported => OperatingSystem.IsWindows();

    public static int AlignedLength(int length)
    {
        if (length <= 0)
        {
            return BlockSize;
        }

        var blocks = (length + BlockSize - 1) / BlockSize;
        return blocks * BlockSize;
    }

    public static bool TryLock(IntPtr address, int length)
    {
        if (!IsSupported || address == IntPtr.Zero || length <= 0)
        {
            return false;
        }

        try
        {
            return VirtualLock(address, (UIntPtr)length);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void Unlock(IntPtr address, int length)
    {
        if (!IsSupported || address == IntPtr.Zero || length <= 0)
        {
            return;
        }

        _ = VirtualUnlock(address, (UIntPtr)length);
    }

    public static bool TryProtect(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (!IsSupported || buffer.Length == 0 || buffer.Length % BlockSize != 0)
        {
            return false;
        }

        try
        {
            return CryptProtectMemory(buffer, (uint)buffer.Length, SameProcess);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool TryUnprotect(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (!IsSupported || buffer.Length == 0 || buffer.Length % BlockSize != 0)
        {
            return false;
        }

        try
        {
            return CryptUnprotectMemory(buffer, (uint)buffer.Length, SameProcess);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void Zero(byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectMemory(byte[] pData, uint cbData, uint dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectMemory(byte[] pData, uint cbData, uint dwFlags);
}
