using System.Runtime.InteropServices;

namespace StemPasswordGenerator.Helpers;

internal static class RuntimeHardening
{
    private const uint ExcludeFromCapture = 0x00000011;
    private const int ProcessAsLrPolicy = 1;
    private const int ProcessStrictHandleCheckPolicy = 3;
    private const int ProcessExtensionPointDisablePolicy = 6;
    private const int ProcessImageLoadPolicy = 10;
    private const uint SemFailCriticalErrors = 0x0001;
    private const uint SemNoGpFaultErrorBox = 0x0002;
    private const uint SemNoOpenFileErrorBox = 0x8000;
    private const uint WerNoHeap = 0x1;
    private const uint WerDisableSnapshotHang = 0x8;
    private const uint WerDisableSnapshotHeap = 0x20;

    public static void ApplyProcessMitigations()
    {
        try
        {
            _ = SetErrorMode(SemFailCriticalErrors | SemNoGpFaultErrorBox | SemNoOpenFileErrorBox);
            _ = WerSetFlags(WerNoHeap | WerDisableSnapshotHang | WerDisableSnapshotHeap);

            var aslr = new MitigationPolicy { Flags = 1 | 2 | 4 };
            SetProcessMitigationPolicy(ProcessAsLrPolicy, ref aslr, (uint)Marshal.SizeOf<MitigationPolicy>());

            var extensionPoints = new MitigationPolicy { Flags = 1 };
            SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, ref extensionPoints, (uint)Marshal.SizeOf<MitigationPolicy>());

            var strictHandles = new MitigationPolicy { Flags = 1 };
            SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, ref strictHandles, (uint)Marshal.SizeOf<MitigationPolicy>());

            var imageLoad = new MitigationPolicy { Flags = 1 | 2 | 4 };
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, ref imageLoad, (uint)Marshal.SizeOf<MitigationPolicy>());
        }
        catch
        {
        }
    }

    public static void ProtectWindowFromCapture(IntPtr windowHandle)
    {
        if (windowHandle == IntPtr.Zero)
        {
            return;
        }

        try
        {
            _ = SetWindowDisplayAffinity(windowHandle, ExcludeFromCapture);
        }
        catch
        {
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MitigationPolicy
    {
        public uint Flags;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessMitigationPolicy(int mitigationPolicy, ref MitigationPolicy lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    private static extern uint SetErrorMode(uint mode);

    [DllImport("wer.dll")]
    private static extern int WerSetFlags(uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);
}
