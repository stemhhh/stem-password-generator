using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Helpers;

internal static class AutofillService
{
    public static bool TryFill(string username, string password)
    {
        var foreground = GetForegroundWindow();
        if (foreground == IntPtr.Zero)
        {
            return false;
        }

        GetWindowThreadProcessId(foreground, out var processId);
        if (processId == 0 || processId == (uint)Environment.ProcessId)
        {
            return false;
        }

        var target = foreground;
        try
        {
            if (!string.IsNullOrEmpty(username))
            {
                if (GetForegroundWindow() != target)
                {
                    return false;
                }

                TypeText(username);
                PressTab();
            }

            if (!string.IsNullOrEmpty(password))
            {
                if (GetForegroundWindow() != target)
                {
                    return false;
                }

                TypeText(password);
            }

            return GetForegroundWindow() == target;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string GetForegroundAppHint()
    {
        var foreground = GetForegroundWindow();
        if (foreground == IntPtr.Zero)
        {
            return string.Empty;
        }

        var title = new StringBuilder(512);
        _ = GetWindowText(foreground, title, title.Capacity);
        GetWindowThreadProcessId(foreground, out var processId);
        try
        {
            using var process = Process.GetProcessById((int)processId);
            var name = process.ProcessName;
            return string.IsNullOrWhiteSpace(title.ToString()) ? name : $"{name} {title}";
        }
        catch (Exception)
        {
            return title.ToString();
        }
    }

    public static VaultItem? Match(IReadOnlyList<VaultItem> items, string hint) =>
        SiteMatchService.BestMatchForHint(items, hint);

    private static void TypeText(string text)
    {
        foreach (var character in text)
        {
            SendUnicode(character, keyUp: false);
            SendUnicode(character, keyUp: true);
        }
    }

    private static void PressTab()
    {
        SendVirtualKey(0x09, keyUp: false);
        SendVirtualKey(0x09, keyUp: true);
    }

    private static void SendUnicode(char character, bool keyUp)
    {
        var input = new Input
        {
            Type = 1,
            Data = new InputUnion
            {
                Keyboard = new KeyboardInput
                {
                    VirtualKey = 0,
                    ScanCode = character,
                    Flags = (uint)(4 | (keyUp ? 2 : 0)),
                    Time = 0,
                    ExtraInfo = IntPtr.Zero
                }
            }
        };
        _ = SendInput(1, [input], Marshal.SizeOf<Input>());
    }

    private static void SendVirtualKey(ushort virtualKey, bool keyUp)
    {
        var input = new Input
        {
            Type = 1,
            Data = new InputUnion
            {
                Keyboard = new KeyboardInput
                {
                    VirtualKey = virtualKey,
                    ScanCode = 0,
                    Flags = (uint)(keyUp ? 2 : 0),
                    Time = 0,
                    ExtraInfo = IntPtr.Zero
                }
            }
        };
        _ = SendInput(1, [input], Marshal.SizeOf<Input>());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Input
    {
        public uint Type;
        public InputUnion Data;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)]
        public KeyboardInput Keyboard;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KeyboardInput
    {
        public ushort VirtualKey;
        public ushort ScanCode;
        public uint Flags;
        public uint Time;
        public IntPtr ExtraInfo;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint count, Input[] inputs, int size);
}
