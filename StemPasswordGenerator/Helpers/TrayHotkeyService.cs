using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Helpers;

internal sealed class TrayHotkeyService : IDisposable
{
    public const int GenerateHotkeyId = 1;
    public const int FillHotkeyId = 2;

    private const int WmDestroy = 0x0002;
    private const int WmHotkey = 0x0312;
    private const int WmTray = 0x8000 + 1;
    private const int WmLButtonUp = 0x0202;
    private const int WmLButtonDblClk = 0x0203;
    private const int WmRButtonUp = 0x0205;
    private const int WmContextMenu = 0x007B;
    private const int NimAdd = 0;
    private const int NimModify = 1;
    private const int NimDelete = 2;
    private const int NimSetVersion = 4;
    private const int NifMessage = 0x01;
    private const int NifIcon = 0x02;
    private const int NifTip = 0x04;
    private const int NifInfo = 0x10;
    private const int NotifyIconVersion4 = 4;
    private const int ModAlt = 0x0001;
    private const int ModControl = 0x0002;
    private const int VkS = 0x53;
    private const int VkF = 0x46;
    private const uint ImageIcon = 1;
    private const uint LrLoadFromFile = 0x0010;
    private const uint LrDefaultSize = 0x0040;
    private const uint MfString = 0;
    private const uint MfSeparator = 0x0800;
    private const uint TpmReturnCmd = 0x0100;
    private const uint TpmRightButton = 0x0002;
    private const int MenuOpen = 1;
    private const int MenuGenerate = 2;
    private const int MenuFill = 3;
    private const int MenuPanic = 4;
    private const int MenuExit = 5;
    private const uint NiifInfo = 0x01;
    private const uint NiifNoSound = 0x10;

    private static readonly IntPtr HwndMessage = new(-3);

    private readonly DispatcherQueue _dispatcher;
    private readonly WndProc _wndProc;
    private readonly string _className = "StemPasswordGenerator.TrayHotkey." + Guid.NewGuid().ToString("N");
    private IntPtr _hwnd;
    private IntPtr _icon;
    private bool _iconVisible;
    private bool _hotkeysRegistered;
    private bool _disposed;

    public TrayHotkeyService(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _wndProc = OnWindowMessage;
        CreateMessageWindow();
        LoadIcon();
    }

    public event Action? OpenRequested;
    public event Action? GenerateRequested;
    public event Action? FillRequested;
    public event Action? PanicRequested;
    public event Action? ExitRequested;

    public bool HotkeysRegistered => _hotkeysRegistered;

    public void ShowIcon()
    {
        if (_hwnd == IntPtr.Zero || _iconVisible)
        {
            return;
        }

        var data = CreateNotifyData(includeInfo: false);
        if (Shell_NotifyIcon(NimAdd, ref data))
        {
            data.uVersion = NotifyIconVersion4;
            _ = Shell_NotifyIcon(NimSetVersion, ref data);
            _iconVisible = true;
        }
    }

    public void HideIcon()
    {
        if (!_iconVisible || _hwnd == IntPtr.Zero)
        {
            return;
        }

        var data = CreateNotifyData(includeInfo: false);
        _ = Shell_NotifyIcon(NimDelete, ref data);
        _iconVisible = false;
    }

    public void UpdateTooltip()
    {
        if (!_iconVisible || _hwnd == IntPtr.Zero)
        {
            return;
        }

        var data = CreateNotifyData(includeInfo: false);
        _ = Shell_NotifyIcon(NimModify, ref data);
    }

    public void ShowNotification(string message)
    {
        if (!_iconVisible || _hwnd == IntPtr.Zero || string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        var data = CreateNotifyData(includeInfo: true);
        data.szInfoTitle = Clip(UiStrings.Get("AppTitle"), 63);
        data.szInfo = Clip(message, 255);
        data.dwInfoFlags = NiifInfo | NiifNoSound;
        _ = Shell_NotifyIcon(NimModify, ref data);
    }

    public void RegisterHotkeys()
    {
        if (_hwnd == IntPtr.Zero || _hotkeysRegistered)
        {
            return;
        }

        var generate = RegisterHotKey(_hwnd, GenerateHotkeyId, ModControl | ModAlt, VkS);
        var fill = RegisterHotKey(_hwnd, FillHotkeyId, ModControl | ModAlt, VkF);
        _hotkeysRegistered = generate && fill;
        if (!_hotkeysRegistered)
        {
            UnregisterHotkeys();
        }
    }

    public void UnregisterHotkeys()
    {
        if (_hwnd == IntPtr.Zero)
        {
            _hotkeysRegistered = false;
            return;
        }

        _ = UnregisterHotKey(_hwnd, GenerateHotkeyId);
        _ = UnregisterHotKey(_hwnd, FillHotkeyId);
        _hotkeysRegistered = false;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        UnregisterHotkeys();
        HideIcon();
        if (_hwnd != IntPtr.Zero)
        {
            _ = DestroyWindow(_hwnd);
            _hwnd = IntPtr.Zero;
        }

        if (_icon != IntPtr.Zero)
        {
            _ = DestroyIcon(_icon);
            _icon = IntPtr.Zero;
        }

        _ = UnregisterClass(_className, GetModuleHandle(null));
    }

    private void CreateMessageWindow()
    {
        var wndClass = new WndClass
        {
            lpfnWndProc = _wndProc,
            hInstance = GetModuleHandle(null),
            lpszClassName = _className
        };
        if (RegisterClass(ref wndClass) == 0)
        {
            return;
        }

        _hwnd = CreateWindowEx(0, _className, "StemTray", 0, 0, 0, 0, 0, HwndMessage, IntPtr.Zero, wndClass.hInstance, IntPtr.Zero);
    }

    private void LoadIcon()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (!File.Exists(path))
        {
            return;
        }

        _icon = LoadImage(IntPtr.Zero, path, ImageIcon, 0, 0, LrLoadFromFile | LrDefaultSize);
    }

    private NotifyIconData CreateNotifyData(bool includeInfo)
    {
        return new NotifyIconData
        {
            cbSize = Marshal.SizeOf<NotifyIconData>(),
            hWnd = _hwnd,
            uID = 1,
            uFlags = (uint)(NifMessage | NifIcon | NifTip | (includeInfo ? NifInfo : 0)),
            uCallbackMessage = WmTray,
            hIcon = _icon,
            szTip = Clip(UiStrings.Get("TrayTooltip"), 127),
            szInfo = string.Empty,
            szInfoTitle = string.Empty
        };
    }

    private IntPtr OnWindowMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == WmHotkey)
        {
            var id = wParam.ToInt32();
            Enqueue(() =>
            {
                if (id == GenerateHotkeyId)
                {
                    GenerateRequested?.Invoke();
                }
                else if (id == FillHotkeyId)
                {
                    FillRequested?.Invoke();
                }
            });
            return IntPtr.Zero;
        }

        if (message == WmTray)
        {
            var eventCode = lParam.ToInt32() & 0xFFFF;
            if (eventCode is WmLButtonUp or WmLButtonDblClk)
            {
                Enqueue(() => OpenRequested?.Invoke());
            }
            else if (eventCode is WmRButtonUp or WmContextMenu)
            {
                ShowContextMenu();
            }

            return IntPtr.Zero;
        }

        if (message == WmDestroy)
        {
            return DefWindowProc(hwnd, message, wParam, lParam);
        }

        return DefWindowProc(hwnd, message, wParam, lParam);
    }

    private void ShowContextMenu()
    {
        if (_hwnd == IntPtr.Zero)
        {
            return;
        }

        GetCursorPos(out var point);
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero)
        {
            return;
        }

        try
        {
            _ = AppendMenu(menu, MfString, (UIntPtr)MenuOpen, UiStrings.Get("TrayOpen"));
            _ = AppendMenu(menu, MfString, (UIntPtr)MenuGenerate, UiStrings.Get("TrayGenerate"));
            _ = AppendMenu(menu, MfString, (UIntPtr)MenuFill, UiStrings.Get("TrayFill"));
            _ = AppendMenu(menu, MfString, (UIntPtr)MenuPanic, UiStrings.Get("PanicLock"));
            _ = AppendMenu(menu, MfSeparator, UIntPtr.Zero, string.Empty);
            _ = AppendMenu(menu, MfString, (UIntPtr)MenuExit, UiStrings.Get("TrayExit"));
            _ = SetForegroundWindow(_hwnd);
            var command = TrackPopupMenu(menu, TpmReturnCmd | TpmRightButton, point.X, point.Y, 0, _hwnd, IntPtr.Zero);
            _ = PostMessage(_hwnd, 0, IntPtr.Zero, IntPtr.Zero);
            Enqueue(() =>
            {
                switch (command)
                {
                    case MenuOpen:
                        OpenRequested?.Invoke();
                        break;
                    case MenuGenerate:
                        GenerateRequested?.Invoke();
                        break;
                    case MenuFill:
                        FillRequested?.Invoke();
                        break;
                    case MenuPanic:
                        PanicRequested?.Invoke();
                        break;
                    case MenuExit:
                        ExitRequested?.Invoke();
                        break;
                }
            });
        }
        finally
        {
            _ = DestroyMenu(menu);
        }
    }

    private void Enqueue(Action action)
    {
        _ = _dispatcher.TryEnqueue(() => action());
    }

    private static string Clip(string value, int max)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Length <= max ? value : value[..max];
    }

    private delegate IntPtr WndProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClass
    {
        public uint style;
        public WndProc lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public int cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClass(ref WndClass lpWndClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool UnregisterClass(string lpClassName, IntPtr hInstance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(int dwExStyle, string lpClassName, string lpWindowName, int dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, int fsModifiers, int vk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int dwMessage, ref NotifyIconData lpData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool AppendMenu(IntPtr hMenu, uint uFlags, UIntPtr uIDNewItem, string lpNewItem);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr hMenu);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out Point lpPoint);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int TrackPopupMenu(IntPtr hMenu, uint uFlags, int x, int y, int nReserved, IntPtr hWnd, IntPtr prcRect);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}
