using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Shared;

ApplicationConfiguration.Initialize();
var serverUrl = AgentForm.ResolveServerUrl(args);
Application.Run(new AgentForm(serverUrl));

sealed class AgentForm : Form
{
    static readonly ImageCodecInfo JpegCodec = ImageCodecInfo.GetImageEncoders().First(e => e.FormatID == ImageFormat.Jpeg.Guid);
    static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    readonly string _serverUrl;
    readonly string _id = Proto.NewId(), _pwd = Proto.NewPassword();
    readonly Secure _sec;
    readonly Label _status = new() { AutoSize = true, Text = "A iniciar..." };
    readonly CancellationTokenSource _cts = new();
    CancellationTokenSource? _capCts;
    volatile bool _allowed;

    public static string ResolveServerUrl(string[] args)
    {
        string? raw = null;

        if (args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
        {
            raw = args[0];
        }
        else
        {
            var cfgPath = Path.Combine(AppContext.BaseDirectory, "server.txt");
            if (File.Exists(cfgPath))
            {
                raw = File.ReadAllText(cfgPath);
            }
        }

        var cleaned = (raw ?? "").Trim().Trim('\uFEFF');
        if (string.IsNullOrWhiteSpace(cleaned))
            return "ws://127.0.0.1:5000/ws";

        if (cleaned.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            cleaned = "wss://" + cleaned["https://".Length..];
        else if (cleaned.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            cleaned = "ws://" + cleaned["http://".Length..];

        cleaned = cleaned.TrimEnd('/');
        if (!cleaned.EndsWith("/ws", StringComparison.OrdinalIgnoreCase))
            cleaned += "/ws";

        return cleaned;
    }

    static void LogError(string context, string url, Exception ex)
    {
        try
        {
            var logPath = Path.Combine(AppContext.BaseDirectory, "agent_debug.log");
            var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ({context}) URL={url}\n{ex}\n----------------------------------------\n";
            File.AppendAllText(logPath, entry);
        }
        catch
        {
            // Ignora falhas de escrita em disco
        }
    }

    public AgentForm(string serverUrl)
    {
        _serverUrl = serverUrl;
        _sec = new Secure(Proto.DeriveKey(_id, _pwd));
        Text = "Suporte Remoto";
        Width = 440;
        Height = 350;
        StartPosition = FormStartPosition.CenterScreen;

        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            Padding = new Padding(16)
        };
        var big = new Font("Segoe UI", 20, FontStyle.Bold);
        var smallInfo = new Font("Segoe UI", 8.5f);

        flow.Controls.Add(new Label { Text = "O seu ID:", AutoSize = true });
        flow.Controls.Add(new Label { Text = $"{_id[..3]} {_id[3..6]} {_id[6..]}", Font = big, AutoSize = true });
        flow.Controls.Add(new Label { Text = "Senha temporária:", AutoSize = true });
        flow.Controls.Add(new Label { Text = _pwd, Font = big, AutoSize = true });
        flow.Controls.Add(_status);
        flow.Controls.Add(new Label { Text = $"Servidor: {_serverUrl}", Font = smallInfo, ForeColor = Color.DimGray, AutoSize = true, Padding = new Padding(0, 4, 0, 6) });

        var stop = new Button { Text = "Terminar sessão", AutoSize = true };
        stop.Click += (_, _) => Close();
        flow.Controls.Add(stop);
        Controls.Add(flow);

        Load += (_, _) => _ = Task.Run(() => RunAsync(_cts.Token));
        FormClosing += (_, _) => { _cts.Cancel(); _capCts?.Cancel(); };
    }

    void SetStatus(string s)
    {
        if (IsHandleCreated && !IsDisposed)
            BeginInvoke(() => _status.Text = s);
    }

    async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            ClientWebSocket? ws = null;
            try
            {
                ws = new ClientWebSocket();
                ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
                SetStatus("A ligar ao servidor...");

                var uri = new Uri(_serverUrl);
                await ws.ConnectAsync(uri, ct);

                var conn = new SafeWs(ws);
                await conn.SendAsync(JsonSerializer.SerializeToUtf8Bytes(
                    new { role = "target", id = _id, hash = Proto.AuthHash(_id, _pwd) }),
                    WebSocketMessageType.Text, ct);

                while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
                {
                    var (type, data) = await WsUtil.ReceiveAsync(ws, ct);
                    if (data is null) break;
                    if (type == WebSocketMessageType.Text) OnText(conn, Encoding.UTF8.GetString(data));
                    else if (_allowed && _sec.Open(data) is { } m && m.type == Proto.Input) Inject(m.data);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                LogError("RunAsync", _serverUrl, ex);
                SetStatus("Ligação perdida: " + ex.Message);
            }
            finally
            {
                StopCapture();
                try { ws?.Dispose(); } catch { }
            }

            try { await Task.Delay(3000, ct); } catch { break; }
        }
    }

    void OnText(SafeWs conn, string msg)
    {
        switch (msg)
        {
            case "OK":
                SetStatus("Pronto — a aguardar o técnico");
                break;
            case "PEER_JOINED":
                _ = Task.Run(() => AskConsentAsync(conn));
                break;
            case "PEER_LEFT":
                StopCapture();
                SetStatus("O técnico desligou-se");
                break;
            case "ERR:id_in_use":
                SetStatus("Erro: ID já em uso no servidor");
                break;
        }
    }

    async Task AskConsentAsync(SafeWs conn)
    {
        bool yes = false;
        try
        {
            Invoke(() => yes = MessageBox.Show(this,
                "Um técnico pediu para ver e controlar este computador.\n\nPermitir?",
                "Pedido de ligação", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2) == DialogResult.Yes);
        }
        catch { return; }

        if (yes)
        {
            _allowed = true;
            await Send(conn, "{\"c\":\"accepted\"}");
            _capCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            var token = _capCts.Token;
            _ = Task.Run(() => CaptureLoopAsync(conn, token));
            SetStatus("SESSÃO ATIVA — técnico ligado");
        }
        else
        {
            await Send(conn, "{\"c\":\"denied\"}");
        }
    }

    Task Send(SafeWs c, string json) =>
        c.SendAsync(_sec.Seal(Proto.Control, Encoding.UTF8.GetBytes(json)), WebSocketMessageType.Binary, CancellationToken.None);

    void StopCapture() { _allowed = false; _capCts?.Cancel(); }

    // ---------- Captura com qualidade/FPS adaptativos ----------
    async Task CaptureLoopAsync(SafeWs conn, CancellationToken ct)
    {
        int quality = 60, fps = 15;
        double scale = 1.0;
        byte[]? last = null;

        while (!ct.IsCancellationRequested)
        {
            var t0 = Stopwatch.GetTimestamp();
            try
            {
                var jpeg = CaptureScreen(quality, scale);
                var h = SHA1.HashData(jpeg);
                if (last is null || !h.AsSpan().SequenceEqual(last))
                {
                    last = h;
                    var s0 = Stopwatch.GetTimestamp();
                    await conn.SendAsync(_sec.Seal(Proto.Frame, jpeg), WebSocketMessageType.Binary, ct);
                    double sendMs = Stopwatch.GetElapsedTime(s0).TotalMilliseconds;
                    double budget = 1000.0 / fps;
                    if (sendMs > budget * 1.5)
                    {
                        quality = Math.Max(25, quality - 8);
                        fps = Math.Max(4, fps - 2);
                        if (quality <= 33) scale = Math.Max(0.5, scale - 0.1);
                    }
                    else if (sendMs < budget * 0.4)
                    {
                        quality = Math.Min(80, quality + 3);
                        fps = Math.Min(24, fps + 1);
                        scale = Math.Min(1.0, scale + 0.05);
                    }
                }
            }
            catch (OperationCanceledException) { break; }
            catch { try { await Task.Delay(500, ct); } catch { break; } }

            var left = (int)(1000.0 / fps - Stopwatch.GetElapsedTime(t0).TotalMilliseconds);
            if (left > 0) { try { await Task.Delay(left, ct); } catch { break; } }
        }
    }

    static byte[] CaptureScreen(int quality, double scale)
    {
        var b = Screen.PrimaryScreen!.Bounds;
        using var full = new Bitmap(b.Width, b.Height, PixelFormat.Format24bppRgb);
        using (var g = Graphics.FromImage(full)) g.CopyFromScreen(b.Location, Point.Empty, b.Size);

        Bitmap src = full;
        Bitmap? small = null;
        if (scale < 0.99)
        {
            small = new Bitmap((int)(b.Width * scale), (int)(b.Height * scale), PixelFormat.Format24bppRgb);
            using var g = Graphics.FromImage(small);
            g.InterpolationMode = InterpolationMode.Bilinear;
            g.DrawImage(full, 0, 0, small.Width, small.Height);
            src = small;
        }
        using var ep = new EncoderParameters(1);
        ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)quality);
        using var ms = new MemoryStream();
        src.Save(ms, JpegCodec, ep);
        small?.Dispose();
        return ms.ToArray();
    }

    // ---------- Injeção de rato/teclado ----------
    static void Inject(byte[] json)
    {
        var e = JsonSerializer.Deserialize<InputMsg>(json, JsonOpts);
        if (e is null) return;
        switch (e.K)
        {
            case "mm": Mouse(e, 0x0001); break;
            case "md": Mouse(e, e.B == 0 ? 0x0002u : e.B == 1 ? 0x0008u : 0x0020u); break;
            case "mu": Mouse(e, e.B == 0 ? 0x0004u : e.B == 1 ? 0x0010u : 0x0040u); break;
            case "mw": Mouse(e, 0x0800, unchecked((uint)e.D)); break;
            case "kd": Key((ushort)e.Vk, false); break;
            case "ku": Key((ushort)e.Vk, true); break;
        }
    }

    static void Mouse(InputMsg e, uint flags, uint data = 0)
    {
        var i = new Native.INPUT { type = 0 };
        i.u.mi.dx = (int)(Math.Clamp(e.X, 0, 1) * 65535);
        i.u.mi.dy = (int)(Math.Clamp(e.Y, 0, 1) * 65535);
        i.u.mi.mouseData = data;
        i.u.mi.dwFlags = flags | 0x8001;
        Native.SendInput(1, new[] { i }, Marshal.SizeOf<Native.INPUT>());
    }

    static void Key(ushort vk, bool up)
    {
        bool ext = vk is (>= 0x21 and <= 0x28) or 0x2D or 0x2E or 0x5B or 0x5C or 0x6F or 0x90 or 0xA3 or 0xA5;
        var i = new Native.INPUT { type = 1 };
        i.u.ki.wVk = vk;
        i.u.ki.wScan = (ushort)Native.MapVirtualKey(vk, 0);
        i.u.ki.dwFlags = (up ? 2u : 0u) | (ext ? 1u : 0u);
        Native.SendInput(1, new[] { i }, Marshal.SizeOf<Native.INPUT>());
    }
}

sealed record InputMsg(string K, double X, double Y, int B, int D, int Vk);

static class Native
{
    [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public nint dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public nint dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)] public struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public InputUnion u; }

    [DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint n, INPUT[] inputs, int cb);
    [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint code, uint mapType);
}