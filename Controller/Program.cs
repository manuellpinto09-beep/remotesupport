using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Shared;

ApplicationConfiguration.Initialize();
var serverUrl = ControllerForm.ResolveServerUrl(args);
Application.Run(new ControllerForm(serverUrl));

sealed class ScreenBox : PictureBox
{
    public ScreenBox() { SetStyle(ControlStyles.Selectable, true); TabStop = true; SizeMode = PictureBoxSizeMode.Zoom; BackColor = Color.Black; Dock = DockStyle.Fill; }
    protected override bool IsInputKey(Keys k) => true;     // Tab, setas, etc. vão para o remoto
}

sealed class ControllerForm : Form
{
    readonly string _serverUrl;

    readonly TextBox _id = new() { PlaceholderText = "ID", Width = 140 };
    readonly TextBox _pwd = new() { PlaceholderText = "Senha", Width = 120 };
    readonly Button _btn = new() { Text = "Ligar", AutoSize = true };
    readonly Label _status = new() { AutoSize = true, Text = "Desligado", Padding = new Padding(8, 6, 0, 0) };
    readonly ScreenBox _pic = new();
    CancellationTokenSource? _cts;
    SafeWs? _conn; Secure? _sec;
    volatile bool _accepted;
    long _lastMove;

    public static string ResolveServerUrl(string[] args)
    {
        if (args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
            return args[0].Trim();

        var cfgPath = Path.Combine(AppContext.BaseDirectory, "server.txt");
        if (File.Exists(cfgPath))
        {
            var content = File.ReadAllText(cfgPath).Trim();
            if (!string.IsNullOrWhiteSpace(content))
                return content;
        }

        return "ws://127.0.0.1:5000/ws";
    }

    public ControllerForm(string serverUrl)
    {
        _serverUrl = serverUrl;
        Text = "Controlador"; Width = 1100; Height = 700;
        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        top.Controls.AddRange(new Control[] { _id, _pwd, _btn, _status });
        Controls.Add(_pic); Controls.Add(top);              // Fill primeiro, Top depois

        _btn.Click += (_, _) => { if (_cts is null) Connect(); else _cts.Cancel(); };
        _pic.MouseDown += (_, e) => { _pic.Focus(); if (Map(e, out var x, out var y)) Send(new { k = "md", x, y, b = Btn(e) }); };
        _pic.MouseUp += (_, e) => { if (Map(e, out var x, out var y)) Send(new { k = "mu", x, y, b = Btn(e) }); };
        _pic.MouseMove += (_, e) =>
        {
            if (Environment.TickCount64 - _lastMove < 12) return;          // limita a ~80 eventos/s
            _lastMove = Environment.TickCount64;
            if (Map(e, out var x, out var y)) Send(new { k = "mm", x, y });
        };
        _pic.MouseWheel += (_, e) => { if (Map(e, out var x, out var y)) Send(new { k = "mw", x, y, d = e.Delta }); };
        _pic.KeyDown += (_, e) => { Send(new { k = "kd", vk = e.KeyValue }); e.Handled = e.SuppressKeyPress = true; };
        _pic.KeyUp += (_, e) => { Send(new { k = "ku", vk = e.KeyValue }); e.Handled = true; };
        FormClosing += (_, _) => _cts?.Cancel();
    }

    static int Btn(MouseEventArgs e) => e.Button == MouseButtons.Left ? 0 : e.Button == MouseButtons.Right ? 1 : 2;

    // Converte posição no PictureBox (Zoom) em coordenadas normalizadas 0..1 do ecrã remoto
    bool Map(MouseEventArgs e, out double nx, out double ny)
    {
        nx = ny = 0; var img = _pic.Image; if (img is null) return false;
        double s = Math.Min((double)_pic.Width / img.Width, (double)_pic.Height / img.Height);
        double w = img.Width * s, h = img.Height * s, ox = (_pic.Width - w) / 2, oy = (_pic.Height - h) / 2;
        nx = (e.X - ox) / w; ny = (e.Y - oy) / h;
        return nx is >= 0 and <= 1 && ny is >= 0 and <= 1;
    }

    void Send(object o)
    {
        var c = _conn; var s = _sec;
        if (c is null || s is null || !_accepted) return;
        _ = c.SendAsync(s.Seal(Proto.Input, JsonSerializer.SerializeToUtf8Bytes(o)), WebSocketMessageType.Binary, CancellationToken.None);
    }

    void SetStatus(string t) { if (IsHandleCreated && !IsDisposed) BeginInvoke(() => _status.Text = t); }

    void Connect()
    {
        var id = _id.Text.Replace(" ", ""); var pwd = _pwd.Text.Trim().ToUpperInvariant();
        if (id.Length < 6 || pwd.Length < 4) { SetStatus("Indique ID e senha"); return; }
        _cts = new CancellationTokenSource(); _btn.Text = "Desligar";
        var ct = _cts.Token;
        _ = Task.Run(async () =>
        {
            await RunAsync(id, pwd, ct);
            BeginInvoke(() => { _btn.Text = "Ligar"; _cts = null; _status.Text = "Desligado"; });
        });
        _pic.Focus();
    }

    async Task RunAsync(string id, string pwd, CancellationToken ct)
    {
        var sec = _sec = new Secure(Proto.DeriveKey(id, pwd));
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var ws = new ClientWebSocket();
                ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
                SetStatus("A ligar...");
                await ws.ConnectAsync(new Uri(_serverUrl), ct);
                var conn = _conn = new SafeWs(ws);
                await conn.SendAsync(JsonSerializer.SerializeToUtf8Bytes(
                    new { role = "controller", id, hash = Proto.AuthHash(id, pwd) }), WebSocketMessageType.Text, ct);

                var (_, d0) = await WsUtil.ReceiveAsync(ws, ct);
                var reply = d0 is null ? "" : Encoding.UTF8.GetString(d0);
                if (reply is "ERR:auth" or "ERR:locked")
                { SetStatus(reply == "ERR:auth" ? "ID/senha incorretos" : "Bloqueado 60 s (demasiadas tentativas)"); return; }

                if (reply != "OK") SetStatus("Cliente offline — a tentar de novo...");
                else
                {
                    SetStatus("Ligado — a aguardar autorização do cliente...");
                    while (true)
                    {
                        var (t, d) = await WsUtil.ReceiveAsync(ws, ct);
                        if (d is null) break;
                        if (t != WebSocketMessageType.Binary || sec.Open(d) is not { } m) continue;
                        if (m.type == Proto.Frame) ShowFrame(m.data);
                        else if (m.type == Proto.Control) OnControl(m.data);
                    }
                }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex) { SetStatus("Erro: " + ex.Message); }
            _accepted = false;
            try { await Task.Delay(3000, ct); } catch { return; }
        }
    }

    void OnControl(byte[] data)
    {
        var c = JsonDocument.Parse(data).RootElement.GetProperty("c").GetString();
        if (c == "accepted") { _accepted = true; SetStatus("Sessão ativa"); }
        else if (c == "denied") { _accepted = false; SetStatus("O cliente recusou a ligação"); }
    }

    void ShowFrame(byte[] jpeg)
    {
        Image img;
        try { img = Image.FromStream(new MemoryStream(jpeg)); } catch { return; }
        BeginInvoke(() => { var old = _pic.Image; _pic.Image = img; old?.Dispose(); });
    }
}