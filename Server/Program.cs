using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text.Json;
using Shared;

var app = WebApplication.CreateBuilder(args).Build();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(20) });
var sessions = new ConcurrentDictionary<string, Session>();
var jsonOpts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

app.MapGet("/", () => "Relay OK");

app.Map("/ws", async (HttpContext ctx) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
    using var raw = await ctx.WebSockets.AcceptWebSocketAsync();
    var me = new SafeWs(raw);
    var ct = ctx.RequestAborted;

    try
    {
        var (t, data) = await WsUtil.ReceiveAsync(raw, ct);
        if (data is null || t != WebSocketMessageType.Text) return;
        var hello = JsonSerializer.Deserialize<Hello>(data, jsonOpts);
        if (hello is null || hello.Id.Length < 6 || hello.Id.Length > 20) return;

        if (hello.Role == "target")
        {
            var s = sessions.GetOrAdd(hello.Id, _ => new Session { Hash = hello.Hash });
            if (s.Hash != hello.Hash) { await me.SendTextAsync("ERR:id_in_use", ct); return; }
            s.Target = me;
            await me.SendTextAsync("OK", ct);
            try { await Pump(me, () => s.Controller, ct); }
            finally
            {
                if (s.Target == me)
                {
                    s.Target = null;
                    s.Controller?.Ws.Abort();           // o controlador volta a tentar sozinho
                    if (s.Controller is null) sessions.TryRemove(hello.Id, out _);
                }
            }
        }
        else if (hello.Role == "controller")
        {
            if (!sessions.TryGetValue(hello.Id, out var s) || s.Target is null)
            { await me.SendTextAsync("ERR:offline", ct); return; }
            if (DateTime.UtcNow < s.LockedUntil) { await me.SendTextAsync("ERR:locked", ct); return; }
            if (s.Hash != hello.Hash)
            {
                if (++s.Fails >= 5) { s.LockedUntil = DateTime.UtcNow.AddSeconds(60); s.Fails = 0; }
                await me.SendTextAsync("ERR:auth", ct); return;
            }
            s.Fails = 0;
            s.Controller = me;
            await me.SendTextAsync("OK", ct);
            if (s.Target is { } tg) await tg.SendTextAsync("PEER_JOINED", ct);
            try { await Pump(me, () => s.Target, ct); }
            finally
            {
                if (s.Controller == me)
                {
                    s.Controller = null;
                    if (s.Target is { } tg2) { try { await tg2.SendTextAsync("PEER_LEFT", CancellationToken.None); } catch { } }
                }
            }
        }
    }
    catch (Exception) { /* ligação terminada */ }
});

app.Run();

static async Task Pump(SafeWs from, Func<SafeWs?> to, CancellationToken ct)
{
    while (from.Ws.State == WebSocketState.Open)
    {
        var (t, d) = await WsUtil.ReceiveAsync(from.Ws, ct);
        if (d is null) break;
        if (t == WebSocketMessageType.Binary && to() is { } peer) await peer.SendAsync(d, t, ct);
    }
}

record Hello(string Role, string Id, string Hash);
sealed class Session { public string Hash = ""; public SafeWs? Target, Controller; public int Fails; public DateTime LockedUntil; }