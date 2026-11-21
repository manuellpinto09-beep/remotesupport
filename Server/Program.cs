using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text.Json;
using Shared;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseWebSockets(new WebSocketOptions
{
    KeepAliveInterval = TimeSpan.FromSeconds(20)
});

var sessions = new ConcurrentDictionary<string, Session>();
var jsonOpts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

app.MapGet("/", () => "Relay OK");
app.MapGet("/health", () => Results.Ok(new { status = "ok", activeSessions = sessions.Count }));

app.Map("/ws", async (HttpContext ctx) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest)
    {
        ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
        await ctx.Response.WriteAsync("Expected WebSocket request");
        return;
    }

    var remoteIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    Console.WriteLine($"[WS] Novo pedido WebSocket de {remoteIp}");

    using var raw = await ctx.WebSockets.AcceptWebSocketAsync();
    var me = new SafeWs(raw);
    var ct = ctx.RequestAborted;

    try
    {
        var (t, data) = await WsUtil.ReceiveAsync(raw, ct);
        if (data is null || t != WebSocketMessageType.Text)
        {
            Console.WriteLine($"[WS] Mensagem inicial inválida de {remoteIp}");
            return;
        }

        var hello = JsonSerializer.Deserialize<Hello>(data, jsonOpts);
        var id = hello?.Id?.Trim() ?? "";
        var role = hello?.Role?.Trim().ToLowerInvariant() ?? "";
        var hash = hello?.Hash?.Trim() ?? "";

        if (id.Length < 6 || id.Length > 20 || string.IsNullOrEmpty(role) || string.IsNullOrEmpty(hash))
        {
            Console.WriteLine($"[WS] Hello inválido de {remoteIp} (role='{role}', idLen={id.Length})");
            return;
        }

        Console.WriteLine($"[WS] Hello aceite: role={role}, id={id}");

        if (role == "target")
        {
            var s = sessions.GetOrAdd(id, _ => new Session { Hash = hash });

            if (!string.Equals(s.Hash, hash, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[TARGET] ID já em uso com outra hash: id={id}");
                await me.SendTextAsync("ERR:id_in_use", ct);
                return;
            }

            s.Target = me;
            Console.WriteLine($"[TARGET] Registado e pronto: id={id}");
            await me.SendTextAsync("OK", ct);

            try
            {
                await Pump(me, () => s.Controller, ct);
            }
            finally
            {
                Console.WriteLine($"[TARGET] Desligado: id={id}");
                if (s.Target == me)
                {
                    s.Target = null;
                    var ctrl = s.Controller;
                    if (ctrl is not null)
                    {
                        try { ctrl.Ws.Abort(); } catch { }
                    }
                    else
                    {
                        sessions.TryRemove(id, out _);
                    }
                }
            }
        }
        else if (role == "controller")
        {
            if (!sessions.TryGetValue(id, out var s) || s.Target is null)
            {
                Console.WriteLine($"[CTRL] Target offline para id={id}");
                await me.SendTextAsync("ERR:offline", ct);
                return;
            }

            if (DateTime.UtcNow < s.LockedUntil)
            {
                Console.WriteLine($"[CTRL] Bloqueado temporariamente para id={id}");
                await me.SendTextAsync("ERR:locked", ct);
                return;
            }

            if (!string.Equals(s.Hash, hash, StringComparison.OrdinalIgnoreCase))
            {
                if (++s.Fails >= 5)
                {
                    s.LockedUntil = DateTime.UtcNow.AddSeconds(60);
                    s.Fails = 0;
                }
                Console.WriteLine($"[CTRL] Falha de autenticação para id={id} (tentativa {s.Fails})");
                await me.SendTextAsync("ERR:auth", ct);
                return;
            }

            s.Fails = 0;
            s.Controller = me;
            Console.WriteLine($"[CTRL] Ligado ao target id={id}");
            await me.SendTextAsync("OK", ct);

            if (s.Target is { } tg)
            {
                await tg.SendTextAsync("PEER_JOINED", ct);
            }

            try
            {
                await Pump(me, () => s.Target, ct);
            }
            finally
            {
                Console.WriteLine($"[CTRL] Desligado do target id={id}");
                if (s.Controller == me)
                {
                    s.Controller = null;
                    if (s.Target is null)
                    {
                        sessions.TryRemove(id, out _);
                    }
                    else if (s.Target is { } tg2)
                    {
                        try { await tg2.SendTextAsync("PEER_LEFT", CancellationToken.None); } catch { }
                    }
                }
            }
        }
        else
        {
            Console.WriteLine($"[WS] Role desconhecida: '{role}'");
        }
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine($"[WS] Ligação cancelada ({remoteIp})");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[WS] Erro na ligação ({remoteIp}): {ex.Message}");
    }
});

app.Run();

static async Task Pump(SafeWs from, Func<SafeWs?> to, CancellationToken ct)
{
    while (from.Ws.State == WebSocketState.Open)
    {
        var (t, d) = await WsUtil.ReceiveAsync(from.Ws, ct);
        if (d is null) break;
        if (t == WebSocketMessageType.Binary && to() is { } peer)
        {
            await peer.SendAsync(d, t, ct);
        }
    }
}

record Hello(string? Role, string? Id, string? Hash);

sealed class Session
{
    public string Hash = "";
    public SafeWs? Target, Controller;
    public int Fails;
    public DateTime LockedUntil;
}