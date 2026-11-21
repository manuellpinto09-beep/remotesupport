using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;

namespace Shared;

public static class Proto
{
    public const byte Frame = 1, Input = 2, Control = 3;

    public static string NewId() => RandomNumberGenerator.GetInt32(100_000_000, 1_000_000_000).ToString();

    public static string NewPassword()
    {
        const string a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // sem 0/O/1/I
        return new string(Enumerable.Range(0, 8).Select(_ => a[RandomNumberGenerator.GetInt32(a.Length)]).ToArray());
    }

    // Vai ao servidor (só serve para autenticar). Diferente da chave de cifra.
    public static string AuthHash(string id, string pwd) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"auth|{id}|{pwd}")));

    // NUNCA sai do agente/controlador.
    public static byte[] DeriveKey(string id, string pwd) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(pwd), Encoding.UTF8.GetBytes("enc|" + id),
                                  120_000, HashAlgorithmName.SHA256, 32);
}

/// Mensagem cifrada: [nonce 12][tag 16][ciphertext]; plaintext = [tipo][dados]
public sealed class Secure
{
    readonly AesGcm _aes;
    public Secure(byte[] key) => _aes = new AesGcm(key, 16);

    public byte[] Seal(byte type, byte[] data)
    {
        var plain = new byte[data.Length + 1];
        plain[0] = type; data.CopyTo(plain, 1);
        var o = new byte[28 + plain.Length];
        RandomNumberGenerator.Fill(o.AsSpan(0, 12));
        lock (_aes) _aes.Encrypt(o.AsSpan(0, 12), plain, o.AsSpan(28), o.AsSpan(12, 16));
        return o;
    }

    public (byte type, byte[] data)? Open(byte[] msg)
    {
        if (msg.Length < 29) return null;
        var plain = new byte[msg.Length - 28];
        try { lock (_aes) _aes.Decrypt(msg.AsSpan(0, 12), msg.AsSpan(28), msg.AsSpan(12, 16), plain); }
        catch (CryptographicException) { return null; }
        return (plain[0], plain[1..]);
    }
}

/// WebSocket com envio serializado (o WebSocket não permite SendAsync concorrentes).
public sealed class SafeWs
{
    public WebSocket Ws { get; }
    readonly SemaphoreSlim _l = new(1, 1);
    public SafeWs(WebSocket ws) => Ws = ws;

    public async Task SendAsync(byte[] d, WebSocketMessageType t, CancellationToken ct)
    {
        await _l.WaitAsync(ct);
        try { if (Ws.State == WebSocketState.Open) await Ws.SendAsync(d, t, true, ct); }
        finally { _l.Release(); }
    }
    public Task SendTextAsync(string s, CancellationToken ct) =>
        SendAsync(Encoding.UTF8.GetBytes(s), WebSocketMessageType.Text, ct);
}

public static class WsUtil
{
    public static async Task<(WebSocketMessageType type, byte[]? data)> ReceiveAsync(WebSocket ws, CancellationToken ct)
    {
        var buf = new byte[64 * 1024];
        using var ms = new MemoryStream();
        while (true)
        {
            var r = await ws.ReceiveAsync(buf, ct);
            if (r.MessageType == WebSocketMessageType.Close) return (r.MessageType, null);
            ms.Write(buf, 0, r.Count);
            if (ms.Length > 8 * 1024 * 1024) throw new InvalidDataException("mensagem demasiado grande");
            if (r.EndOfMessage) return (r.MessageType, ms.ToArray());
        }
    }
}