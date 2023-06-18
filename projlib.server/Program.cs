using System.Net;
using System.Net.Sockets;
using netlib;

namespace CoolandonRS.projlib.server;

internal static class Program {
    public const int UpdaterPort = 1248;
    internal const string UserKeyPath = "./keys"; // {name}.pub.pem
    internal const string BinaryPath = "./bin"; // {name}/{platform}
    internal const string InfoPath = "./info"; // {name}.json
    internal const string AuthPath = "./auth"; // server.key.pem // yubikeys.txt // yubiapi.txt
    internal static readonly string PemData = File.ReadAllText($"{AuthPath}/server.key.pem");
    internal static readonly SemVer SerVer = new(1, 0, 0);

    public static void Main(string[] args) {
        var cancelSource = new CancellationTokenSource();
        var listener = new TcpListener(new IPEndPoint(IPAddress.Any, UpdaterPort));
        Console.CancelKeyPress += (sender, eventArgs) => {
            try {
                listener.Stop();
                cancelSource.Cancel();
            } catch {}
        };
        try {
            listener.Start();
            while (true) {
                var client = listener.AcceptTcpClient();
                new Thread(async () => { await Negotiator.Negotiate(client, cancelSource.Token); }).Start();
            }
        } finally {
            try {
                listener.Stop();
                cancelSource.Cancel();
            } catch {}
        }
    }
}