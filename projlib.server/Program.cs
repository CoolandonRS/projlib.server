using System.Net;
using System.Net.Sockets;
using netlib;

namespace CoolandonRS.projlib.server;

internal static class Program {
    public const int UpdaterPort = 1248;
    internal const string UserKeyPath = "./keys/";
    internal const string BinaryPath = "./bin/";
    internal const string InfoPath = "./info/";
    internal static readonly string PemData = File.ReadAllText("./server.key.pem");
    internal static readonly SemVer SerVer = new(1, 0, 0);

    public static void Main(string[] args) {
        var listener = new TcpListener(new IPEndPoint(IPAddress.Any, UpdaterPort));
        try {
            listener.Start();
            while (true) {
                var client = listener.AcceptTcpClient();
                new Thread(() => { Negotiator.Negotiate(client); }).Start();
            }
        } finally {
            listener.Stop();
        }
    }
}