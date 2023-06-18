using netlib;

namespace CoolandonRS.projlib.server; 

/// <summary>
/// Negotiator for Super User / Admin commands
/// </summary>
public static class SuperNegotiator {
    // TODO more commands
    public static async Task<bool> Negotiate(TcpRsaCommunicator communicator, CancellationToken cancelToken) {
        while (true) {
            cancelToken.ThrowIfCancellationRequested();
            var cmd = communicator.ReadStr().Split(' ').Select(s => s.Trim()).ToArray();
            switch (cmd[0]) {
                case "disconnect":
                    return true;
                case "demote":
                    communicator.WriteStr("ACK: demoted");
                    return false;
                case "makeadmin":
                    await File.AppendAllLinesAsync($"{Program.AuthPath}/yubikeys.txt", cmd[1..], cancelToken);
                    break;
                case "commands":
                    communicator.WriteStr("ACK: disconnect; demote; makeadmin; commands");
                    break;
                default:
                    communicator.WriteStr("NAK: Unknown sudo command");
                    break;
            }
        }
    }
}