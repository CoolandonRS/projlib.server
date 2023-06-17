using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using netlib;

namespace CoolandonRS.projlib.server;

internal static class Negotiator {
    private const int TestLen = 64;
    public static void Negotiate(TcpClient client) {
        try {
            var rawPrep = Prepare(client);
            if (rawPrep.term) return;
            var (communicator, projDetails, platform, bin, encryptedBin) = rawPrep.prep!.Value;
            while (true) {
                var cmd = communicator.ReadStr();
                switch (cmd) {
                    case "disconnect":
                        return;
                    case "version":
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, projDetails.Ver);
                        break;
                    case "author":
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, projDetails.Author);
                        break;
                    case "desc":
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, projDetails.Desc);
                        break;
                    case "info":
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, JsonSerializer.Serialize(projDetails, new JsonSerializerOptions()));
                        break;
                    case "sha256sum":
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, NetUtil.GetSha256Sum(bin));
                        break;
                    case "len":
                        // NOTE: Provides length of ENCRYPTED binary, not the actual binary. That's what "truelen" is for.
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, encryptedBin.LongLength.ToString());
                        break;
                    case "truelen":
                        if (InDevMode(platform, communicator)) break;
                        AckWithData(communicator, bin.LongLength.ToString());
                        break;
                    case "binary":
                        if (InDevMode(platform, communicator)) break;
                        communicator.WriteStr("ACK");
                        communicator.Write(encryptedBin);
                        break;
                    case "promote":
                        communicator.WriteStr("ACK: Send authorization");
                        var authToken = communicator.ReadStr();
                        // TODO (implement in keyring, use here)
                        break;
                    default:
                        communicator.WriteStr("NAK: Unknown command");
                        break;
                }
                break;
            }
        } catch {
            // Suppress Errors
        } finally {
            try {
                client.Close();
            } catch {
                // Client already dead, so we aren't able to close. This means we are fine to terminate.
            }
        }
    }

    private static (bool term, (TcpRsaCommunicator communicator, ProjectDetails projectDetails, string platform, byte[] bin, byte[] encryptedBin)? prep) Prepare(TcpClient client) {
        var outPemData = Login(client);
        if (outPemData == null) return (true, null);
        var communicator = new TcpRsaCommunicator(client, Program.PemData, outPemData);
        if (!VerifyVer(communicator)) {
            communicator.WriteStr("NAK: Incompatible version or invalid string.\nTerminating Connection.");
            return (true, null);
        }
        communicator.WriteStr("ACK: Version verified. Post projName");

        var projName = communicator.ReadStr();
        if (projName == "listAll") {
            communicator.WriteStr("ACK: Now sending all project names and disconnecting");
            communicator.WriteStr(string.Join('\n', Directory.GetFiles(Program.InfoPath).Select(Path.GetFileNameWithoutExtension).ToArray()));
            return (true, null);
        }

        ProjectDetails projDetails;
        if (projName != "dev") {
            var rawProj = GetProjDetails(projName, communicator);
            if (rawProj.term) return (true, null);
            projDetails = rawProj.projDetails!;
        } else {
            projDetails = new ProjectDetails();
        }

        communicator.WriteStr("ACK: Project Loaded. Send platform.");
        var platform = communicator.ReadStr();
        byte[] bin;
        byte[] encryptedBin;
        if (!(projDetails.SupportedPlatforms.Contains(platform)) && platform != "dev") {
            communicator.WriteStr("NAK: Unknown or unsupported platform");
            return (true, null);
        }
        if (platform == "dev") {
            communicator.WriteStr("ACK: Dev mode enabled. sha256sum, len, truelen, and binary aren't supported");
            bin = Array.Empty<byte>();
            encryptedBin = bin;
        } else {
            communicator.WriteStr("ACK: Platform registered. Now accepting commands.");
            bin = File.ReadAllBytes(Program.BinaryPath + projName + "/" + platform);
            encryptedBin = communicator.GetRSAkeys().send.Encrypt(bin);
        }

        return (false, (communicator, projDetails, platform, bin, encryptedBin));
    }

    internal static (bool term, ProjectDetails? projDetails) GetProjDetails(string projName, TcpRsaCommunicator communicator) {
        if (!File.Exists(Program.InfoPath + projName + ".json")) {
            communicator.WriteStr("NAK: Unknown project");
            return (true, null);
        }
        var projDetails = JsonSerializer.Deserialize<ProjectDetails>(File.ReadAllText(Program.InfoPath + projName + ".json"));
        if (projDetails != null) return (false, projDetails);
        communicator.WriteStr("NAK: Unknown project");
        return (true, null);

    }

    /// <summary>
    /// Checks if in dev mode
    /// </summary>
    /// <param name="platform">Platform. If "dev", program is in dev mode.</param>
    /// <param name="communicator">Optional. If provided, will write a NAK</param>
    /// <returns>If in dev mode</returns>
    private static bool InDevMode(string platform, TcpCommunicator? communicator = null) {
        if (platform != "dev") return false;
        communicator?.WriteStr("NAK: Unsupported in dev mode");
        return true;
    }

    private static string? Login(TcpClient client) {
        // Do not close Communicators used in Login, as that would close the client, which we wish to reuse.
        // (Plus, its not like closing the communicators actually does much besides closing the client)
        var tempCommunicator = new TcpRsaCommunicator(client, Program.PemData, "");
        var name = tempCommunicator.ReadStr();
        var testPemData = File.ReadAllText(Program.UserKeyPath + name + ".pub.pem");
        var testCommunicator = new TcpRsaCommunicator(client, Program.PemData, testPemData);
        var confirmData = Convert.ToBase64String(RandomNumberGenerator.GetBytes(TestLen));
        testCommunicator.WriteStr(confirmData);
        if (testCommunicator.ReadStr() != confirmData) return null;
        testCommunicator.WriteStr("ACK: Verified. Post updater version.");
        testCommunicator.Close();
        return testPemData;
    }

    private static bool VerifyVer(TcpCommunicator communicator) {
        try {
            var ver = new SemVer(communicator.ReadStr());
            return Program.SerVer.IsCompatibleWith(ver);
        } catch {
            return false;
        }
    }

    /// <summary>
    /// Sends "ACK: [data]"
    /// </summary>
    /// <param name="communicator">Communicator to send to</param>
    /// <param name="data">Value of [data]</param>
    internal static void AckWithData(TcpCommunicator communicator, string data) {
        communicator.WriteStr("ACK: " + data);
    }
}