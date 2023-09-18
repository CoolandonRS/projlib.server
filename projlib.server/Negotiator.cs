using System.ComponentModel.Design;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using CoolandonRS.keyring;
using CoolandonRS.keyring.Yubikey;
using CoolandonRS.netlib;
using CoolandonRS.netlib.Encrypted;
using CoolandonRS.projlib.server.Extensions;
using CoolandonRS.projlib.server.generics;

namespace CoolandonRS.projlib.server;

internal static class Negotiator {
    private const int TestLen = 64;
    public static async Task Negotiate(TcpClient client, CancellationToken cancelToken) {
        try {
            var rawPrep = await Task.Run(()  => Prepare(client), cancelToken);
            if (rawPrep.term) return;
            var (communicator, projDetails, platform, bin) = rawPrep.prep!.Value;
            while (true) {
                cancelToken.ThrowIfCancellationRequested();
                var cmd = communicator.ReadStr().Trim();
                switch (cmd) {
                    case "disconnect":
                        return;
                    case "version":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack(projDetails.Ver);
                        break;
                    case "author":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack(projDetails.Author);
                        break;
                    case "desc":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack(projDetails.Desc);
                        break;
                    case "info":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack(JsonSerializer.Serialize(projDetails, new JsonSerializerOptions()));
                        break;
                    case "sha256sum":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack(NetUtil.GetSha256Sum(bin));
                        break;
                    case "len":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack(bin.LongLength.ToString());
                        break;
                    case "binary":
                        if (DevStatus(platform, communicator)) break;
                        communicator.Ack();
                        communicator.Write(bin);
                        break;
                    case "promote":
                        if (DevStatus(platform, communicator, true)) break;
                        communicator.Ack("Send authorization");
                        var otp = communicator.ReadStr();
                        try {
                            var keys = await File.ReadAllLinesAsync($"{Program.AuthPath}/yubikeys.txt", cancelToken);
                            var api = await File.ReadAllLinesAsync($"{Program.AuthPath}/yubiapi.txt", cancelToken);
                            if (await YubiOTP.Verify(communicator.ReadStr(), (api[0], api[1]), keys)) {
                                communicator.Ack("Promoted");
                                if (await SuperNegotiator.Negotiate(communicator, cancelToken)) return;
                            } else {
                                communicator.Nak("Unauthorized");
                            }
                        } catch (YubicoErrorException e) {
                            communicator.Nak($"{e.Message}");
                        } catch (DiscrepancyException e) {
                            communicator.Nak("Auth Discrepancy");
                        }
                        break;
                    case "commands":
                        communicator.Ack($"disconnect; {(DevStatus(platform) ? "promote; " : "version; author; desc; info; sha256sum; len; truelen; binary; ")} commands");
                        break;
                    default:
                        communicator.Nak("Unknown command");
                        break;
                }
            }
        } catch (Exception e) {
            // Suppress Errors, except when canceled
            if (e is OperationCanceledException) throw;
        } finally {
            try {
                client.Close();
            } catch {
                // Client already dead, so we aren't able to close. This means we are fine to terminate.
            }
        }
    }

    private static (bool term, (AESTcpCommunicator communicator, ProjectDetails projectDetails, string platform, byte[] bin)? prep) Prepare(TcpClient client) {
        var communicator = EncryptedUtil.AuthToAESServer(client, new RSAUtil(KeyType.Private, Program.PemData), str => {
            try {
                return new RSAUtil(KeyType.Public, File.ReadAllText($"{Program.UserKeyPath}/{str}.pub.pem"));
            } catch {
                return null;
            }
        });
        if (communicator == null) return (true, null);
        if (!VerifyVer(communicator)) {
            communicator.Nak("Incompatible version or invalid string", "Terminating Connection");
            return (true, null);
        }
        communicator.Ack("Version verified", "Post projName");

        var projName = communicator.ReadStr();
        if (projName == "listAll") {
            communicator.Ack("Now sending all project names and disconnecting");
            communicator.WriteStr(string.Join('\n', Directory.GetFiles(Program.InfoPath).Select(Path.GetFileNameWithoutExtension).ToArray()));
            return (true, null);
        }

        ProjectDetails projDetails;
        if (projName != "dev") {
            var rawProj = GetProjDetails(projName, communicator);
            if (rawProj.term) return (true, null);
            projDetails = rawProj.projDetails!;
        } else {
            projDetails = new ProjectDetails("", "", "", new []{"dev"});
        }

        communicator.Ack("Project Loaded", "Send platform.");
        var platform = communicator.ReadStr();
        byte[] bin;
        byte[] encryptedBin;
        if (projDetails.SupportedPlatforms.Contains(platform)) {
            communicator.Nak("Unknown or unsupported platform");
            return (true, null);
        }
        if (platform == "dev") {
            communicator.Ack("Dev mode enabled", "sha256sum, len, truelen, and binary aren't supported");
            bin = Array.Empty<byte>();
        } else {
            communicator.Ack("Platform registered", "Now accepting commands");
            bin = File.ReadAllBytes($"{Program.BinaryPath}/{projName}/{platform}");
        }

        return (false, (communicator, projDetails, platform, bin));
    }

    internal static (bool term, ProjectDetails? projDetails) GetProjDetails(string projName, AESTcpCommunicator communicator, bool write = true) {
        if (!File.Exists($"{Program.InfoPath}/{projName}.json")) {
            if (write) communicator.Nak("Unknown Project");
            return (true, null);
        }
        var projDetails = JsonSerializer.Deserialize<ProjectDetails>(File.ReadAllText($"{Program.InfoPath}/{projName}.json"));
        if (projDetails != null) return (false, projDetails);
        if (write) communicator.Nak("Unknown Project");
        return (true, null);
    }

    /// <summary>
    /// Checks if in dev mode
    /// </summary>
    /// <param name="platform">Platform. If "dev", program is in dev mode.</param>
    /// <param name="communicator">Optional. If provided, will write a NAK</param>
    /// <param name="desired">Desired State</param>
    /// <returns>desired if in project mode, !desired if in dev mode</returns>
    private static bool DevStatus(string platform, TcpCommunicator? communicator = null, bool desired = false) {
        if (platform != "dev") return desired;
        communicator?.Nak($"Unsupported in {(desired ? "project" : "dev")} mode");
        return !desired;
    }

    private static bool VerifyVer(TcpCommunicator communicator) {
        try {
            var ver = new SemVer(communicator.ReadStr());
            return Program.SerVer.IsCompatibleWith(ver);
        } catch {
            return false;
        }
    }
}