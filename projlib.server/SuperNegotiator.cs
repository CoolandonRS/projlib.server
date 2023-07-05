using System.Data;
using System.Text.Json;
using CoolandonRS.netlib;
using CoolandonRS.projlib.server.Extensions;
using CoolandonRS.projlib.server.generics;

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
                    communicator.Ack("demoted");
                    return false;
                case "makeadmin":
                    await File.AppendAllLinesAsync($"{Program.AuthPath}/yubikeys.txt", cmd[1..], cancelToken);
                    break;
                case "upload":
                    var projName = cmd[1];
                    var ver = cmd[2];
                    var (unknownProj, projDetails) = Negotiator.GetProjDetails(projName, communicator);
                    switch (unknownProj) {
                        case false when new SemVer(projDetails!.Ver).IsBetaComparedTo(new SemVer(ver)):
                            communicator.Nak("Attempting to upload outdated version");
                            continue;
                        case true:
                            communicator.Ack("Creating new project", "Send author(s)");
                            var author = communicator.ReadStr();
                            if (author == "cancel") {
                                communicator.Ack("Canceled");
                                continue;
                            }
                            communicator.Ack($"Author {author}", "Send desc");
                            var desc = communicator.ReadStr();
                            if (desc == "cancel") {
                                communicator.Ack("Canceled");
                                continue;
                            }
                            communicator.Ack($"Desc {desc}");
                            projDetails = new ProjectDetails(ver, author, desc, Array.Empty<string>(), true);
                            Directory.CreateDirectory($"{Program.BinaryPath}/{projName}");
                            break;
                        default:
                            projDetails = new ProjectDetails(projDetails, true);
                            projDetails.Ver = ver;
                            foreach (var file in Directory.GetFiles($"{Program.BinaryPath}/{projName}")) File.Delete(file);
                            break;
                    }
                    var platforms = new List<string>();
                    communicator.Ack("Wiped", "Begin sending uploads");
                    while (true) {
                        var upload = communicator.ReadStr().Split(' ').Select(s => s.Trim()).ToArray();
                        var platform = upload[0];
                        if (platform == "done") break;
                        var len = int.Parse(upload[1]);
                        if (!NetUtil.IsPlatformIdentifier(platform)) {
                            communicator.Nak("Not a platform");
                            continue;
                        } else if (platforms.Contains(platform)) {
                            communicator.Nak("Duplicate platform");
                            continue;
                        }
                        var bin = communicator.ReadN(len);
                        platforms.Add(platform);
                        await File.WriteAllBytesAsync($"{Program.BinaryPath}/{projName}/{platform}", bin, cancelToken);
                        communicator.Ack($"Uploaded {platform}");
                    }
                    projDetails.SupportedPlatforms = platforms.ToArray();
                    await File.WriteAllTextAsync($"{Program.InfoPath}/{projName}.json", JsonSerializer.Serialize(projDetails), cancelToken);
                    communicator.Ack("Upload complete");
                    break;
                case "commands":
                    communicator.Ack("disconnect; demote; makeadmin; upload; commands");
                    break;
                default:
                    communicator.Nak("Unknown sudo command");
                    break;
            }
        }
    }
}