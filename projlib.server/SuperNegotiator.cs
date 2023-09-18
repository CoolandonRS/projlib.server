using System.ComponentModel.Design;
using System.Data;
using System.Net.Http.Json;
using System.Runtime.InteropServices.ComTypes;
using System.Text.Json;
using CoolandonRS.netlib;
using CoolandonRS.netlib.Encrypted;
using CoolandonRS.projlib.server.Extensions;
using CoolandonRS.projlib.server.generics;

namespace CoolandonRS.projlib.server; 

/// <summary>
/// Negotiator for Super User / Admin commands
/// </summary>
public static class SuperNegotiator {
    // TODO more commands
    public static async Task<bool> Negotiate(AESTcpCommunicator communicator, CancellationToken cancelToken) {
        while (true) {
            cancelToken.ThrowIfCancellationRequested();
            var cmd = communicator.ReadStr().Split(' ').Select(s => s.Trim()).ToArray();
            switch (cmd[0]) {
                case "disconnect":
                    return true;
                case "demote":
                    communicator.Ack("demoted");
                    return false;
                case "makeuser":
                    communicator.Ack($"Creating {cmd[1]}", "Send rsa.pub.pem");
                    await File.WriteAllBytesAsync($"{Program.UserKeyPath}/{cmd[1]}.pub.pem", communicator.Read(), cancelToken);
                    communicator.Ack($"Created {cmd[1]}");
                    break;
                case "deluser":
                    try {
                        File.Delete($"{Program.UserKeyPath}/{cmd[1]}");
                        communicator.Ack($"Deleted {cmd[1]}");
                    } catch {
                        communicator.Nak($"Unable to delete {cmd[1]}");
                    }
                    break;
                case "makeadmin":
                    await File.AppendAllLinesAsync($"{Program.AuthPath}/yubikeys.txt", cmd[1..], cancelToken);
                    break;
                case "deladmin":
                    var contents = (await File.ReadAllLinesAsync($"{Program.AuthPath}/yubikeys.txt", cancelToken));
                    await File.WriteAllLinesAsync($"{Program.AuthPath}/yubikeys.txt", contents.Except(cmd[1..]), cancelToken);
                    break;
                case "upload":
                    var projName = cmd[1];
                    var ver = cmd[2];
                    var (unknownProj, projDetails) = Negotiator.GetProjDetails(projName, communicator, false);
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
                            projDetails = new ProjectDetails(projDetails, true) {
                                Ver = ver
                            };
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
                        var bin = communicator.Read();
                        platforms.Add(platform);
                        await File.WriteAllBytesAsync($"{Program.BinaryPath}/{projName}/{platform}", bin, cancelToken);
                        communicator.Ack($"Uploaded {platform}");
                    }
                    projDetails.SupportedPlatforms = platforms.ToArray();
                    await File.WriteAllTextAsync($"{Program.InfoPath}/{projName}.json", JsonSerializer.Serialize(projDetails), cancelToken);
                    communicator.Ack("Upload complete");
                    break;
                case "del":
                    var (found, _) = Negotiator.GetProjDetails(cmd[1], communicator);
                    if (!found) continue;
                    Directory.Delete($"{Program.BinaryPath}/{cmd[1]}", true);
                    communicator.Ack($"Deleted {cmd[1]}");
                    break;
                case "commands":
                    communicator.Ack("disconnect; demote; makeuser; deluser; makeadmin; deladmin; upload; del; commands");
                    break;
                default:
                    communicator.Nak("Unknown sudo command");
                    break;
            }
        }
    }
}