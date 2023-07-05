using CoolandonRS.netlib;

namespace CoolandonRS.projlib.server.Extensions; 

public static class TcpCommunicatorExtensions {
    public static void Ack(this TcpCommunicator communicator) => communicator.WriteStr("ACK");
    public static void Nak(this TcpCommunicator communicator) => communicator.WriteStr("NAK");
    public static void Ack(this TcpCommunicator communicator, string data) => communicator.WriteStr($"ACK: {data}");
    public static void Nak(this TcpCommunicator communicator, string data) => communicator.WriteStr($"NAK: {data}");

    public static void Ack(this TcpCommunicator communicator, params string[] data) => communicator.WriteStr($"ACK: {string.Join(". ", data)}.");
    public static void Nak(this TcpCommunicator communicator, params string[] data) => communicator.WriteStr($"NAK: {string.Join(". ", data)}.");
}