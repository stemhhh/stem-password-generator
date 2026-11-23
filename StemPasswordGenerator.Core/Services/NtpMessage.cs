namespace StemPasswordGenerator.Services;

public static class NtpMessage
{
    public const int PacketSize = 48;

    private static readonly DateTimeOffset NtpEpoch = new(1900, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static byte[] Request()
    {
        var packet = new byte[PacketSize];
        packet[0] = 0x23;
        return packet;
    }

    public static bool TryParseTransmitUtc(ReadOnlySpan<byte> packet, out DateTimeOffset utc)
    {
        utc = default;
        if (packet.Length < PacketSize)
        {
            return false;
        }

        var seconds = ReadUInt32BigEndian(packet, 40);
        var fraction = ReadUInt32BigEndian(packet, 44);
        if (seconds == 0)
        {
            return false;
        }

        var millis = fraction * 1000.0 / uint.MaxValue;
        utc = NtpEpoch.AddSeconds(seconds).AddMilliseconds(millis);
        if (utc.Year is < 2020 or > 2100)
        {
            return false;
        }

        return true;
    }

    public static void WriteTransmitUtc(Span<byte> packet, DateTimeOffset utc)
    {
        utc = utc.ToUniversalTime();
        var delta = utc - NtpEpoch;
        var seconds = (uint)delta.TotalSeconds;
        var fraction = (uint)((delta.TotalSeconds - seconds) * uint.MaxValue);
        WriteUInt32BigEndian(packet, 40, seconds);
        WriteUInt32BigEndian(packet, 44, fraction);
    }

    private static uint ReadUInt32BigEndian(ReadOnlySpan<byte> packet, int offset) =>
        ((uint)packet[offset] << 24)
        | ((uint)packet[offset + 1] << 16)
        | ((uint)packet[offset + 2] << 8)
        | packet[offset + 3];

    private static void WriteUInt32BigEndian(Span<byte> packet, int offset, uint value)
    {
        packet[offset] = (byte)(value >> 24);
        packet[offset + 1] = (byte)(value >> 16);
        packet[offset + 2] = (byte)(value >> 8);
        packet[offset + 3] = (byte)value;
    }
}
