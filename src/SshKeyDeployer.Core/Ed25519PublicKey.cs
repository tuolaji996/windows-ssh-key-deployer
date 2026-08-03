using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SshKeyDeployer.Core;

internal sealed partial record Ed25519PublicKey(
    string NormalizedText,
    string KeyData,
    string Sha256Fingerprint)
{
    private const int MaximumPublicKeyFileLength = 16 * 1024;

    public static Ed25519PublicKey Read(string path)
    {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("Public-key file was not found.", path);
        }

        if (fileInfo.Length > MaximumPublicKeyFileLength)
        {
            throw new InvalidDataException("Public-key file is unexpectedly large.");
        }

        return Parse(File.ReadAllText(path, Encoding.UTF8));
    }

    public static Ed25519PublicKey Parse(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var match = PublicKeyRegex().Match(value.Trim());
        if (!match.Success)
        {
            throw new InvalidDataException(
                "Public key must contain exactly one OpenSSH Ed25519 public key.");
        }

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(match.Groups[1].Value);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("Public-key data is not valid base64.", exception);
        }

        ValidateBlob(blob);
        var keyData = Convert.ToBase64String(blob);
        var fingerprintBytes = SHA256.HashData(blob);
        var fingerprint = Convert.ToBase64String(fingerprintBytes).TrimEnd('=');
        return new Ed25519PublicKey(
            $"ssh-ed25519 {keyData} ssh-key-deployer",
            keyData,
            $"SHA256:{fingerprint}");
    }

    private static void ValidateBlob(ReadOnlySpan<byte> blob)
    {
        var offset = 0;
        var algorithm = ReadSshString(blob, ref offset);
        var publicKey = ReadSshString(blob, ref offset);

        if (!algorithm.SequenceEqual("ssh-ed25519"u8) ||
            publicKey.Length != 32 ||
            offset != blob.Length)
        {
            throw new InvalidDataException("Public-key blob is not a valid Ed25519 key.");
        }
    }

    private static ReadOnlySpan<byte> ReadSshString(ReadOnlySpan<byte> source, ref int offset)
    {
        if (source.Length - offset < sizeof(uint))
        {
            throw new InvalidDataException("Public-key blob is truncated.");
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(source[offset..]);
        offset += sizeof(uint);

        if (length > int.MaxValue || source.Length - offset < (int)length)
        {
            throw new InvalidDataException("Public-key blob contains an invalid field length.");
        }

        var value = source.Slice(offset, (int)length);
        offset += (int)length;
        return value;
    }

    [GeneratedRegex(
        "^ssh-ed25519[\\t ]+([A-Za-z0-9+/]+={0,2})(?:[\\t ]+[^\\r\\n]*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex PublicKeyRegex();
}
