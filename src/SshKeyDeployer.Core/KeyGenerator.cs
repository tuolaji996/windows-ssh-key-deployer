namespace SshKeyDeployer.Core;

public sealed class KeyGenerator
{
    private readonly OpenSshTools _openSshTools;
    private readonly PrivateKeyAclProtector _aclProtector;

    public KeyGenerator()
        : this(sshKeygenPath: null, new PrivateKeyAclProtector())
    {
    }

    public KeyGenerator(string? sshKeygenPath)
        : this(sshKeygenPath, new PrivateKeyAclProtector())
    {
    }

    internal KeyGenerator(
        string? sshKeygenPath,
        PrivateKeyAclProtector aclProtector)
    {
        _openSshTools = new OpenSshTools(sshKeygenPath);
        _aclProtector = aclProtector;
    }

    public async Task<KeyGenerationResult> GenerateAsync(
        string keyPath,
        CancellationToken cancellationToken = default)
    {
        var fullPath = ValidateNewKeyPath(keyPath);
        var publicKeyPath = fullPath + ".pub";
        var parentDirectory = Path.GetDirectoryName(fullPath)
            ?? throw new KeyGenerationException("Key path must have a parent directory.");

        var parentDirectoryAlreadyExists = Directory.Exists(parentDirectory);
        Directory.CreateDirectory(parentDirectory);
        if (!parentDirectoryAlreadyExists)
        {
            _aclProtector.ProtectDirectory(parentDirectory);
        }

        if (File.Exists(fullPath) || File.Exists(publicKeyPath))
        {
            throw new KeyGenerationException(
                "The private-key path or matching .pub path already exists. Choose a new path to avoid overwriting a key.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var stagingDirectory = CreateStagingDirectory(parentDirectory);
        var stagedPrivateKeyPath = Path.Combine(stagingDirectory, "id_ed25519");
        var stagedPublicKeyPath = stagedPrivateKeyPath + ".pub";
        var privateKeyPublished = false;
        var publicKeyPublished = false;
        try
        {
            _aclProtector.ProtectDirectory(stagingDirectory);
            var result = await _openSshTools
                .GenerateEd25519Async(stagedPrivateKeyPath, cancellationToken)
                .ConfigureAwait(false);

            if (result.ExitCode != 0)
            {
                throw new KeyGenerationException(BuildFailureMessage(
                    "ssh-keygen did not generate the key.",
                    result.StandardError));
            }

            if (!File.Exists(stagedPrivateKeyPath) || !File.Exists(stagedPublicKeyPath))
            {
                throw new KeyGenerationException(
                    "ssh-keygen reported success but the private/public key pair was not created.");
            }

            _aclProtector.Protect(stagedPrivateKeyPath);
            var publicKey = Ed25519PublicKey.Read(stagedPublicKeyPath);
            await EnsureMatchingPairAsync(stagedPrivateKeyPath, publicKey, cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                // Publishing the public key first ensures a private key is never left behind
                // when a destination collision is discovered at the final boundary.
                File.Move(stagedPublicKeyPath, publicKeyPath);
                publicKeyPublished = true;

                cancellationToken.ThrowIfCancellationRequested();
                File.Move(stagedPrivateKeyPath, fullPath);
                privateKeyPublished = true;
            }
            catch (IOException exception)
            {
                throw new KeyGenerationException(
                    "The generated key could not be published without overwriting an existing file.",
                    exception);
            }
            catch (UnauthorizedAccessException exception)
            {
                throw new KeyGenerationException(
                    OperatingSystem.IsWindows()
                        ? "Windows denied access while publishing the generated key."
                        : "The operating system denied access while publishing the generated key.",
                    exception);
            }

            cancellationToken.ThrowIfCancellationRequested();
            _aclProtector.Protect(fullPath);

            return new KeyGenerationResult(
                fullPath,
                publicKeyPath,
                publicKey.NormalizedText,
                publicKey.Sha256Fingerprint);
        }
        catch
        {
            if (privateKeyPublished)
            {
                TryDelete(fullPath);
            }

            if (publicKeyPublished)
            {
                TryDelete(publicKeyPath);
            }

            throw;
        }
        finally
        {
            TryDeleteDirectory(stagingDirectory);
        }
    }

    public async Task<KeyGenerationResult> ReadExistingAsync(
        string keyPath,
        CancellationToken cancellationToken = default)
    {
        var fullPath = ValidateExistingKeyPath(keyPath);
        var publicKeyPath = fullPath + ".pub";
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            await Task.Run(
                    () => _aclProtector.Protect(fullPath),
                    cancellationToken)
                .ConfigureAwait(false);
            var publicKey = Ed25519PublicKey.Read(publicKeyPath);
            await EnsureMatchingPairAsync(fullPath, publicKey, cancellationToken)
                .ConfigureAwait(false);

            return new KeyGenerationResult(
                fullPath,
                publicKeyPath,
                publicKey.NormalizedText,
                publicKey.Sha256Fingerprint);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (KeyGenerationException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new KeyGenerationException(
                "The existing private/public key pair could not be validated.",
                exception);
        }
    }

    internal async Task EnsureMatchingPairAsync(
        string privateKeyPath,
        Ed25519PublicKey publicKey,
        CancellationToken cancellationToken)
    {
        var result = await _openSshTools
            .DerivePublicKeyAsync(privateKeyPath, cancellationToken)
            .ConfigureAwait(false);

        if (result.ExitCode != 0)
        {
            throw new KeyGenerationException(BuildFailureMessage(
                OperatingSystem.IsWindows()
                    ? "The private key could not be read by Windows OpenSSH. Only an unencrypted Ed25519 key is supported."
                    : "The private key could not be read by OpenSSH. Only an unencrypted Ed25519 key is supported.",
                result.StandardError));
        }

        Ed25519PublicKey derived;
        try
        {
            derived = Ed25519PublicKey.Parse(result.StandardOutput);
        }
        catch (InvalidDataException exception)
        {
            throw new KeyGenerationException(
                "The private key is not an Ed25519 OpenSSH key.",
                exception);
        }

        if (!string.Equals(derived.KeyData, publicKey.KeyData, StringComparison.Ordinal))
        {
            throw new KeyGenerationException(
                "The .pub file does not match the selected private key.");
        }
    }

    private static string ValidateNewKeyPath(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(keyPath.Trim());
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new KeyGenerationException("Key path is invalid.", exception);
        }

        if (!Path.IsPathFullyQualified(keyPath))
        {
            throw new KeyGenerationException("Key path must be absolute.");
        }

        if (fullPath.EndsWith(".pub", StringComparison.OrdinalIgnoreCase))
        {
            throw new KeyGenerationException("Choose a private-key path without the .pub suffix.");
        }

        if (PrivateKeyPathPolicy.IsUnsupportedWindowsNetworkPath(fullPath))
        {
            throw new KeyGenerationException(
                PrivateKeyPathPolicy.WindowsNetworkPathErrorMessage);
        }

        return fullPath;
    }

    private static string ValidateExistingKeyPath(string keyPath)
    {
        var fullPath = ValidateNewKeyPath(keyPath);
        if (!File.Exists(fullPath) || !File.Exists(fullPath + ".pub"))
        {
            throw new KeyGenerationException(
                "Both the private key and matching .pub file must exist.");
        }

        return fullPath;
    }

    private static string BuildFailureMessage(string summary, string diagnostic) =>
        string.IsNullOrWhiteSpace(diagnostic)
            ? summary
            : $"{summary} {diagnostic}";

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string CreateStagingDirectory(string parentDirectory)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var stagingDirectory = Path.Combine(
                parentDirectory,
                $".ssh-key-deployer-{Guid.NewGuid():N}");
            if (File.Exists(stagingDirectory) || Directory.Exists(stagingDirectory))
            {
                continue;
            }

            try
            {
                Directory.CreateDirectory(stagingDirectory);
                return stagingDirectory;
            }
            catch (IOException) when (
                File.Exists(stagingDirectory) || Directory.Exists(stagingDirectory))
            {
            }
        }

        throw new KeyGenerationException(
            "A unique staging directory for SSH key generation could not be created.");
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
