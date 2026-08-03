using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Json.Serialization;

namespace SshKeyDeployer.Core;

public sealed class DeploymentRequest
{
    public DeploymentRequest(
        string host,
        int port,
        string username,
        string password,
        string keyPath,
        bool enableRootLogin,
        bool allowPasswordLogin)
    {
        Host = NormalizeHost(host);
        Port = port;
        Username = username?.Trim() ?? string.Empty;
        Password = password ?? string.Empty;
        KeyPath = keyPath?.Trim() ?? string.Empty;
        EnableRootLogin = enableRootLogin;
        AllowPasswordLogin = allowPasswordLogin;
    }

    public string Host { get; }

    public int Port { get; }

    public string Username { get; }

    [JsonIgnore]
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string Password { get; }

    public string KeyPath { get; }

    public bool EnableRootLogin { get; }

    public bool AllowPasswordLogin { get; }

    public override string ToString() =>
        $"{Username}@{Host}:{Port}, KeyPath={KeyPath}, Password=[redacted]";

    private static string NormalizeHost(string? host)
    {
        var value = host?.Trim() ?? string.Empty;
        return value.Length >= 2 && value[0] == '[' && value[^1] == ']'
            ? value[1..^1]
            : value;
    }
}

public sealed record ValidationError(string PropertyName, string Message);

public sealed class ValidationResult
{
    public static ValidationResult Success { get; } = new(Array.Empty<ValidationError>());

    public ValidationResult(IEnumerable<ValidationError> errors)
    {
        Errors = new ReadOnlyCollection<ValidationError>(errors.ToArray());
    }

    public bool IsValid => Errors.Count == 0;

    public IReadOnlyList<ValidationError> Errors { get; }
}

public enum DeploymentStage
{
    Validating,
    SecuringPrivateKey,
    Connecting,
    AwaitingHostKeyApproval,
    CheckingPrivileges,
    InstallingPublicKey,
    WritingSshdConfiguration,
    ValidatingSshdConfiguration,
    ReloadingSsh,
    VerifyingEffectiveConfiguration,
    VerifyingKeyLogin,
    RollingBack,
    Completed
}

public sealed record DeploymentProgress(
    DeploymentStage Stage,
    string Message,
    int Percent);

public sealed record HostKeyInfo(
    string Host,
    int Port,
    string Algorithm,
    int KeyLength,
    string Sha256Fingerprint,
    string Md5Fingerprint);

public sealed record KeyGenerationResult(
    string PrivateKeyPath,
    string PublicKeyPath,
    string PublicKey,
    string Sha256Fingerprint);

public enum RootLoginPolicy
{
    Disabled,
    PasswordAndKey,
    KeyOnly
}

public sealed record DeploymentResult(
    bool Succeeded,
    string VerifiedUsername,
    string PrivateKeyPath,
    string PublicKeyFingerprint,
    HostKeyInfo ApprovedHostKey,
    string ManagedConfigPath,
    RootLoginPolicy RootLoginPolicy,
    bool PasswordLoginAllowed,
    IReadOnlyList<string> Warnings);

public delegate Task<bool> HostKeyApprovalCallback(
    HostKeyInfo hostKey,
    CancellationToken cancellationToken);

public delegate void DeploymentProgressCallback(DeploymentProgress progress);

public sealed class DeploymentValidationException : ArgumentException
{
    public DeploymentValidationException(IReadOnlyList<ValidationError> errors)
        : base(string.Join(Environment.NewLine, errors.Select(error =>
            $"{error.PropertyName}: {error.Message}")))
    {
        Errors = errors;
    }

    public IReadOnlyList<ValidationError> Errors { get; }
}

public class DeploymentException : Exception
{
    public DeploymentException(string message, Exception? innerException = null)
        : this(message, rollbackAttempted: false, rollbackSucceeded: false, innerException)
    {
    }

    public DeploymentException(
        string message,
        bool rollbackAttempted,
        bool rollbackSucceeded,
        Exception? innerException = null)
        : base(message, innerException)
    {
        RollbackAttempted = rollbackAttempted;
        RollbackSucceeded = rollbackSucceeded;
    }

    public bool RollbackAttempted { get; }

    public bool RollbackSucceeded { get; }
}

public sealed class KeyGenerationException : Exception
{
    public KeyGenerationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
