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

public enum InitialSshConnectionFailureReason
{
    AuthenticationRejected,
    TimedOut,
    NetworkUnavailable,
    Unknown
}

public sealed class InitialSshConnectionException : DeploymentException
{
    public InitialSshConnectionException(
        string host,
        int port,
        string username,
        InitialSshConnectionFailureReason reason,
        Exception innerException)
        : base(BuildMessage(host, port, username, reason), innerException)
    {
        Host = host;
        Port = port;
        Username = username;
        Reason = reason;
    }

    public string Host { get; }

    public int Port { get; }

    public string Username { get; }

    public InitialSshConnectionFailureReason Reason { get; }

    private static string BuildMessage(
        string host,
        int port,
        string username,
        InitialSshConnectionFailureReason reason) => reason switch
        {
            InitialSshConnectionFailureReason.AuthenticationRejected =>
                $"The SSH server at {host}:{port} was reached, but password authentication was rejected for account '{username}'. " +
                "Verify the account name and current account password, and confirm that password authentication is enabled for this account. " +
                "No server changes were made.",
            InitialSshConnectionFailureReason.TimedOut =>
                $"The SSH connection to {host}:{port} timed out. Verify the address, port, firewall, VPN or LAN connection, and that sshd is running. " +
                "No server changes were made.",
            InitialSshConnectionFailureReason.NetworkUnavailable =>
                $"An SSH connection to {host}:{port} could not be opened. Verify the address, port, firewall, VPN or LAN connection, and that sshd is running. " +
                "No server changes were made.",
            _ =>
                "The initial password-authenticated SSH connection failed. Verify the server address, port, account, password, and SSH service. " +
                "No server changes were made."
        };
}

public enum SudoAccessFailureReason
{
    NotAuthorized,
    CommandUnavailable,
    AuthenticationRejected
}

public sealed class SudoAccessException : DeploymentException
{
    public SudoAccessException(
        string username,
        SudoAccessFailureReason reason,
        string serverDiagnostic)
        : base(BuildMessage(username, reason))
    {
        Username = username;
        Reason = reason;
        ServerDiagnostic = serverDiagnostic;
    }

    public string Username { get; }

    public SudoAccessFailureReason Reason { get; }

    public string ServerDiagnostic { get; }

    private static string BuildMessage(
        string username,
        SudoAccessFailureReason reason) => reason switch
        {
            SudoAccessFailureReason.NotAuthorized =>
                $"SSH password login succeeded, but account '{username}' is not authorized to use sudo. " +
                "Using 'su' with the root password is different from having sudo permission. " +
                $"From a root console, run: adduser {username} sudo. Then fully sign out of '{username}', " +
                "sign in again, and retry.",
            SudoAccessFailureReason.CommandUnavailable =>
                "SSH password login succeeded, but sudo is not installed on the server. " +
                $"From a root console, run: apt-get update && apt-get install -y sudo && adduser {username} sudo. " +
                $"Then fully sign out of '{username}', sign in again, and retry.",
            SudoAccessFailureReason.AuthenticationRejected =>
                $"SSH password login succeeded, but sudo rejected the password for account '{username}'. " +
                "sudo normally requires the current account password, not the root password. " +
                "Verify 'sudo -k true' in a new login session and retry.",
            _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, null)
        };
}

public sealed class KeyGenerationException : Exception
{
    public KeyGenerationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
