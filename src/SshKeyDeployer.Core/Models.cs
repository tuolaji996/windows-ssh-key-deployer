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
        bool allowPasswordLogin,
        string? rootPassword = null,
        int? newSshPort = null)
    {
        Host = NormalizeHost(host);
        Port = port;
        Username = username?.Trim() ?? string.Empty;
        Password = password ?? string.Empty;
        KeyPath = keyPath?.Trim() ?? string.Empty;
        EnableRootLogin = enableRootLogin;
        AllowPasswordLogin = allowPasswordLogin;
        RootPassword = string.IsNullOrEmpty(rootPassword) ? null : rootPassword;
        NewSshPort = newSshPort;
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

    /// <summary>
    /// Root password, used only with su when the account cannot use sudo. Never logged.
    /// </summary>
    [JsonIgnore]
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public string? RootPassword { get; }

    /// <summary>
    /// Move sshd to this port (verified before the old port is closed); null keeps the current port.
    /// </summary>
    public int? NewSshPort { get; }

    /// <summary>
    /// The account whose key login is verified at the end of the deployment.
    /// </summary>
    public string TargetUsername => EnableRootLogin ? "root" : Username;

    public override string ToString() =>
        $"{Username}@{Host}:{Port}, KeyPath={KeyPath}, Password=[redacted], " +
        $"RootPassword={(RootPassword is null ? "none" : "[redacted]")}, " +
        $"NewSshPort={(NewSshPort is int port ? port.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unchanged")}";

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
    /// <summary>Detecting privileges, OS release, package manager, init system, firewall, SELinux.</summary>
    InspectingServer,
    AwaitingPlanApproval,
    /// <summary>Installing missing packages and/or granting temporary sudo through su.</summary>
    PreparingPrivileges,
    CheckingPrivileges,
    InstallingPublicKey,
    WritingSshdConfiguration,
    ValidatingSshdConfiguration,
    ReloadingSsh,
    VerifyingEffectiveConfiguration,
    /// <summary>Opening the new port (firewall, SELinux), verifying it, then closing the old one.</summary>
    ChangingPort,
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
    IReadOnlyList<string> Warnings,
    ServerInfo? Server,
    int SshPort);

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
        : this(username, reason, serverDiagnostic, LinuxFamily.Debian)
    {
    }

    public SudoAccessException(
        string username,
        SudoAccessFailureReason reason,
        string serverDiagnostic,
        LinuxFamily family)
        : base(BuildMessage(username, reason, family))
    {
        Username = username;
        Reason = reason;
        ServerDiagnostic = serverDiagnostic;
        Family = family;
    }

    public string Username { get; }

    public SudoAccessFailureReason Reason { get; }

    public string ServerDiagnostic { get; }

    public LinuxFamily Family { get; }

    private static string BuildMessage(
        string username,
        SudoAccessFailureReason reason,
        LinuxFamily family)
    {
        const string rootPasswordAlternative =
            " Alternatively, enter the root password in the 'Root password' field: the tool then uses su to grant " +
            "temporary sudo for this deployment and removes it afterwards.";
        return reason switch
        {
            SudoAccessFailureReason.NotAuthorized =>
                $"SSH password login succeeded, but account '{username}' is not authorized to use sudo. " +
                "Using 'su' with the root password is different from having sudo permission. " +
                $"From a root console, run: {string.Join(" ; ", PrivilegeGuidance.GetSudoSetupCommands(family, username, sudoInstalled: true))}. " +
                $"Then fully sign out of '{username}', sign in again, and retry." +
                rootPasswordAlternative,
            SudoAccessFailureReason.CommandUnavailable =>
                "SSH password login succeeded, but sudo is not installed on the server. " +
                $"From a root console, run: {string.Join(" ; ", PrivilegeGuidance.GetSudoSetupCommands(family, username, sudoInstalled: false))}. " +
                $"Then fully sign out of '{username}', sign in again, and retry." +
                rootPasswordAlternative,
            SudoAccessFailureReason.AuthenticationRejected =>
                $"SSH password login succeeded, but sudo rejected the password for account '{username}'. " +
                "sudo normally requires the current account password, not the root password. " +
                "Verify 'sudo -k true' in a new login session and retry." +
                rootPasswordAlternative,
            _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, null)
        };
    }
}

public enum PrivilegeFailureReason
{
    /// <summary>No sudo rights and no root password was given.</summary>
    NoPrivilege,
    /// <summary>su rejected the root password.</summary>
    RootPasswordRejected,
    /// <summary>su is missing or not permitted for this account.</summary>
    SuUnavailable
}

public sealed class PrivilegeException : DeploymentException
{
    public PrivilegeException(
        string username,
        PrivilegeFailureReason reason,
        LinuxFamily family,
        string osName,
        bool sudoInstalled,
        string serverDiagnostic = "")
        : base(BuildMessage(username, reason, family, osName, sudoInstalled))
    {
        Username = username;
        Reason = reason;
        Family = family;
        OsName = osName;
        SudoInstalled = sudoInstalled;
        ServerDiagnostic = serverDiagnostic;
    }

    public string Username { get; }

    public PrivilegeFailureReason Reason { get; }

    public LinuxFamily Family { get; }

    public string OsName { get; }

    public bool SudoInstalled { get; }

    public string ServerDiagnostic { get; }

    private static string BuildMessage(
        string username,
        PrivilegeFailureReason reason,
        LinuxFamily family,
        string osName,
        bool sudoInstalled) => reason switch
        {
            PrivilegeFailureReason.NoPrivilege =>
                $"SSH password login succeeded on {osName}, but account '{username}' cannot run commands as root: " +
                (sudoInstalled ? "it has no working sudo access" : "sudo is not installed") +
                " and no root password was entered. Either enter the root password in the 'Root password' field " +
                "(the tool then uses su to grant temporary sudo and removes it afterwards), or from a root console run: " +
                $"{string.Join(" ; ", PrivilegeGuidance.GetSudoSetupCommands(family, username, sudoInstalled))}. " +
                $"Then fully sign out of '{username}', sign in again, and retry. No server changes were made.",
            PrivilegeFailureReason.RootPasswordRejected =>
                "su rejected the root password. Enter the password of the root account (not the password of " +
                $"'{username}') and retry. No server changes were made.",
            PrivilegeFailureReason.SuUnavailable =>
                $"su is not available or not permitted for account '{username}' on {osName}, so the root password " +
                "cannot be used. Grant the account sudo from a root console instead: " +
                $"{string.Join(" ; ", PrivilegeGuidance.GetSudoSetupCommands(family, username, sudoInstalled))}. " +
                "No server changes were made.",
            _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, null)
        };
}

public enum UnsupportedServerReason
{
    /// <summary>The main sshd_config does not load /etc/ssh/sshd_config.d/*.conf.</summary>
    SshdConfigWithoutInclude,
    /// <summary>/etc/sudoers does not include /etc/sudoers.d, so temporary sudo cannot be granted.</summary>
    SudoersWithoutIncludeDir
}

public sealed class UnsupportedServerException : DeploymentException
{
    public const string RequiredSshdIncludeLine = "Include /etc/ssh/sshd_config.d/*.conf";
    public const string RequiredSudoersIncludeLine = "@includedir /etc/sudoers.d";

    public UnsupportedServerException(UnsupportedServerReason reason, string configPath)
        : base(BuildMessage(reason, configPath))
    {
        Reason = reason;
        ConfigPath = configPath;
    }

    public UnsupportedServerReason Reason { get; }

    public string ConfigPath { get; }

    public string RequiredLine => Reason == UnsupportedServerReason.SshdConfigWithoutInclude
        ? RequiredSshdIncludeLine
        : RequiredSudoersIncludeLine;

    private static string BuildMessage(UnsupportedServerReason reason, string configPath) => reason switch
    {
        UnsupportedServerReason.SshdConfigWithoutInclude =>
            $"{configPath} does not load /etc/ssh/sshd_config.d, so the managed SSH policy would be ignored. " +
            $"Add this line at the top of {configPath} as root, check it with 'sshd -t', then retry: " +
            $"{RequiredSshdIncludeLine}. The tool never edits the main sshd_config. No server changes were made.",
        UnsupportedServerReason.SudoersWithoutIncludeDir =>
            $"{configPath} does not include /etc/sudoers.d, so temporary sudo cannot be granted through su. " +
            $"Add this line with 'visudo' as root, then retry: {RequiredSudoersIncludeLine}. No server changes were made.",
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, null)
    };
}

public sealed class PlanRejectedException : DeploymentException
{
    public PlanRejectedException()
        : base("The deployment plan was not approved. No server changes were made.")
    {
    }
}

public sealed class KeyGenerationException : Exception
{
    public KeyGenerationException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
