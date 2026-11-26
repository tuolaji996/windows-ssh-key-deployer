using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace SshKeyDeployer.Core;

public sealed class DeploymentService
{
    public const string ManagedConfigPath = "/etc/ssh/sshd_config.d/00-ssh-key-deployer.conf";

    private const string SshdPath = "/usr/sbin/sshd";
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RecoveryTimeout = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan PackageTimeout = TimeSpan.FromMinutes(20);
    private static readonly TimeSpan SelinuxTimeout = TimeSpan.FromMinutes(5);

    private readonly PrivateKeyAclProtector _aclProtector;
    private readonly KeyGenerator _keyGenerator;

    public DeploymentService()
        : this(new PrivateKeyAclProtector(), new KeyGenerator())
    {
    }

    internal DeploymentService(
        PrivateKeyAclProtector aclProtector,
        KeyGenerator keyGenerator)
    {
        _aclProtector = aclProtector;
        _keyGenerator = keyGenerator;
    }

    public Task<DeploymentResult> DeployAsync(
        DeploymentRequest request,
        HostKeyApprovalCallback hostKeyApproval,
        DeploymentProgressCallback? progress = null,
        CancellationToken cancellationToken = default) =>
        DeployAsync(
            request,
            hostKeyApproval,
            static (_, _) => Task.FromResult(true),
            progress,
            cancellationToken);

    public async Task<DeploymentResult> DeployAsync(
        DeploymentRequest request,
        HostKeyApprovalCallback hostKeyApproval,
        PlanApprovalCallback planApproval,
        DeploymentProgressCallback? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(hostKeyApproval);
        ArgumentNullException.ThrowIfNull(planApproval);

        var reporter = new ProgressReporter(progress, SynchronizationContext.Current);
        reporter.Report(DeploymentStage.Validating, "Validating deployment settings...", 2);
        DeploymentRequestValidator.EnsureValid(request);
        cancellationToken.ThrowIfCancellationRequested();

        var privateKeyPath = Path.GetFullPath(request.KeyPath);
        Ed25519PublicKey publicKey;
        try
        {
            publicKey = Ed25519PublicKey.Read(privateKeyPath + ".pub");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new DeploymentException("The Ed25519 public key could not be read.", exception);
        }

        reporter.Report(DeploymentStage.SecuringPrivateKey, "Securing the private key...", 6);
        try
        {
            await Task.Run(
                    () => _aclProtector.Protect(privateKeyPath),
                    cancellationToken)
                .ConfigureAwait(false);
            await _keyGenerator
                .EnsureMatchingPairAsync(privateKeyPath, publicKey, cancellationToken)
                .ConfigureAwait(false);

            // Validate SSH.NET compatibility before making any server-side change.
            using var ignored = new PrivateKeyFile(privateKeyPath);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DeploymentException(
                "The selected private/public key pair is not a usable unencrypted Ed25519 key.",
                exception);
        }

        reporter.Report(DeploymentStage.Connecting, "Connecting with password authentication...", 10);
        using var passwordClient = CreatePasswordClient(request);
        var approvedHostKey = await ConnectWithApprovalAsync(
                passwordClient,
                request,
                hostKeyApproval,
                reporter,
                cancellationToken)
            .ConfigureAwait(false);

        var targetUsername = request.TargetUsername;
        var state = new DeploymentState(
            targetUsername,
            backupPath: $"/etc/ssh/sshd_config.d/.ssh-key-deployer-backup-{Guid.NewGuid():N}");

        try
        {
            var server = await InspectServerAsync(
                    passwordClient,
                    request,
                    state,
                    reporter,
                    cancellationToken)
                .ConfigureAwait(false);

            var packages = ServerInspection.GetRequiredPackages(
                server.Privilege,
                server.SudoInstalled,
                server.Family,
                server.PackageManager,
                request.NewSshPort is not null,
                server.SelinuxEnforcing,
                state.SemanageInstalled);
            var plan = ServerInspection.BuildPlan(server, request, packages);

            reporter.Report(DeploymentStage.AwaitingPlanApproval, "Review and approve the deployment plan.", 18);
            var approved = await reporter
                .InvokeOnContextAsync(() => planApproval(plan, cancellationToken))
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            if (!approved)
            {
                throw new PlanRejectedException();
            }

            await PreparePrivilegesAsync(
                    passwordClient,
                    request,
                    state,
                    packages,
                    reporter,
                    cancellationToken)
                .ConfigureAwait(false);

            await RunCheckedAsync(
                    passwordClient,
                    "locating the OpenSSH server",
                    $"test -x {SshdPath}",
                    request.Password,
                    standardInput: null,
                    runAsRoot: true,
                    state.SessionIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);

            state.ConnectionContext = await ReadConnectionContextAsync(
                    passwordClient,
                    request,
                    cancellationToken)
                .ConfigureAwait(false);

            reporter.Report(DeploymentStage.InstallingPublicKey, "Installing the public key...", 32);
            var currentUserIsRoot = request.Username.Equals("root", StringComparison.Ordinal);
            state.CurrentUserIsRoot = currentUserIsRoot;
            state.CurrentUserKeySnapshotMayExist = true;
            await PrepareAuthorizedKeysBackupAsync(
                    passwordClient,
                    state.CurrentUserKeyBackupPath,
                    state,
                    request.Password,
                    rootTarget: currentUserIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);

            state.CurrentUserKeyMutationMayHaveStarted = true;
            await InstallPublicKeyAsync(
                    passwordClient,
                    publicKey.NormalizedText,
                    state.CurrentUserKeyBackupPath,
                    state,
                    request.Password,
                    rootTarget: currentUserIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);

            if (state.TargetUsername.Equals("root", StringComparison.Ordinal) && !state.SessionIsRoot)
            {
                state.RootKeySnapshotMayExist = true;
                await PrepareAuthorizedKeysBackupAsync(
                        passwordClient,
                        state.RootKeyBackupPath,
                        state,
                        request.Password,
                        rootTarget: true,
                        cancellationToken)
                    .ConfigureAwait(false);

                state.RootKeyMutationMayHaveStarted = true;
                await InstallPublicKeyAsync(
                        passwordClient,
                        publicKey.NormalizedText,
                        state.RootKeyBackupPath,
                        state,
                        request.Password,
                        rootTarget: true,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            reporter.Report(
                DeploymentStage.InstallingPublicKey,
                $"Verifying key login as {request.Username} before changing sshd...",
                39);
            await VerifyKeyLoginAsync(
                    request,
                    request.Username,
                    privateKeyPath,
                    approvedHostKey,
                    request.Port,
                    cancellationToken)
                .ConfigureAwait(false);

            reporter.Report(DeploymentStage.WritingSshdConfiguration, "Writing the managed SSH configuration...", 45);
            await PrepareAndWriteConfigAsync(
                    passwordClient,
                    request,
                    state,
                    cancellationToken)
                .ConfigureAwait(false);

            reporter.Report(DeploymentStage.ValidatingSshdConfiguration, "Validating sshd syntax and effective settings...", 58);
            await ValidateSshdAsync(
                    passwordClient,
                    request,
                    state,
                    cancellationToken)
                .ConfigureAwait(false);

            reporter.Report(DeploymentStage.ReloadingSsh, "Reloading the SSH service...", 70);
            await ReloadSshAsync(
                    passwordClient,
                    request.Password,
                    state.SessionIsRoot,
                    restartSocket: false,
                    cancellationToken)
                .ConfigureAwait(false);

            reporter.Report(DeploymentStage.VerifyingEffectiveConfiguration, "Verifying effective settings after reload...", 78);
            await ValidateEffectiveSshdAsync(
                    passwordClient,
                    request,
                    state,
                    cancellationToken)
                .ConfigureAwait(false);

            reporter.Report(DeploymentStage.VerifyingKeyLogin, $"Verifying key login as {targetUsername}...", 84);
            await VerifyKeyLoginAsync(
                    request,
                    targetUsername,
                    privateKeyPath,
                    approvedHostKey,
                    request.Port,
                    cancellationToken)
                .ConfigureAwait(false);

            var warnings = new List<string>();
            var finalPort = request.Port;
            if (request.NewSshPort is int newPort)
            {
                warnings.AddRange(await ChangePortAsync(
                        passwordClient,
                        request,
                        state,
                        privateKeyPath,
                        approvedHostKey,
                        newPort,
                        reporter,
                        cancellationToken)
                    .ConfigureAwait(false));
                finalPort = newPort;
            }

            warnings.AddRange(await CommitConfigAsync(
                    passwordClient,
                    request.Password,
                    state,
                    cancellationToken)
                .ConfigureAwait(false));

            if (state.SudoersDropInMayExist)
            {
                if (await TryRemoveSudoersDropInAsync(passwordClient, request, state).ConfigureAwait(false))
                {
                    state.SudoersDropInMayExist = false;
                }
                else
                {
                    warnings.Add(
                        $"Deployment is verified, but the temporary sudo grant {state.SudoersDropInPath} could not be removed. " +
                        $"Remove it now as root: rm -f {state.SudoersDropInPath}");
                }
            }

            reporter.Report(DeploymentStage.Completed, "SSH key deployment verified.", 100);
            return new DeploymentResult(
                Succeeded: true,
                VerifiedUsername: targetUsername,
                PrivateKeyPath: privateKeyPath,
                PublicKeyFingerprint: publicKey.Sha256Fingerprint,
                ApprovedHostKey: approvedHostKey.Info,
                ManagedConfigPath: ManagedConfigPath,
                RootLoginPolicy: ServerInspection.GetRootLoginPolicy(request),
                PasswordLoginAllowed: request.AllowPasswordLogin,
                Warnings: new ReadOnlyCollection<string>(warnings),
                Server: state.Server,
                SshPort: finalPort);
        }
        catch (Exception exception)
        {
            var recovery = await RecoverAsync(
                    passwordClient,
                    request,
                    publicKey.NormalizedText,
                    state,
                    reporter)
                .ConfigureAwait(false);

            if (exception is OperationCanceledException && recovery.Succeeded)
            {
                throw;
            }

            var packageNote = state.InstalledPackages.Count > 0
                ? $" Installed packages were kept ({string.Join(", ", state.InstalledPackages)})."
                : string.Empty;

            if (!recovery.Attempted && exception is DeploymentException deploymentException && packageNote.Length == 0)
            {
                throw deploymentException;
            }

            var recoveryMessage = recovery.Attempted
                ? recovery.Succeeded
                    ? "Server changes were rolled back."
                    : $"Automatic rollback was incomplete: {recovery.Detail}"
                : "No server-side change required rollback.";
            var failureDetail = SafeExceptionMessage(exception, request);

            throw new DeploymentException(
                $"Deployment failed: {failureDetail} {recoveryMessage}{packageNote}",
                recovery.Attempted,
                recovery.Succeeded,
                exception);
        }
    }

    private static async Task<ServerInfo> InspectServerAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        ProgressReporter reporter,
        CancellationToken cancellationToken)
    {
        reporter.Report(DeploymentStage.InspectingServer, "Detecting privileges and the Linux distribution...", 16);
        var probeResult = await RunCheckedAsync(
                client,
                "inspecting the server",
                BuildShellCommand(ServerInspection.UnprivilegedProbeScript),
                request.Password,
                standardInput: null,
                runAsRoot: false,
                sessionIsRoot: false,
                cancellationToken)
            .ConfigureAwait(false);
        var probe = ServerInspection.ParseUnprivilegedProbe(probeResult.StandardOutput);
        if (probe.Uid is null)
        {
            throw new DeploymentException("The server did not report the account UID. No server changes were made.");
        }

        state.SessionIsRoot = probe.Uid == 0;
        if (request.Username.Equals("root", StringComparison.Ordinal) && !state.SessionIsRoot)
        {
            throw new DeploymentException("The remote root account did not report UID 0.");
        }

        var family = ServerInspection.DetectFamily(probe.OsId, probe.OsIdLike);
        var osName = string.IsNullOrWhiteSpace(probe.OsName)
            ? string.IsNullOrWhiteSpace(probe.OsId) ? "this server" : probe.OsId
            : probe.OsName;
        var sudoInstalled = probe.Has("sudo");
        var suInstalled = probe.Has("su");
        var rootPasswordGiven = request.RootPassword is not null;
        state.SemanageInstalled = probe.Has(ServerInspection.SemanageCommand);

        SudoCheck? sudoFailure = null;
        var sudoWorks = false;
        if (!state.SessionIsRoot && sudoInstalled)
        {
            var check = await CheckSudoAccessAsync(client, request, cancellationToken).ConfigureAwait(false);
            sudoWorks = check.Succeeded;
            if (!check.Succeeded)
            {
                sudoFailure = check;
            }
        }

        var privilege = ServerInspection.DecidePrivilege(
            state.SessionIsRoot,
            sudoWorks,
            suInstalled,
            rootPasswordGiven);

        if (privilege == PrivilegeMode.None)
        {
            if (sudoFailure is not null && sudoFailure.Reason is SudoAccessFailureReason reason)
            {
                throw new SudoAccessException(request.Username, reason, sudoFailure.Diagnostic, family);
            }

            if (sudoFailure is not null)
            {
                throw CreateRemoteCommandException("checking sudo access", sudoFailure.Result, request.Password);
            }

            throw new PrivilegeException(
                request.Username,
                rootPasswordGiven ? PrivilegeFailureReason.SuUnavailable : PrivilegeFailureReason.NoPrivilege,
                family,
                osName,
                sudoInstalled);
        }

        state.Privilege = privilege;
        state.Family = family;
        state.OsName = osName;
        state.SudoInstalled = sudoInstalled;

        reporter.Report(
            DeploymentStage.InspectingServer,
            privilege == PrivilegeMode.Su
                ? "Checking the root password with su and inspecting sshd..."
                : "Inspecting sshd, firewall and SELinux...",
            17);
        var rootProbeOutput = await RunRootScriptAsync(
                client,
                request,
                state,
                "inspecting sshd, firewall and SELinux",
                ServerInspection.RootProbeScript,
                CommandTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        var rootProbe = ServerInspection.ParseRootProbe(rootProbeOutput);

        if (!rootProbe.SshdAvailable)
        {
            throw new DeploymentException($"The OpenSSH server was not found at {SshdPath}. No server changes were made.");
        }

        if (!rootProbe.SshdConfigValid)
        {
            throw new DeploymentException(
                $"The current sshd configuration does not pass '{SshdPath} -T'. Fix it from the server console and retry. " +
                "No server changes were made.");
        }

        if (!rootProbe.IncludesDropIns)
        {
            throw new UnsupportedServerException(
                UnsupportedServerReason.SshdConfigWithoutInclude,
                rootProbe.MainConfigPath);
        }

        if (privilege == PrivilegeMode.Su && rootProbe.SudoersIncludesDropIns == false)
        {
            throw new UnsupportedServerException(
                UnsupportedServerReason.SudoersWithoutIncludeDir,
                "/etc/sudoers");
        }

        if (request.NewSshPort is int newPort &&
            rootProbe.Ports.Count == 1 &&
            rootProbe.Ports[0] == newPort)
        {
            throw new DeploymentException(
                $"sshd already listens only on port {newPort}; choose a different new port. No server changes were made.");
        }

        state.MainConfigPorts = rootProbe.MainConfigPorts;
        state.ManagedPorts = rootProbe.ManagedPorts;
        state.SocketActivated = rootProbe.SocketActivated;

        var server = new ServerInfo(
            probe.OsId,
            probe.OsName,
            probe.OsVersion,
            family,
            ServerInspection.SelectPackageManager(family, probe.Commands),
            probe.InitSystem,
            privilege,
            sudoInstalled,
            rootProbe.IncludesDropIns,
            rootProbe.SelinuxEnforcing,
            rootProbe.Firewall,
            rootProbe.SocketActivated,
            rootProbe.Ports);
        state.Server = server;
        reporter.Report(
            DeploymentStage.InspectingServer,
            $"Detected {server.DisplayName}; privilege mode: {privilege}.",
            17);
        return server;
    }

    private static async Task PreparePrivilegesAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        IReadOnlyList<string> packages,
        ProgressReporter reporter,
        CancellationToken cancellationToken)
    {
        if (packages.Count > 0)
        {
            var manager = state.Server?.PackageManager
                ?? throw new DeploymentException("No supported package manager was found.");
            reporter.Report(
                DeploymentStage.PreparingPrivileges,
                $"Installing {string.Join(", ", packages)} with {ServerInspection.CommandName(manager)}...",
                19);
            await RunRootScriptAsync(
                    client,
                    request,
                    state,
                    "installing required packages",
                    RemoteScripts.InstallPackages(manager, packages),
                    PackageTimeout,
                    cancellationToken,
                    failureKindIsPackage: true)
                .ConfigureAwait(false);
            state.InstalledPackages.AddRange(packages);
            if (packages.Contains("sudo", StringComparer.Ordinal))
            {
                state.SudoInstalled = true;
            }
        }

        if (state.Privilege != PrivilegeMode.Su)
        {
            reporter.Report(DeploymentStage.CheckingPrivileges, "Checking sshd and root access...", 20);
            return;
        }

        reporter.Report(DeploymentStage.PreparingPrivileges, "Granting temporary sudo through su...", 19);
        var (finalPath, temporaryPath) = RemoteScripts.NewSudoersPaths();
        state.SudoersDropInPath = finalPath;
        state.SudoersTemporaryPath = temporaryPath;

        // Raised before the command: its outcome is uncertain if the connection drops.
        state.SudoersDropInMayExist = true;
        await RunRootScriptAsync(
                client,
                request,
                state,
                "granting temporary sudo",
                RemoteScripts.CreateSudoersDropIn(request.Username, finalPath, temporaryPath),
                CommandTimeout,
                cancellationToken)
            .ConfigureAwait(false);

        reporter.Report(DeploymentStage.CheckingPrivileges, "Checking temporary sudo access...", 20);
        var check = await CheckSudoAccessAsync(client, request, cancellationToken).ConfigureAwait(false);
        if (!check.Succeeded)
        {
            throw new DeploymentException(
                "The temporary sudo grant was created, but sudo still rejected the account password" +
                (string.IsNullOrWhiteSpace(check.Diagnostic) ? "." : $": {check.Diagnostic}"));
        }

        state.TemporarySudoReady = true;
    }

    /// <summary>
    /// Runs a root script: through su while temporary sudo does not exist yet, otherwise through sudo or directly.
    /// </summary>
    private static async Task<string> RunRootScriptAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        string operation,
        string script,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        bool failureKindIsPackage = false)
    {
        if (state.Privilege == PrivilegeMode.Su && !state.TemporarySudoReady)
        {
            return await RunViaSuAsync(client, request, state, operation, script, timeout, cancellationToken, failureKindIsPackage)
                .ConfigureAwait(false);
        }

        var result = await RunAsync(
                client,
                operation,
                BuildShellCommand(script),
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken,
                timeout)
            .ConfigureAwait(false);
        if (result.ExitStatus != 0)
        {
            var exception = CreateRemoteCommandException(operation, result, request.Password);
            throw failureKindIsPackage
                ? new DeploymentException($"Package installation failed. {exception.Message} No other server changes were made.")
                : exception;
        }

        return result.StandardOutput;
    }

    private static async Task<string> RunViaSuAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        string operation,
        string script,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        bool failureKindIsPackage = false)
    {
        var rootPassword = request.RootPassword
            ?? throw new DeploymentException("A root password is required to use su.");
        SuShell.SuOutcome outcome;
        try
        {
            outcome = await SuShell.RunAsync(
                    client,
                    rootPassword,
                    RemoteScripts.RootPath + script,
                    timeout,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DeploymentException(
                $"Remote operation failed while {operation} through su ({Redact(SafeExceptionMessage(exception, request), rootPassword)}).",
                exception);
        }

        if (!outcome.Authenticated)
        {
            var kind = SuShell.ClassifyFailure(outcome.Diagnostic, outcome.PasswordSent);
            throw new PrivilegeException(
                request.Username,
                kind == SuFailureKind.PasswordRejected
                    ? PrivilegeFailureReason.RootPasswordRejected
                    : PrivilegeFailureReason.SuUnavailable,
                state.Family,
                state.OsName,
                state.SudoInstalled,
                Redact(Redact(outcome.Diagnostic, rootPassword), request.Password));
        }

        var output = Redact(Redact(outcome.Output, rootPassword), request.Password);
        if (outcome.ExitStatus != 0)
        {
            var message = string.IsNullOrWhiteSpace(output)
                ? $"Remote operation failed while {operation} (exit {outcome.ExitStatus})."
                : $"Remote operation failed while {operation} (exit {outcome.ExitStatus}): {LimitOutput(output)}";
            throw new DeploymentException(
                failureKindIsPackage
                    ? $"Package installation failed. {message} No other server changes were made."
                    : message);
        }

        return output;
    }

    private static async Task<bool> TryRemoveSudoersDropInAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state)
    {
        if (state.SudoersDropInPath is null || state.SudoersTemporaryPath is null)
        {
            return true;
        }

        using var timeout = new CancellationTokenSource(RecoveryTimeout);
        try
        {
            // Always through su: it must work even if the sudo grant is broken or half-created.
            var output = await RunViaSuAsync(
                    client,
                    request,
                    state,
                    "removing the temporary sudo grant",
                    RemoteScripts.RemoveSudoersDropIn(state.SudoersDropInPath, state.SudoersTemporaryPath),
                    RecoveryTimeout,
                    timeout.Token)
                .ConfigureAwait(false);
            return output.Contains("removed", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<List<string>> ChangePortAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        string privateKeyPath,
        ApprovedHostKey approvedHostKey,
        int newPort,
        ProgressReporter reporter,
        CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        var server = state.Server ?? throw new InvalidOperationException("Server inspection is missing.");
        state.NewPort = newPort;

        if (server.SelinuxEnforcing)
        {
            reporter.Report(DeploymentStage.ChangingPort, $"Labelling TCP port {newPort} as ssh_port_t for SELinux...", 88);
            var check = await RunRootScriptAsync(
                    client,
                    request,
                    state,
                    "checking the SELinux label of the new port",
                    RemoteScripts.SelinuxPortCheck(newPort),
                    SelinuxTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            if (check.Trim() != "present")
            {
                state.SelinuxPortMayBeAdded = true;
                await RunRootScriptAsync(
                        client,
                        request,
                        state,
                        "labelling the new port for SELinux",
                        RemoteScripts.SelinuxPortAdd(newPort),
                        SelinuxTimeout,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        if (server.Firewall == Firewall.Ufw)
        {
            reporter.Report(DeploymentStage.ChangingPort, $"Opening TCP port {newPort} in ufw...", 89);
            var check = await RunRootScriptAsync(
                    client,
                    request,
                    state,
                    "checking ufw rules",
                    RemoteScripts.UfwCheck(newPort),
                    CommandTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            if (check.Trim() != "present")
            {
                state.UfwRuleMayBeAdded = true;
                await RunRootScriptAsync(
                        client,
                        request,
                        state,
                        "opening the new port in ufw",
                        RemoteScripts.UfwAdd(newPort),
                        CommandTimeout,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        else if (server.Firewall == Firewall.Firewalld)
        {
            reporter.Report(DeploymentStage.ChangingPort, $"Opening TCP port {newPort} in firewalld...", 89);
            var check = await RunRootScriptAsync(
                    client,
                    request,
                    state,
                    "checking firewalld ports",
                    RemoteScripts.FirewalldCheck(newPort),
                    CommandTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            var addRuntime = !check.Contains("runtime=1", StringComparison.Ordinal);
            var addPermanent = !check.Contains("permanent=1", StringComparison.Ordinal);
            if (addRuntime || addPermanent)
            {
                state.FirewalldRuntimeMayBeAdded = addRuntime;
                state.FirewalldPermanentMayBeAdded = addPermanent;
                await RunRootScriptAsync(
                        client,
                        request,
                        state,
                        "opening the new port in firewalld",
                        RemoteScripts.FirewalldChange(newPort, addRuntime, addPermanent, add: true),
                        SelinuxTimeout,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        // Phase 1: listen on the old and the new port, then prove key login on the new port.
        reporter.Report(DeploymentStage.ChangingPort, $"Adding port {newPort} next to the current port...", 90);
        var transitionPorts = ServerInspection.GetTransitionPorts(server.CurrentPorts, state.MainConfigPorts, newPort);
        state.PortConfigWritten = true;
        await WriteManagedConfigFileAsync(client, request, state, transitionPorts, cancellationToken).ConfigureAwait(false);
        await RunCheckedAsync(
                client,
                "validating sshd syntax with the new port",
                $"{SshdPath} -t",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
        await ReloadSshAsync(
                client,
                request.Password,
                state.SessionIsRoot,
                restartSocket: state.SocketActivated,
                cancellationToken)
            .ConfigureAwait(false);

        reporter.Report(DeploymentStage.ChangingPort, $"Verifying key login on the new port {newPort}...", 92);
        await VerifyKeyLoginWithRetryAsync(
                request,
                request.TargetUsername,
                privateKeyPath,
                approvedHostKey,
                newPort,
                cancellationToken)
            .ConfigureAwait(false);

        // Phase 2: only the new port.
        reporter.Report(DeploymentStage.ChangingPort, $"Closing the old port; sshd keeps only port {newPort}...", 94);
        IReadOnlyList<int> finalPorts = [newPort];
        if (!transitionPorts.SequenceEqual(finalPorts))
        {
            await WriteManagedConfigFileAsync(client, request, state, finalPorts, cancellationToken).ConfigureAwait(false);
            await RunCheckedAsync(
                    client,
                    "validating sshd syntax with only the new port",
                    $"{SshdPath} -t",
                    request.Password,
                    standardInput: null,
                    runAsRoot: true,
                    state.SessionIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);
            await ReloadSshAsync(
                    client,
                    request.Password,
                    state.SessionIsRoot,
                    restartSocket: state.SocketActivated,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        reporter.Report(DeploymentStage.VerifyingEffectiveConfiguration, "Verifying effective settings on the new port...", 95);
        var effective = await RunCheckedAsync(
                client,
                "reading the effective sshd ports",
                $"{SshdPath} -T",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
        var effectivePorts = ParseEffectivePorts(effective.StandardOutput);
        if (!effectivePorts.Contains(newPort))
        {
            throw new DeploymentException(
                $"After the port change, sshd -T does not list port {newPort} (found: {string.Join(", ", effectivePorts)}).");
        }

        state.ConnectionContext = state.ConnectionContext with { LocalPort = newPort };
        await ValidateEffectiveSshdAsync(client, request, state, cancellationToken).ConfigureAwait(false);

        reporter.Report(DeploymentStage.VerifyingKeyLogin, $"Verifying key login on port {newPort} again...", 97);
        await VerifyKeyLoginWithRetryAsync(
                request,
                request.TargetUsername,
                privateKeyPath,
                approvedHostKey,
                newPort,
                cancellationToken)
            .ConfigureAwait(false);

        var stillOpen = effectivePorts.Where(port => port != newPort).ToArray();
        if (stillOpen.Length > 0)
        {
            var source = state.MainConfigPorts.Count > 0
                ? $"because the main sshd_config sets 'Port {string.Join("' and 'Port ", state.MainConfigPorts)}' explicitly. The tool never edits that file; remove the line yourself if you want to close the old port"
                : "because another configuration file sets it";
            warnings.Add(
                $"sshd now listens on port {newPort}, but port(s) {string.Join(", ", stillOpen)} remain open {source}.");
        }

        return warnings;
    }

    private static IReadOnlyList<int> ParseEffectivePorts(string output) =>
        output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries))
            .Where(parts => parts.Length == 2 && parts[0].Equals("port", StringComparison.OrdinalIgnoreCase))
            .Select(parts => int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : 0)
            .Where(port => port is >= 1 and <= 65535)
            .Distinct()
            .ToArray();

    private static SshClient CreatePasswordClient(DeploymentRequest request)
    {
        var client = new SshClient(
            request.Host,
            request.Port,
            request.Username,
            request.Password);
        client.ConnectionInfo.Timeout = ConnectionTimeout;
        client.KeepAliveInterval = TimeSpan.FromSeconds(10);
        return client;
    }

    private static async Task<ApprovedHostKey> ConnectWithApprovalAsync(
        SshClient client,
        DeploymentRequest request,
        HostKeyApprovalCallback callback,
        ProgressReporter reporter,
        CancellationToken cancellationToken)
    {
        ApprovedHostKey? approvedHostKey = null;
        Exception? approvalFailure = null;
        var approvalInvoked = false;
        var approvalAccepted = false;

        client.HostKeyReceived += (_, eventArgs) =>
        {
            // SSH.NET initializes CanTrust to true, so every handler must fail closed.
            eventArgs.CanTrust = false;
            var hostKey = ToHostKeyInfo(request.Host, request.Port, eventArgs);
            if (approvedHostKey is not null)
            {
                eventArgs.CanTrust =
                    string.Equals(
                        eventArgs.HostKeyName,
                        approvedHostKey.Info.Algorithm,
                        StringComparison.Ordinal) &&
                    eventArgs.HostKey.Length == approvedHostKey.KeyData.Length &&
                    CryptographicOperations.FixedTimeEquals(
                        eventArgs.HostKey,
                        approvedHostKey.KeyData);
                return;
            }

            approvalInvoked = true;
            reporter.Report(
                DeploymentStage.AwaitingHostKeyApproval,
                $"Confirm the server host key ({hostKey.Sha256Fingerprint}).",
                14);

            try
            {
                approvalAccepted = reporter
                    .InvokeHostKeyApprovalAsync(callback, hostKey, cancellationToken)
                    .WaitAsync(cancellationToken)
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();
                eventArgs.CanTrust = approvalAccepted;

                if (approvalAccepted)
                {
                    approvedHostKey = new ApprovedHostKey(
                        hostKey,
                        eventArgs.HostKey.ToArray());
                }
            }
            catch (Exception exception)
            {
                approvalFailure = exception;
                eventArgs.CanTrust = false;
            }
        };

        try
        {
            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            if (approvalFailure is OperationCanceledException || cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if (approvalFailure is not null)
            {
                throw new DeploymentException(
                    "Host-key confirmation could not be completed. No server changes were made.",
                    approvalFailure);
            }

            if (approvalInvoked && !approvalAccepted)
            {
                throw new DeploymentException(
                    "The server host key was not approved. No server changes were made.",
                    exception);
            }

            throw new InitialSshConnectionException(
                request.Host,
                request.Port,
                request.Username,
                ClassifyInitialSshConnectionFailure(exception),
                exception);
        }

        return approvedHostKey
            ?? throw new DeploymentException(
                "SSH.NET connected without an explicitly approved host key. No server changes were made.");
    }

    private static InitialSshConnectionFailureReason ClassifyInitialSshConnectionFailure(
        Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is SshAuthenticationException)
            {
                return InitialSshConnectionFailureReason.AuthenticationRejected;
            }

            if (current is SshOperationTimeoutException or TimeoutException ||
                current is SocketException { SocketErrorCode: SocketError.TimedOut })
            {
                return InitialSshConnectionFailureReason.TimedOut;
            }

            if (current is SocketException)
            {
                return InitialSshConnectionFailureReason.NetworkUnavailable;
            }
        }

        return InitialSshConnectionFailureReason.Unknown;
    }

    private static HostKeyInfo ToHostKeyInfo(
        string host,
        int port,
        HostKeyEventArgs eventArgs) =>
        new(
            host,
            port,
            eventArgs.HostKeyName,
            eventArgs.KeyLength,
            $"SHA256:{eventArgs.FingerPrintSHA256}",
            $"MD5:{eventArgs.FingerPrintMD5}");

    private static async Task<RemoteCommandResult> InstallPublicKeyAsync(
        SshClient client,
        string publicKey,
        string backupPath,
        DeploymentState state,
        string password,
        bool rootTarget,
        CancellationToken cancellationToken)
    {
        var command = rootTarget ? InstallRootKeyCommand : InstallCurrentUserKeyCommand;
        return await RunCheckedAsync(
                client,
                "installing the public key",
                command,
                password,
                backupPath + "\n" + publicKey + "\n",
                runAsRoot: rootTarget,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task PrepareAuthorizedKeysBackupAsync(
        SshClient client,
        string backupPath,
        DeploymentState state,
        string password,
        bool rootTarget,
        CancellationToken cancellationToken)
    {
        await RunCheckedAsync(
                client,
                "snapshotting authorized_keys before modification",
                BuildPrepareAuthorizedKeysBackupCommand(backupPath, rootTarget),
                password,
                standardInput: null,
                runAsRoot: rootTarget,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task PrepareAndWriteConfigAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        CancellationToken cancellationToken)
    {
        await RunCheckedAsync(
                client,
                "creating the SSH configuration directory",
                "install -d -o root -g root -m 0755 -- /etc/ssh/sshd_config.d",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        var symlinkResult = await RunAsync(
                client,
                "checking the managed SSH configuration path",
                $"test -L {ManagedConfigPath}",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        if (symlinkResult.ExitStatus == 0)
        {
            throw new DeploymentException(
                $"Refusing to replace the symbolic link at {ManagedConfigPath}.");
        }

        if (symlinkResult.ExitStatus != 1)
        {
            throw CreateRemoteCommandException(
                "checking the managed SSH configuration path",
                symlinkResult,
                request.Password);
        }

        var existsResult = await RunAsync(
                client,
                "checking for an existing managed SSH configuration",
                $"test -e {ManagedConfigPath}",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        if (existsResult.ExitStatus is not (0 or 1))
        {
            throw CreateRemoteCommandException(
                "checking for an existing managed SSH configuration",
                existsResult,
                request.Password);
        }

        state.ConfigOriginallyExisted = existsResult.ExitStatus == 0;
        if (state.ConfigOriginallyExisted)
        {
            var regularFileResult = await RunAsync(
                    client,
                    "checking the existing managed SSH configuration",
                    $"test -f {ManagedConfigPath}",
                    request.Password,
                    standardInput: null,
                    runAsRoot: true,
                    state.SessionIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);

            if (regularFileResult.ExitStatus != 0)
            {
                throw new DeploymentException(
                    $"Refusing to replace a non-regular file at {ManagedConfigPath}.");
            }

            var markerResult = await RunCheckedAsync(
                    client,
                    "checking ownership of the existing managed SSH configuration",
                    $"head -n 1 -- {ManagedConfigPath}",
                    request.Password,
                    standardInput: null,
                    runAsRoot: true,
                    state.SessionIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    markerResult.StandardOutput.Trim(),
                    "# Managed by SSH Key Deployer. Local edits will be replaced.",
                    StringComparison.Ordinal))
            {
                throw new DeploymentException(
                    $"Refusing to replace {ManagedConfigPath} because it is not owned by SSH Key Deployer.");
            }

            await RunCheckedAsync(
                    client,
                    "backing up the managed SSH configuration",
                    $"cp -a -- {ManagedConfigPath} {state.BackupPath}",
                    request.Password,
                    standardInput: null,
                    runAsRoot: true,
                    state.SessionIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);
            state.BackupCreated = true;
        }

        // Keep ports that an earlier run of this tool moved sshd to, unless this run changes the port.
        await WriteManagedConfigFileAsync(
                client,
                request,
                state,
                state.ManagedPorts,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task WriteManagedConfigFileAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        IReadOnlyList<int> ports,
        CancellationToken cancellationToken)
    {
        var tempResult = await RunCheckedAsync(
                client,
                "creating a temporary SSH configuration",
                "mktemp /etc/ssh/sshd_config.d/.ssh-key-deployer.XXXXXXXXXX",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        state.TempConfigPath = tempResult.StandardOutput.Trim();
        if (!IsSafeTemporaryConfigPath(state.TempConfigPath))
        {
            throw new DeploymentException(
                "The server returned an unexpected temporary configuration path.");
        }

        var config = BuildManagedConfig(request, ports);
        await RunCheckedAsync(
                client,
                "writing the temporary SSH configuration",
                $"sh -c 'cat > {state.TempConfigPath}'",
                request.Password,
                config,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        // From this point onward the command outcome may be uncertain if the network drops.
        // Recovery must therefore assume the destination could have been replaced.
        state.ConfigModified = true;
        await RunCheckedAsync(
                client,
                "activating the managed SSH configuration",
                $"sh -c 'chown root:root -- {state.TempConfigPath} && chmod 0644 -- {state.TempConfigPath} && test ! -d {ManagedConfigPath} && mv -f -- {state.TempConfigPath} {ManagedConfigPath}'",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        state.TempConfigPath = null;
    }

    private static async Task ValidateSshdAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        CancellationToken cancellationToken)
    {
        await RunCheckedAsync(
                client,
                "validating sshd syntax",
                $"{SshdPath} -t",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        await ValidateEffectiveSshdAsync(client, request, state, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task ValidateEffectiveSshdAsync(
        SshClient client,
        DeploymentRequest request,
        DeploymentState state,
        CancellationToken cancellationToken)
    {
        var globalResult = await RunCheckedAsync(
                client,
                "reading global effective sshd settings",
                $"{SshdPath} -T",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);

        var globalSettings = ParseEffectiveSettings(globalResult.StandardOutput);
        if (!globalSettings.TryGetValue("usedns", out var useDns) ||
            !(useDns.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
              useDns.Equals("no", StringComparison.OrdinalIgnoreCase)))
        {
            throw new DeploymentException(
                $"Effective sshd setting usedns is '{useDns ?? "missing"}', expected 'yes' or 'no'.");
        }

        var clientHost = useDns.Equals("yes", StringComparison.OrdinalIgnoreCase)
            ? await ResolveClientHostAsync(
                    client,
                    state.ConnectionContext.ClientAddress,
                    request.Password,
                    cancellationToken)
                .ConfigureAwait(false)
            : state.ConnectionContext.ClientAddress;
        state.ConnectionContext = state.ConnectionContext with { ClientHost = clientHost };

        // Always verify root as well as the entered account. A later Match User root
        // block must not be able to silently override a requested root-login policy.
        var usernames = new[] { request.Username, "root" }
            .Distinct(StringComparer.Ordinal);

        foreach (var username in usernames)
        {
            var connectionSpec = state.ConnectionContext.ToSshdConnectionSpec(username);
            var result = await RunCheckedAsync(
                    client,
                    $"reading effective sshd settings for {username}",
                    $"{SshdPath} -T -C {ShellQuote(connectionSpec)}",
                    request.Password,
                    standardInput: null,
                    runAsRoot: true,
                    state.SessionIsRoot,
                    cancellationToken)
                .ConfigureAwait(false);

            AssertEffectiveSettings(result.StandardOutput, request, username);
        }
    }

    private static async Task ReloadSshAsync(
        SshClient client,
        string password,
        bool sessionIsRoot,
        bool restartSocket,
        CancellationToken cancellationToken)
    {
        await RunCheckedAsync(
                client,
                "reloading the SSH service",
                BuildShellCommand(RemoteScripts.Reload(restartSocket)),
                password,
                standardInput: null,
                runAsRoot: true,
                sessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task VerifyKeyLoginWithRetryAsync(
        DeploymentRequest request,
        string targetUsername,
        string privateKeyPath,
        ApprovedHostKey approvedHostKey,
        int port,
        CancellationToken cancellationToken)
    {
        // sshd re-executes itself on reload, so a new listening port can take a moment to appear.
        const int attempts = 5;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await VerifyKeyLoginAsync(
                        request,
                        targetUsername,
                        privateKeyPath,
                        approvedHostKey,
                        port,
                        cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
            catch (DeploymentException exception) when (
                attempt < attempts &&
                exception.InnerException is not null &&
                ClassifyInitialSshConnectionFailure(exception.InnerException) is
                    InitialSshConnectionFailureReason.NetworkUnavailable or
                    InitialSshConnectionFailureReason.TimedOut)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static async Task VerifyKeyLoginAsync(
        DeploymentRequest request,
        string targetUsername,
        string privateKeyPath,
        ApprovedHostKey approvedHostKey,
        int port,
        CancellationToken cancellationToken)
    {
        try
        {
            using var privateKey = new PrivateKeyFile(privateKeyPath);
            using var client = new SshClient(
                request.Host,
                port,
                targetUsername,
                privateKey);
            client.ConnectionInfo.Timeout = ConnectionTimeout;
            client.KeepAliveInterval = TimeSpan.FromSeconds(10);

            var hostKeyMatched = false;
            client.HostKeyReceived += (_, eventArgs) =>
            {
                eventArgs.CanTrust = false;
                hostKeyMatched =
                    string.Equals(
                        eventArgs.HostKeyName,
                        approvedHostKey.Info.Algorithm,
                        StringComparison.Ordinal) &&
                    eventArgs.HostKey.Length == approvedHostKey.KeyData.Length &&
                    CryptographicOperations.FixedTimeEquals(
                        eventArgs.HostKey,
                        approvedHostKey.KeyData);
                eventArgs.CanTrust = hostKeyMatched;
            };

            await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
            if (!hostKeyMatched)
            {
                throw new DeploymentException(
                    "The server host key changed during key-login verification.");
            }

            var identity = await RunCheckedAsync(
                    client,
                    "verifying the key-authenticated account",
                    "id -un",
                    password: string.Empty,
                    standardInput: null,
                    runAsRoot: false,
                    sessionIsRoot: false,
                    cancellationToken)
                .ConfigureAwait(false);

            if (!string.Equals(
                    identity.StandardOutput.Trim(),
                    targetUsername,
                    StringComparison.Ordinal))
            {
                throw new DeploymentException(
                    "Key authentication connected as an unexpected account.");
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DeploymentException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DeploymentException(
                $"Key authentication as {targetUsername} on port {port} could not be verified.",
                exception);
        }
    }

    private static async Task<List<string>> CommitConfigAsync(
        SshClient client,
        string password,
        DeploymentState state,
        CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        cancellationToken.ThrowIfCancellationRequested();

        // Verification is complete before commit begins. Cleanup is best-effort so a
        // cancellation or transport failure cannot trigger rollback after one of the
        // snapshots has already been irreversibly deleted.
        if (state.CurrentUserKeySnapshotMayExist)
        {
            if (await TryCleanupAuthorizedKeysBackupAsync(
                    client,
                    state.CurrentUserKeyBackupPath,
                    password,
                    rootTarget: state.CurrentUserIsRoot,
                    state.SessionIsRoot)
                .ConfigureAwait(false))
            {
                state.CurrentUserKeySnapshotMayExist = false;
                state.CurrentUserKeyMutationMayHaveStarted = false;
            }
            else
            {
                warnings.Add(
                    $"Deployment is verified, but the temporary authorized_keys snapshot {state.CurrentUserKeyBackupPath} could not be removed.");
            }
        }

        if (state.RootKeySnapshotMayExist)
        {
            if (await TryCleanupAuthorizedKeysBackupAsync(
                    client,
                    state.RootKeyBackupPath,
                    password,
                    rootTarget: true,
                    state.SessionIsRoot)
                .ConfigureAwait(false))
            {
                state.RootKeySnapshotMayExist = false;
                state.RootKeyMutationMayHaveStarted = false;
            }
            else
            {
                warnings.Add(
                    $"Deployment is verified, but the temporary root authorized_keys snapshot {state.RootKeyBackupPath} could not be removed.");
            }
        }

        if (state.BackupCreated)
        {
            try
            {
                var result = await RunAsync(
                        client,
                        "removing the temporary configuration backup",
                        $"rm -f -- {state.BackupPath}",
                        password,
                        standardInput: null,
                        runAsRoot: true,
                        state.SessionIsRoot,
                        CancellationToken.None)
                    .ConfigureAwait(false);

                if (result.ExitStatus == 0)
                {
                    state.BackupCreated = false;
                }
                else
                {
                    warnings.Add(
                        $"Deployment is verified, but the temporary backup {state.BackupPath} could not be removed.");
                }
            }
            catch
            {
                warnings.Add(
                    $"Deployment is verified, but the temporary backup {state.BackupPath} could not be removed.");
            }
        }

        return warnings;
    }

    private static async Task<RecoveryResult> RecoverAsync(
        SshClient client,
        DeploymentRequest request,
        string publicKey,
        DeploymentState state,
        ProgressReporter reporter)
    {
        var attempted = state.ConfigModified ||
                        state.BackupCreated ||
                        state.TempConfigPath is not null ||
                        state.CurrentUserKeySnapshotMayExist ||
                        state.RootKeySnapshotMayExist ||
                        state.UfwRuleMayBeAdded ||
                        state.FirewalldRuntimeMayBeAdded ||
                        state.FirewalldPermanentMayBeAdded ||
                        state.SelinuxPortMayBeAdded ||
                        state.SudoersDropInMayExist;
        if (!attempted)
        {
            return RecoveryResult.NotAttempted;
        }

        reporter.Report(DeploymentStage.RollingBack, "Rolling back server changes...", 94);
        using var recoveryTimeout = new CancellationTokenSource(RecoveryTimeout);
        var errors = new List<string>();
        var configRestored = !state.ConfigModified;

        try
        {
            if (state.ConfigModified)
            {
                var restoreCommand = state.ConfigOriginallyExisted
                    ? $"sh -c 'test ! -d {ManagedConfigPath} && mv -f -- {state.BackupPath} {ManagedConfigPath}'"
                    : $"rm -f -- {ManagedConfigPath}";

                await RunCheckedAsync(
                        client,
                        "restoring the SSH configuration",
                        restoreCommand,
                        request.Password,
                        standardInput: null,
                        runAsRoot: true,
                        state.SessionIsRoot,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);

                state.ConfigModified = false;
                state.BackupCreated = false;

                await RunCheckedAsync(
                        client,
                        "validating the restored SSH configuration",
                        $"{SshdPath} -t",
                        request.Password,
                        standardInput: null,
                        runAsRoot: true,
                        state.SessionIsRoot,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);

                await ReloadSshAsync(
                        client,
                        request.Password,
                        state.SessionIsRoot,
                        restartSocket: state.SocketActivated && state.PortConfigWritten,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);
                configRestored = true;
            }
        }
        catch (Exception exception)
        {
            errors.Add($"SSH configuration recovery failed ({SafeExceptionMessage(exception, request)}).");
        }

        // Firewall and SELinux entries are only removed once sshd is back on its old port;
        // otherwise removing them could lock out the only port sshd still listens on.
        if (configRestored && state.NewPort is int newPort)
        {
            if (state.UfwRuleMayBeAdded)
            {
                try
                {
                    await RunCheckedAsync(
                            client,
                            "removing the ufw rule for the new port",
                            BuildShellCommand(RemoteScripts.UfwRemove(newPort)),
                            request.Password,
                            standardInput: null,
                            runAsRoot: true,
                            state.SessionIsRoot,
                            recoveryTimeout.Token)
                        .ConfigureAwait(false);
                    state.UfwRuleMayBeAdded = false;
                }
                catch (Exception exception)
                {
                    errors.Add($"The ufw rule for port {newPort} could not be removed ({SafeExceptionMessage(exception, request)}).");
                }
            }

            if (state.FirewalldRuntimeMayBeAdded || state.FirewalldPermanentMayBeAdded)
            {
                try
                {
                    await RunCheckedAsync(
                            client,
                            "removing the firewalld port",
                            BuildShellCommand(RemoteScripts.FirewalldChange(
                                newPort,
                                state.FirewalldRuntimeMayBeAdded,
                                state.FirewalldPermanentMayBeAdded,
                                add: false)),
                            request.Password,
                            standardInput: null,
                            runAsRoot: true,
                            state.SessionIsRoot,
                            recoveryTimeout.Token)
                        .ConfigureAwait(false);
                    state.FirewalldRuntimeMayBeAdded = false;
                    state.FirewalldPermanentMayBeAdded = false;
                }
                catch (Exception exception)
                {
                    errors.Add($"The firewalld entry for port {newPort} could not be removed ({SafeExceptionMessage(exception, request)}).");
                }
            }

            if (state.SelinuxPortMayBeAdded)
            {
                try
                {
                    using var selinuxTimeout = new CancellationTokenSource(SelinuxTimeout);
                    await RunCheckedAsync(
                            client,
                            "removing the SELinux label of the new port",
                            BuildShellCommand(RemoteScripts.SelinuxPortRemove(newPort)),
                            request.Password,
                            standardInput: null,
                            runAsRoot: true,
                            state.SessionIsRoot,
                            selinuxTimeout.Token,
                            SelinuxTimeout)
                        .ConfigureAwait(false);
                    state.SelinuxPortMayBeAdded = false;
                }
                catch (Exception exception)
                {
                    errors.Add($"The SELinux label for port {newPort} could not be removed ({SafeExceptionMessage(exception, request)}).");
                }
            }
        }

        // Restore in reverse mutation order. The snapshots cover uncertain command
        // outcomes, including a connection loss after authorized_keys was renamed.
        if (configRestored && state.RootKeyMutationMayHaveStarted)
        {
            try
            {
                await RestoreAuthorizedKeysAsync(
                        client,
                        state.RootKeyBackupPath,
                        publicKey,
                        state,
                        request.Password,
                        rootTarget: true,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);
                state.RootKeyMutationMayHaveStarted = false;
                state.RootKeySnapshotMayExist = false;
            }
            catch (Exception exception)
            {
                errors.Add($"The root authorized_keys snapshot could not be restored ({SafeExceptionMessage(exception, request)}).");
            }
        }

        if (configRestored && state.CurrentUserKeyMutationMayHaveStarted)
        {
            try
            {
                await RestoreAuthorizedKeysAsync(
                        client,
                        state.CurrentUserKeyBackupPath,
                        publicKey,
                        state,
                        request.Password,
                        rootTarget: state.CurrentUserIsRoot,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);
                state.CurrentUserKeyMutationMayHaveStarted = false;
                state.CurrentUserKeySnapshotMayExist = false;
            }
            catch (Exception exception)
            {
                errors.Add($"The authorized_keys snapshot could not be restored ({SafeExceptionMessage(exception, request)}).");
            }
        }

        if (configRestored &&
            state.RootKeySnapshotMayExist &&
            !state.RootKeyMutationMayHaveStarted)
        {
            if (await TryCleanupAuthorizedKeysBackupAsync(
                    client,
                    state.RootKeyBackupPath,
                    request.Password,
                    rootTarget: true,
                    state.SessionIsRoot)
                .ConfigureAwait(false))
            {
                state.RootKeySnapshotMayExist = false;
            }
            else
            {
                errors.Add("The unused root authorized_keys snapshot could not be removed.");
            }
        }

        if (configRestored &&
            state.CurrentUserKeySnapshotMayExist &&
            !state.CurrentUserKeyMutationMayHaveStarted)
        {
            if (await TryCleanupAuthorizedKeysBackupAsync(
                    client,
                    state.CurrentUserKeyBackupPath,
                    request.Password,
                    rootTarget: state.CurrentUserIsRoot,
                    state.SessionIsRoot)
                .ConfigureAwait(false))
            {
                state.CurrentUserKeySnapshotMayExist = false;
            }
            else
            {
                errors.Add("The unused authorized_keys snapshot could not be removed.");
            }
        }

        try
        {
            if (state.TempConfigPath is not null)
            {
                await RunCheckedAsync(
                        client,
                        "removing the temporary SSH configuration",
                        $"rm -f -- {state.TempConfigPath}",
                        request.Password,
                        standardInput: null,
                        runAsRoot: true,
                        state.SessionIsRoot,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);
                state.TempConfigPath = null;
            }

            if (!state.ConfigModified && state.BackupCreated)
            {
                await RunCheckedAsync(
                        client,
                        "removing the temporary configuration backup",
                        $"rm -f -- {state.BackupPath}",
                        request.Password,
                        standardInput: null,
                        runAsRoot: true,
                        state.SessionIsRoot,
                        recoveryTimeout.Token)
                    .ConfigureAwait(false);
                state.BackupCreated = false;
            }
        }
        catch (Exception exception)
        {
            errors.Add($"Temporary recovery files could not be removed ({SafeExceptionMessage(exception, request)}).");
        }

        // Always the last step: rollback above may still need the temporary sudo grant.
        if (state.SudoersDropInMayExist)
        {
            if (await TryRemoveSudoersDropInAsync(client, request, state).ConfigureAwait(false))
            {
                state.SudoersDropInMayExist = false;
            }
            else
            {
                errors.Add(
                    $"The temporary sudo grant {state.SudoersDropInPath} could not be removed; remove it as root: rm -f {state.SudoersDropInPath}.");
            }
        }

        return new RecoveryResult(
            Attempted: true,
            Succeeded: errors.Count == 0,
            Detail: errors.Count == 0 ? "Rollback completed." : string.Join(" ", errors));
    }

    private static async Task RestoreAuthorizedKeysAsync(
        SshClient client,
        string backupPath,
        string publicKey,
        DeploymentState state,
        string password,
        bool rootTarget,
        CancellationToken cancellationToken)
    {
        await RunCheckedAsync(
                client,
                "restoring the authorized_keys snapshot",
                BuildRestoreAuthorizedKeysCommand(backupPath, rootTarget),
                password,
                standardInput: publicKey + "\n",
                runAsRoot: rootTarget,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<bool> TryCleanupAuthorizedKeysBackupAsync(
        SshClient client,
        string backupPath,
        string password,
        bool rootTarget,
        bool sessionIsRoot)
    {
        try
        {
            var result = await RunAsync(
                    client,
                    "removing the temporary authorized_keys snapshot",
                    BuildCleanupAuthorizedKeysBackupCommand(backupPath),
                    password,
                    standardInput: null,
                    runAsRoot: rootTarget,
                    sessionIsRoot,
                    CancellationToken.None)
                .ConfigureAwait(false);
            return result.ExitStatus == 0;
        }
        catch
        {
            return false;
        }
    }

    private static async Task RemovePublicKeyAsync(
        SshClient client,
        string publicKey,
        DeploymentState state,
        string password,
        bool rootTarget,
        CancellationToken cancellationToken)
    {
        var command = rootTarget ? RemoveRootKeyCommand : RemoveCurrentUserKeyCommand;
        await RunCheckedAsync(
                client,
                "removing the newly added public key",
                command,
                password,
                publicKey + "\n",
                runAsRoot: rootTarget,
                state.SessionIsRoot,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task<EffectiveConnectionContext> ReadConnectionContextAsync(
        SshClient client,
        DeploymentRequest request,
        CancellationToken cancellationToken)
    {
        var result = await RunCheckedAsync(
                client,
                "reading the SSH connection context",
                "printf '%s\\n' \"$SSH_CONNECTION\"",
                request.Password,
                standardInput: null,
                runAsRoot: false,
                sessionIsRoot: false,
                cancellationToken)
            .ConfigureAwait(false);

        var fields = result.StandardOutput.Split(
            (char[]?)null,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (fields.Length != 4 ||
            !IPAddress.TryParse(fields[0], out _) ||
            !int.TryParse(fields[1], out _) ||
            !IPAddress.TryParse(fields[2], out _) ||
            !int.TryParse(fields[3], out var localPort) ||
            localPort is < 1 or > 65535)
        {
            throw new DeploymentException(
                "The server returned an invalid SSH connection context; effective Match settings cannot be verified safely.");
        }

        return new EffectiveConnectionContext(
            fields[0],
            fields[0],
            fields[2],
            localPort);
    }

    private static async Task<string> ResolveClientHostAsync(
        SshClient client,
        string clientAddress,
        string password,
        CancellationToken cancellationToken)
    {
        var lookup = await RunAsync(
                client,
                "resolving the SSH client hostname",
                $"getent hosts {ShellQuote(clientAddress)}",
                password,
                standardInput: null,
                runAsRoot: false,
                sessionIsRoot: false,
                cancellationToken)
            .ConfigureAwait(false);

        if (lookup.ExitStatus == 0 && IPAddress.TryParse(clientAddress, out var clientIp))
        {
            var candidates = lookup.StandardOutput
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(line => line.Split(
                    (char[]?)null,
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Where(fields => fields.Length >= 2)
                .Select(fields => fields[1])
                .Where(IsSafeConnectionHost)
                .Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var candidate in candidates)
            {
                var forwardLookup = await RunAsync(
                        client,
                        "forward-confirming the SSH client hostname",
                        $"getent ahosts {ShellQuote(candidate)}",
                        password,
                        standardInput: null,
                        runAsRoot: false,
                        sessionIsRoot: false,
                        cancellationToken)
                    .ConfigureAwait(false);

                if (forwardLookup.ExitStatus == 0 &&
                    forwardLookup.StandardOutput
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(line => line.Split(
                            (char[]?)null,
                            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        .Where(fields => fields.Length >= 1)
                        .Select(fields => fields[0])
                        .Any(value =>
                            IPAddress.TryParse(value, out var resolvedAddress) &&
                            resolvedAddress.Equals(clientIp)))
                {
                    return candidate;
                }
            }
        }

        return clientAddress;
    }

    private static async Task<RemoteCommandResult> RunCheckedAsync(
        SshClient client,
        string operation,
        string commandText,
        string password,
        string? standardInput,
        bool runAsRoot,
        bool sessionIsRoot,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        var result = await RunAsync(
                client,
                operation,
                commandText,
                password,
                standardInput,
                runAsRoot,
                sessionIsRoot,
                cancellationToken,
                timeout)
            .ConfigureAwait(false);

        if (result.ExitStatus != 0)
        {
            throw CreateRemoteCommandException(operation, result, password);
        }

        return result;
    }

    private static async Task<SudoCheck> CheckSudoAccessAsync(
        SshClient client,
        DeploymentRequest request,
        CancellationToken cancellationToken)
    {
        var result = await RunAsync(
                client,
                "checking sudo access",
                "true",
                request.Password,
                standardInput: null,
                runAsRoot: true,
                sessionIsRoot: false,
                cancellationToken)
            .ConfigureAwait(false);

        if (result.ExitStatus == 0)
        {
            return new SudoCheck(true, null, string.Empty, result);
        }

        var diagnostic = GetRemoteDiagnostic(result, request.Password);
        if (request.RootPassword is not null)
        {
            diagnostic = Redact(diagnostic, request.RootPassword);
        }

        return new SudoCheck(false, ClassifySudoAccessFailure(diagnostic), diagnostic, result);
    }

    private static SudoAccessFailureReason? ClassifySudoAccessFailure(
        string diagnostic)
    {
        if (ContainsAny(
                diagnostic,
                "not in the sudoers file",
                "is not allowed to run sudo",
                "may not run sudo",
                "is not in the sudoers"))
        {
            return SudoAccessFailureReason.NotAuthorized;
        }

        if (ContainsAny(
                diagnostic,
                "sudo: command not found",
                "sudo: not found",
                "sudo: no such file or directory"))
        {
            return SudoAccessFailureReason.CommandUnavailable;
        }

        if (ContainsAny(
                diagnostic,
                "incorrect password attempt",
                "sorry, try again",
                "authentication failure",
                "a password is required",
                "no password was provided"))
        {
            return SudoAccessFailureReason.AuthenticationRejected;
        }

        return null;
    }

    private static bool ContainsAny(string value, params string[] candidates) =>
        candidates.Any(candidate =>
            value.Contains(candidate, StringComparison.OrdinalIgnoreCase));

    private static async Task<RemoteCommandResult> RunAsync(
        SshClient client,
        string operation,
        string commandText,
        string password,
        string? standardInput,
        bool runAsRoot,
        bool sessionIsRoot,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        var useSudo = runAsRoot && !sessionIsRoot;
        var effectiveCommand = useSudo
            ? standardInput is null
                ? $"sudo -k -S -p '' -- {commandText}"
                : BuildSudoPayloadCommand(commandText)
            : commandText;

        using var command = client.CreateCommand(effectiveCommand, Encoding.UTF8);
        command.CommandTimeout = timeout ?? CommandTimeout;

        try
        {
            var execution = command.ExecuteAsync(cancellationToken);
            if (useSudo || standardInput is not null)
            {
                using var input = command.CreateInputStream();
                if (useSudo)
                {
                    await WritePasswordLineAsync(input, password, cancellationToken)
                        .ConfigureAwait(false);
                }

                if (standardInput is not null)
                {
                    var inputBytes = Encoding.UTF8.GetBytes(standardInput);
                    await input.WriteAsync(inputBytes, cancellationToken).ConfigureAwait(false);
                }
            }

            await execution.ConfigureAwait(false);
            return new RemoteCommandResult(
                command.ExitStatus ?? -1,
                LimitOutput(command.Result),
                LimitOutput(command.Error));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new DeploymentException(
                $"Remote operation failed while {operation}.",
                exception);
        }
    }

    private static async Task WritePasswordLineAsync(
        Stream stream,
        string password,
        CancellationToken cancellationToken)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            await stream.WriteAsync(passwordBytes, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static DeploymentException CreateRemoteCommandException(
        string operation,
        RemoteCommandResult result,
        string password)
    {
        var diagnostic = GetRemoteDiagnostic(result, password);

        return new DeploymentException(
            string.IsNullOrWhiteSpace(diagnostic)
                ? $"Remote operation failed while {operation} (exit {result.ExitStatus})."
                : $"Remote operation failed while {operation} (exit {result.ExitStatus}): {diagnostic}");
    }

    private static string GetRemoteDiagnostic(
        RemoteCommandResult result,
        string password)
    {
        var diagnostic = string.IsNullOrWhiteSpace(result.StandardError)
            ? result.StandardOutput
            : result.StandardError;
        return Redact(diagnostic, password);
    }

    private static string BuildManagedConfig(DeploymentRequest request) =>
        BuildManagedConfig(request, Array.Empty<int>());

    private static string BuildManagedConfig(DeploymentRequest request, IReadOnlyList<int> ports)
    {
        var portLines = string.Concat(ports.Select(port =>
            $"Port {port.ToString(CultureInfo.InvariantCulture)}\n"));
        var passwordAuthentication = request.AllowPasswordLogin ? "yes" : "no";
        var permitRootLogin = request.EnableRootLogin
            ? request.AllowPasswordLogin ? "yes" : "prohibit-password"
            : "no";

        return
            "# Managed by SSH Key Deployer. Local edits will be replaced.\n" +
            "# Loaded early so these verified authentication settings take precedence.\n" +
            "PubkeyAuthentication yes\n" +
            $"PasswordAuthentication {passwordAuthentication}\n" +
            "KbdInteractiveAuthentication no\n" +
            $"PermitRootLogin {permitRootLogin}\n" +
            portLines;
    }

    private static string BuildPrepareAuthorizedKeysBackupCommand(
        string backupPath,
        bool rootTarget)
    {
        var sshDirectoryAssignment = rootTarget
            ? "sshdir=/root/.ssh"
            : "sshdir=\"$HOME/.ssh\"";
        return BuildShellCommand(
            $$"""
            set -eu
            umask 077
            txn={{ShellQuote(backupPath)}}
            test ! -e "$txn"
            test ! -L "$txn"
            mkdir -m 0700 -- "$txn"
            cleanup_partial() {
                rm -f -- "$txn/ready" "$txn/file.existed" "$txn/directory.existed" "$txn/directory.meta" "$txn/directory.timestamps" "$txn/authorized_keys" "$txn/expected" "$txn/key.added" "$txn/key.existed"
                rmdir -- "$txn" 2>/dev/null || true
            }
            trap cleanup_partial EXIT
            {{sshDirectoryAssignment}}
            test ! -L "$sshdir"
            if test -e "$sshdir"; then
                test -d "$sshdir"
                stat -c '%a %u %g' -- "$sshdir" > "$txn/directory.meta"
                touch -r "$sshdir" -- "$txn/directory.timestamps"
                : > "$txn/directory.existed"
                file="$sshdir/authorized_keys"
                test ! -L "$file"
                if test -e "$file"; then
                    test -f "$file"
                    cp -a -- "$file" "$txn/authorized_keys"
                    : > "$txn/file.existed"
                fi
            fi
            : > "$txn/ready"
            trap - EXIT
            """);
    }

    private static string BuildRestoreAuthorizedKeysCommand(
        string backupPath,
        bool rootTarget)
    {
        var sshDirectoryAssignment = rootTarget
            ? "sshdir=/root/.ssh"
            : "sshdir=\"$HOME/.ssh\"";
        var restoreDirectoryOwner = rootTarget
            ? "chown \"$directory_uid:$directory_gid\" -- \"$sshdir\""
            : ":";
        var protectTemporaryOwner = rootTarget
            ? "chown root:root -- \"$tmp\""
            : ":";
        return BuildShellCommand(
            $$"""
            set -eu
            umask 077
            txn={{ShellQuote(backupPath)}}
            test -d "$txn"
            test ! -L "$txn"
            test -f "$txn/ready"
            test ! -L "$txn/ready"
            cleanup_snapshot() {
                rm -f -- "$txn/ready" "$txn/file.existed" "$txn/directory.existed" "$txn/directory.meta" "$txn/directory.timestamps" "$txn/authorized_keys" "$txn/expected" "$txn/key.added" "$txn/key.existed"
                rmdir -- "$txn"
            }
            key=$(cat)
            set -- $key
            test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
            blob=$2
            {{sshDirectoryAssignment}}
            test ! -L "$sshdir"
            if test -f "$txn/directory.existed" && test ! -L "$txn/directory.existed"; then
                test -d "$sshdir"
                test -f "$txn/directory.meta"
                test ! -L "$txn/directory.meta"
                test -f "$txn/directory.timestamps"
                test ! -L "$txn/directory.timestamps"
                IFS=' ' read -r directory_mode directory_uid directory_gid < "$txn/directory.meta"
                test -n "$directory_mode"
                test -n "$directory_uid"
                test -n "$directory_gid"
                case "$directory_mode$directory_uid$directory_gid" in *[!0-9]*) exit 70 ;; esac
                file="$sshdir/authorized_keys"
                test ! -L "$file"
                original_file=false
                if test -e "$txn/file.existed"; then
                    test -f "$txn/file.existed"
                    test ! -L "$txn/file.existed"
                    test -f "$txn/authorized_keys"
                    test ! -L "$txn/authorized_keys"
                    original_file=true
                fi
                if test -e "$file"; then test -f "$file"; fi

                exact_state=false
                if test -f "$file" && test -f "$txn/expected" && test ! -L "$txn/expected" && cmp -s -- "$file" "$txn/expected"; then
                    exact_state=true
                elif test "$original_file" = true && test -f "$file" && cmp -s -- "$file" "$txn/authorized_keys"; then
                    exact_state=true
                elif test "$original_file" = false && test ! -e "$file"; then
                    exact_state=true
                fi

                if test "$exact_state" = true; then
                    if test "$original_file" = true; then
                        tmp=$(mktemp "$sshdir/.authorized_keys.restore.XXXXXXXXXX")
                        trap 'rm -f -- "$tmp"' EXIT
                        rm -f -- "$tmp"
                        cp -a -- "$txn/authorized_keys" "$tmp"
                        test ! -d "$file"
                        mv -f -- "$tmp" "$file"
                        trap - EXIT
                    else
                        rm -f -- "$file"
                    fi
                    {{restoreDirectoryOwner}}
                    chmod "$directory_mode" -- "$sshdir"
                    touch -r "$txn/directory.timestamps" -- "$sshdir"
                    cleanup_snapshot
                    exit 0
                fi

                if test -f "$txn/key.added" && test ! -L "$txn/key.added" && test -f "$file"; then
                    tmp=$(mktemp "$sshdir/.authorized_keys.rollback.XXXXXXXXXX")
                    trap 'rm -f -- "$tmp"' EXIT
                    awk -v blob="$blob" '!($1 == "ssh-ed25519" && $2 == blob)' "$file" > "$tmp"
                    {{protectTemporaryOwner}}
                    chmod 0600 -- "$tmp"
                    if test "$original_file" = false && test ! -s "$tmp"; then
                        rm -f -- "$tmp" "$file"
                        trap - EXIT
                        {{restoreDirectoryOwner}}
                        chmod "$directory_mode" -- "$sshdir"
                        touch -r "$txn/directory.timestamps" -- "$sshdir"
                    else
                        test ! -d "$file"
                        mv -f -- "$tmp" "$file"
                        trap - EXIT
                    fi
                    cleanup_snapshot
                    exit 0
                fi

                printf '%s\n' 'authorized_keys changed concurrently; refusing to replace it with the old snapshot' >&2
                exit 73
            else
                test ! -e "$txn/directory.existed"
                if test -e "$sshdir"; then
                    test -d "$sshdir"
                    file="$sshdir/authorized_keys"
                    test ! -L "$file"
                    if test -e "$file"; then test -f "$file"; fi

                    exact_state=false
                    if test -f "$file" && test -f "$txn/expected" && test ! -L "$txn/expected" && cmp -s -- "$file" "$txn/expected"; then
                        exact_state=true
                    elif test ! -e "$file"; then
                        exact_state=true
                    fi

                    if test "$exact_state" = true; then
                        rm -f -- "$file"
                        rmdir -- "$sshdir" 2>/dev/null || true
                        cleanup_snapshot
                        exit 0
                    fi

                    if test -f "$txn/key.added" && test ! -L "$txn/key.added" && test -f "$file"; then
                        tmp=$(mktemp "$sshdir/.authorized_keys.rollback.XXXXXXXXXX")
                        trap 'rm -f -- "$tmp"' EXIT
                        awk -v blob="$blob" '!($1 == "ssh-ed25519" && $2 == blob)' "$file" > "$tmp"
                        {{protectTemporaryOwner}}
                        chmod 0600 -- "$tmp"
                        if test ! -s "$tmp"; then
                            rm -f -- "$tmp" "$file"
                            trap - EXIT
                            rmdir -- "$sshdir" 2>/dev/null || true
                        else
                            test ! -d "$file"
                            mv -f -- "$tmp" "$file"
                            trap - EXIT
                        fi
                        cleanup_snapshot
                        exit 0
                    fi

                    printf '%s\n' 'authorized_keys changed concurrently; refusing to remove the directory' >&2
                    exit 73
                else
                    cleanup_snapshot
                    exit 0
                fi
            fi
            """);
    }

    private static string BuildCleanupAuthorizedKeysBackupCommand(string backupPath) =>
        BuildShellCommand(
            $"""
            set -eu
            txn={ShellQuote(backupPath)}
            if test ! -e "$txn"; then
                test ! -L "$txn"
                exit 0
            fi
            test -d "$txn"
            test ! -L "$txn"
            rm -f -- "$txn/ready" "$txn/file.existed" "$txn/directory.existed" "$txn/directory.meta" "$txn/directory.timestamps" "$txn/authorized_keys" "$txn/expected" "$txn/key.added" "$txn/key.existed"
            rmdir -- "$txn"
            """);

    private static string BuildSudoPayloadCommand(string commandText)
    {
        const string outerScript =
            "set -eu; umask 077; " +
            "work=$(mktemp -d /tmp/ssh-key-deployer-sudo.XXXXXXXXXX); " +
            "trap 'rm -f -- \"$work/payload\"; rmdir -- \"$work\"' EXIT; " +
            "IFS= read -r password; cat > \"$work/payload\"; " +
            "printf '%s\\n' \"$password\" | " +
            "sudo -k -S -p '' -- sh -c \"$1\" sh \"$work/payload\"";
        var privilegedScript = $"exec {commandText} < \"$1\"";
        return $"sh -c {ShellQuote(outerScript)} sh {ShellQuote(privilegedScript)}";
    }

    private static void AssertEffectiveSettings(
        string output,
        DeploymentRequest request,
        string contextUsername)
    {
        var settings = ParseEffectiveSettings(output);

        RequireEffectiveValue(settings, "pubkeyauthentication", "yes");

        var isRootContext = contextUsername.Equals("root", StringComparison.Ordinal);
        var contextCanAuthenticate = !isRootContext || request.EnableRootLogin;
        if (contextCanAuthenticate)
        {
            RequireEffectiveValue(
                settings,
                "passwordauthentication",
                request.AllowPasswordLogin ? "yes" : "no");
            RequireEffectiveValue(settings, "kbdinteractiveauthentication", "no");
        }

        if (isRootContext)
        {
            var expectedRoot = request.EnableRootLogin
                ? request.AllowPasswordLogin ? "yes" : "prohibit-password"
                : "no";
            if (!settings.TryGetValue("permitrootlogin", out var actualRoot) ||
                !(string.Equals(actualRoot, expectedRoot, StringComparison.OrdinalIgnoreCase) ||
                  expectedRoot == "prohibit-password" &&
                  string.Equals(actualRoot, "without-password", StringComparison.OrdinalIgnoreCase)))
            {
                throw new DeploymentException(
                    $"Effective sshd setting permitrootlogin is '{actualRoot ?? "missing"}', expected '{expectedRoot}'.");
            }
        }
    }

    private static IReadOnlyDictionary<string, string> ParseEffectiveSettings(string output) =>
        output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries))
            .Where(parts => parts.Length == 2)
            .GroupBy(parts => parts[0], StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.First()[1].Trim(),
                StringComparer.OrdinalIgnoreCase);

    private static void RequireEffectiveValue(
        IReadOnlyDictionary<string, string> settings,
        string name,
        string expected)
    {
        if (!settings.TryGetValue(name, out var actual) ||
            !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new DeploymentException(
                $"Effective sshd setting {name} is '{actual ?? "missing"}', expected '{expected}'.");
        }
    }

    private static bool IsSafeTemporaryConfigPath(string? value) =>
        value is not null &&
        value.StartsWith(
            "/etc/ssh/sshd_config.d/.ssh-key-deployer.",
            StringComparison.Ordinal) &&
        value.Length <= 128 &&
        value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '/' or '.' or '-' or '_');

    private static bool IsSafeConnectionHost(string value) =>
        value.Length is > 0 and <= 253 &&
        !value.Contains(',', StringComparison.Ordinal) &&
        (IPAddress.TryParse(value, out _) || Uri.CheckHostName(value) != UriHostNameType.Unknown);

    private static string ShellQuote(string value) =>
        $"'{value.Replace("'", "'\"'\"'", StringComparison.Ordinal)}'";

    private static string SafeExceptionMessage(Exception exception, string password) =>
        Redact(exception.Message, password);

    private static string SafeExceptionMessage(Exception exception, DeploymentRequest request) =>
        request.RootPassword is null
            ? Redact(exception.Message, request.Password)
            : Redact(Redact(exception.Message, request.Password), request.RootPassword);

    private static string Redact(string value, string password) =>
        string.IsNullOrEmpty(password)
            ? value
            : value.Replace(password, "[redacted]", StringComparison.Ordinal);

    private static string LimitOutput(string value)
    {
        const int maximumLength = 16 * 1024;
        var trimmed = value.Trim();
        return trimmed.Length <= maximumLength
            ? trimmed
            : trimmed[..maximumLength] + "...";
    }

    private static readonly string InstallCurrentUserKeyCommand = BuildShellCommand(
        """
        set -eu
        umask 077
        IFS= read -r txn
        case "$txn" in /tmp/ssh-key-deployer-authorized-[0-9a-f]*) ;; *) exit 66 ;; esac
        test -d "$txn"
        test ! -L "$txn"
        test -f "$txn/ready"
        test ! -L "$txn/ready"
        sshdir="$HOME/.ssh"
        test ! -L "$sshdir"
        install -d -m 0700 -- "$sshdir"
        file="$sshdir/authorized_keys"
        test ! -L "$file"
        touch -- "$file"
        chmod 0600 -- "$file"
        key=$(cat)
        set -- $key
        test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
        blob=$2
        if awk -v blob="$blob" '$1 == "ssh-ed25519" && $2 == blob { found=1 } END { exit !found }' "$file"; then
            cp -a -- "$file" "$txn/expected"
            : > "$txn/key.existed"
            if test -x /usr/sbin/restorecon; then /usr/sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; elif test -x /sbin/restorecon; then /sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; fi
            printf 'EXISTS\n'
            exit 0
        fi
        tmp=$(mktemp "$sshdir/.authorized_keys.XXXXXXXXXX")
        trap 'rm -f -- "$tmp"' EXIT
        cat -- "$file" > "$tmp"
        test ! -s "$tmp" || printf '\n' >> "$tmp"
        printf '%s\n' "$key" >> "$tmp"
        chmod 0600 -- "$tmp"
        cp -a -- "$tmp" "$txn/expected"
        : > "$txn/key.added"
        test ! -d "$file"
        mv -f -- "$tmp" "$file"
        trap - EXIT
        if test -x /usr/sbin/restorecon; then /usr/sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; elif test -x /sbin/restorecon; then /sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; fi
        printf 'ADDED\n'
        """);

    private static readonly string InstallRootKeyCommand = BuildShellCommand(
        """
        set -eu
        umask 077
        IFS= read -r txn
        case "$txn" in /tmp/ssh-key-deployer-authorized-[0-9a-f]*) ;; *) exit 66 ;; esac
        test -d "$txn"
        test ! -L "$txn"
        test -f "$txn/ready"
        test ! -L "$txn/ready"
        sshdir=/root/.ssh
        test ! -L "$sshdir"
        install -d -o root -g root -m 0700 -- "$sshdir"
        file="$sshdir/authorized_keys"
        test ! -L "$file"
        touch -- "$file"
        chown root:root -- "$file"
        chmod 0600 -- "$file"
        key=$(cat)
        set -- $key
        test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
        blob=$2
        if awk -v blob="$blob" '$1 == "ssh-ed25519" && $2 == blob { found=1 } END { exit !found }' "$file"; then
            cp -a -- "$file" "$txn/expected"
            : > "$txn/key.existed"
            if test -x /usr/sbin/restorecon; then /usr/sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; elif test -x /sbin/restorecon; then /sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; fi
            printf 'EXISTS\n'
            exit 0
        fi
        tmp=$(mktemp "$sshdir/.authorized_keys.XXXXXXXXXX")
        trap 'rm -f -- "$tmp"' EXIT
        cat -- "$file" > "$tmp"
        test ! -s "$tmp" || printf '\n' >> "$tmp"
        printf '%s\n' "$key" >> "$tmp"
        chown root:root -- "$tmp"
        chmod 0600 -- "$tmp"
        cp -a -- "$tmp" "$txn/expected"
        : > "$txn/key.added"
        test ! -d "$file"
        mv -f -- "$tmp" "$file"
        trap - EXIT
        if test -x /usr/sbin/restorecon; then /usr/sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; elif test -x /sbin/restorecon; then /sbin/restorecon -R "$sshdir" >/dev/null 2>&1 || true; fi
        printf 'ADDED\n'
        """);

    private static readonly string RemoveCurrentUserKeyCommand = BuildShellCommand(
        """
        set -eu
        sshdir="$HOME/.ssh"
        file="$sshdir/authorized_keys"
        test -f "$file" || exit 0
        test ! -L "$sshdir"
        test ! -L "$file"
        key=$(cat)
        set -- $key
        test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
        blob=$2
        tmp=$(mktemp "$sshdir/.authorized_keys.XXXXXXXXXX")
        trap 'rm -f -- "$tmp"' EXIT
        awk -v blob="$blob" '!($1 == "ssh-ed25519" && $2 == blob)' "$file" > "$tmp"
        chmod 0600 -- "$tmp"
        test ! -d "$file"
        mv -f -- "$tmp" "$file"
        trap - EXIT
        """);

    private static readonly string RemoveRootKeyCommand = BuildShellCommand(
        """
        set -eu
        sshdir=/root/.ssh
        file="$sshdir/authorized_keys"
        test -f "$file" || exit 0
        test ! -L "$sshdir"
        test ! -L "$file"
        key=$(cat)
        set -- $key
        test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
        blob=$2
        tmp=$(mktemp "$sshdir/.authorized_keys.XXXXXXXXXX")
        trap 'rm -f -- "$tmp"' EXIT
        awk -v blob="$blob" '!($1 == "ssh-ed25519" && $2 == blob)' "$file" > "$tmp"
        chown root:root -- "$tmp"
        chmod 0600 -- "$tmp"
        test ! -d "$file"
        mv -f -- "$tmp" "$file"
        trap - EXIT
        """);

    private static string BuildShellCommand(string script) =>
        $"sh -c {ShellQuote(script.Replace("\r", string.Empty, StringComparison.Ordinal))}";

    private sealed class ProgressReporter
    {
        private readonly DeploymentProgressCallback? _callback;
        private readonly SynchronizationContext? _synchronizationContext;

        public ProgressReporter(
            DeploymentProgressCallback? callback,
            SynchronizationContext? synchronizationContext)
        {
            _callback = callback;
            _synchronizationContext = synchronizationContext;
        }

        public void Report(DeploymentStage stage, string message, int percent)
        {
            if (_callback is null)
            {
                return;
            }

            var progress = new DeploymentProgress(stage, message, percent);
            if (_synchronizationContext is null ||
                ReferenceEquals(SynchronizationContext.Current, _synchronizationContext))
            {
                TryReport(progress);
                return;
            }

            _synchronizationContext.Post(state => TryReport((DeploymentProgress)state!), progress);
        }

        public Task<bool> InvokeHostKeyApprovalAsync(
            HostKeyApprovalCallback callback,
            HostKeyInfo hostKey,
            CancellationToken cancellationToken) =>
            InvokeOnContextAsync(() => callback(hostKey, cancellationToken));

        public Task<bool> InvokeOnContextAsync(Func<Task<bool>> callback)
        {
            if (_synchronizationContext is null ||
                ReferenceEquals(SynchronizationContext.Current, _synchronizationContext))
            {
                return callback();
            }

            var completion = new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _synchronizationContext.Post(
                async _ =>
                {
                    try
                    {
                        completion.TrySetResult(await callback());
                    }
                    catch (OperationCanceledException exception)
                    {
                        completion.TrySetCanceled(exception.CancellationToken);
                    }
                    catch (Exception exception)
                    {
                        completion.TrySetException(exception);
                    }
                },
                null);
            return completion.Task;
        }

        private void TryReport(DeploymentProgress progress)
        {
            try
            {
                _callback?.Invoke(progress);
            }
            catch
            {
                // Progress observers cannot be allowed to interrupt a security transaction.
            }
        }
    }

    private sealed class DeploymentState
    {
        public DeploymentState(string targetUsername, string backupPath)
        {
            TargetUsername = targetUsername;
            BackupPath = backupPath;
            CurrentUserKeyBackupPath =
                $"/tmp/ssh-key-deployer-authorized-{Guid.NewGuid():N}";
            RootKeyBackupPath =
                $"/tmp/ssh-key-deployer-authorized-{Guid.NewGuid():N}";
        }

        public string TargetUsername { get; }

        public string BackupPath { get; }

        public string CurrentUserKeyBackupPath { get; }

        public string RootKeyBackupPath { get; }

        public bool SessionIsRoot { get; set; }

        public bool CurrentUserIsRoot { get; set; }

        public bool CurrentUserKeySnapshotMayExist { get; set; }

        public bool CurrentUserKeyMutationMayHaveStarted { get; set; }

        public bool RootKeySnapshotMayExist { get; set; }

        public bool RootKeyMutationMayHaveStarted { get; set; }

        public bool ConfigOriginallyExisted { get; set; }

        public bool BackupCreated { get; set; }

        public bool ConfigModified { get; set; }

        public string? TempConfigPath { get; set; }

        public EffectiveConnectionContext ConnectionContext { get; set; } = null!;

        public PrivilegeMode Privilege { get; set; } = PrivilegeMode.None;

        public LinuxFamily Family { get; set; } = LinuxFamily.Unknown;

        public string OsName { get; set; } = "this server";

        public bool SudoInstalled { get; set; }

        public bool SemanageInstalled { get; set; }

        public ServerInfo? Server { get; set; }

        public IReadOnlyList<int> MainConfigPorts { get; set; } = Array.Empty<int>();

        public IReadOnlyList<int> ManagedPorts { get; set; } = Array.Empty<int>();

        public bool SocketActivated { get; set; }

        public List<string> InstalledPackages { get; } = [];

        public string? SudoersDropInPath { get; set; }

        public string? SudoersTemporaryPath { get; set; }

        public bool SudoersDropInMayExist { get; set; }

        public bool TemporarySudoReady { get; set; }

        public int? NewPort { get; set; }

        public bool PortConfigWritten { get; set; }

        public bool UfwRuleMayBeAdded { get; set; }

        public bool FirewalldRuntimeMayBeAdded { get; set; }

        public bool FirewalldPermanentMayBeAdded { get; set; }

        public bool SelinuxPortMayBeAdded { get; set; }
    }

    private sealed record SudoCheck(
        bool Succeeded,
        SudoAccessFailureReason? Reason,
        string Diagnostic,
        RemoteCommandResult Result);

    private sealed record EffectiveConnectionContext(
        string ClientHost,
        string ClientAddress,
        string LocalAddress,
        int LocalPort)
    {
        public string ToSshdConnectionSpec(string username) =>
            $"user={username},host={ClientHost},addr={ClientAddress},laddr={LocalAddress},lport={LocalPort}";
    }

    private sealed record RemoteCommandResult(
        int ExitStatus,
        string StandardOutput,
        string StandardError);

    private sealed record ApprovedHostKey(HostKeyInfo Info, byte[] KeyData);

    private sealed record RecoveryResult(bool Attempted, bool Succeeded, string Detail)
    {
        public static RecoveryResult NotAttempted { get; } =
            new(Attempted: false, Succeeded: true, Detail: string.Empty);
    }
}
