using System.Net.Sockets;
using System.Reflection;
using Renci.SshNet.Common;
using SshKeyDeployer.Core;

var tests = new (string Name, Func<Task> Run)[]
{
    ("Request normalization and password redaction", TestRequestNormalizationAsync),
    ("Deployment input validation", TestValidationAsync),
    ("SSH policy rendering", TestSshPolicyRenderingAsync),
    ("Managed drop-in path precedence", TestManagedPathAsync),
    ("Remote command safety contracts", TestRemoteCommandSafetyAsync),
    ("Initial SSH connection diagnosis", TestInitialConnectionGuidanceAsync),
    ("Sudo failure diagnosis and recovery guidance", TestSudoGuidanceAsync),
    ("Windows private-key local path policy", TestPrivateKeyPathPolicyAsync),
    ("Ed25519 generation, ACL, reuse, and collision safety", TestKeyLifecycleAsync)
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine($"PASS  {test.Name}");
    }
    catch (Exception exception)
    {
        failures.Add($"{test.Name}: {exception}");
        Console.WriteLine($"FAIL  {test.Name}");
    }
}

if (failures.Count > 0)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("Self-test failures:");
    foreach (var failure in failures)
    {
        Console.Error.WriteLine($"- {failure}");
    }

    return 1;
}

Console.WriteLine();
Console.WriteLine($"All {tests.Length} self-tests passed.");
return 0;

static Task TestRequestNormalizationAsync()
{
    const string passwordCanary = "self-test-password-canary";
    var request = new DeploymentRequest(
        " [2001:db8::1] ",
        2222,
        "root",
        passwordCanary,
        Path.Combine(Path.GetTempPath(), "server_ed25519"),
        enableRootLogin: true,
        allowPasswordLogin: true);

    AssertEqual("2001:db8::1", request.Host, "Bracketed IPv6 host was not normalized.");
    Assert(!request.ToString().Contains(passwordCanary, StringComparison.Ordinal),
        "DeploymentRequest.ToString exposed the password.");
    Assert(request.ToString().Contains("[redacted]", StringComparison.Ordinal),
        "DeploymentRequest.ToString did not mark the password as redacted.");
    return Task.CompletedTask;
}

static Task TestValidationAsync()
{
    var valid = NewRequest(
        host: "debian.example.test",
        username: "deploy_user",
        enableRootLogin: false);
    Assert(DeploymentRequestValidator.Validate(valid, requireExistingKey: false).IsValid,
        "A valid Debian deployment request was rejected.");

    var invalidHost = NewRequest(host: "ssh://example.test:2222");
    AssertHasError(invalidHost, nameof(DeploymentRequest.Host));

    var hostWithPort = NewRequest(host: "example.test:2222");
    AssertHasError(hostWithPort, nameof(DeploymentRequest.Host));

    var invalidPort = NewRequest(port: 0);
    AssertHasError(invalidPort, nameof(DeploymentRequest.Port));

    var invalidUser = NewRequest(username: "Root Admin");
    AssertHasError(invalidUser, nameof(DeploymentRequest.Username));

    var rootConflict = NewRequest(username: "root", enableRootLogin: false);
    AssertHasError(rootConflict, nameof(DeploymentRequest.EnableRootLogin));

    var missingPassword = NewRequest(password: string.Empty);
    AssertHasError(missingPassword, nameof(DeploymentRequest.Password));

    var multilinePassword = NewRequest(password: "line-" + "one\nline-two");
    AssertHasError(multilinePassword, nameof(DeploymentRequest.Password));
    return Task.CompletedTask;
}

static Task TestSshPolicyRenderingAsync()
{
    var method = typeof(DeploymentService).GetMethod(
        "BuildManagedConfig",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("BuildManagedConfig was not found.");

    var rootWithPassword = RenderPolicy(method, NewRequest(
        username: "root",
        enableRootLogin: true,
        allowPasswordLogin: true));
    AssertContains(rootWithPassword, "PubkeyAuthentication yes");
    AssertContains(rootWithPassword, "PasswordAuthentication yes");
    AssertContains(rootWithPassword, "KbdInteractiveAuthentication no");
    AssertContains(rootWithPassword, "PermitRootLogin yes");

    var rootKeyOnly = RenderPolicy(method, NewRequest(
        username: "root",
        enableRootLogin: true,
        allowPasswordLogin: false));
    AssertContains(rootKeyOnly, "PasswordAuthentication no");
    AssertContains(rootKeyOnly, "PermitRootLogin prohibit-password");

    var rootDisabled = RenderPolicy(method, NewRequest(
        username: "debian",
        enableRootLogin: false,
        allowPasswordLogin: true));
    AssertContains(rootDisabled, "PasswordAuthentication yes");
    AssertContains(rootDisabled, "PermitRootLogin no");

    var assertEffective = typeof(DeploymentService).GetMethod(
        "AssertEffectiveSettings",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("AssertEffectiveSettings was not found.");
    AssertEffectiveSettings(
        assertEffective,
        "pubkeyauthentication yes\npasswordauthentication yes\nkbdinteractiveauthentication no\npermitrootlogin forced-commands-only\n",
        NewRequest(username: "debian", enableRootLogin: false, allowPasswordLogin: true),
        "debian");
    AssertEffectiveSettings(
        assertEffective,
        "pubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication yes\npermitrootlogin no\n",
        NewRequest(username: "debian", enableRootLogin: false, allowPasswordLogin: true),
        "root");
    return Task.CompletedTask;
}

static Task TestManagedPathAsync()
{
    AssertEqual(
        "/etc/ssh/sshd_config.d/00-ssh-key-deployer.conf",
        DeploymentService.ManagedConfigPath,
        "The managed Debian drop-in no longer has the expected early lexical name.");
    return Task.CompletedTask;
}

static Task TestRemoteCommandSafetyAsync()
{
    var type = typeof(DeploymentService);
    foreach (var fieldName in new[]
             {
                 "InstallCurrentUserKeyCommand",
                 "InstallRootKeyCommand",
                 "RemoveCurrentUserKeyCommand",
                 "RemoveRootKeyCommand"
             })
    {
        var command = type.GetField(fieldName, BindingFlags.Static | BindingFlags.NonPublic)
            ?.GetValue(null) as string
            ?? throw new InvalidOperationException($"{fieldName} was not found.");
        AssertContains(command, "test ! -L");
        AssertContains(command, "mktemp");
        AssertContains(command, "mv -fT");
        AssertContains(command, "awk -v blob=");
        if (fieldName.StartsWith("Install", StringComparison.Ordinal))
        {
            AssertContains(command, "$txn/expected");
            AssertContains(command, "$txn/key.added");
        }
    }

    var restoreBuilder = type.GetMethod(
        "BuildRestoreAuthorizedKeysCommand",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("BuildRestoreAuthorizedKeysCommand was not found.");
    var restoreCommand = restoreBuilder.Invoke(
        null,
        ["/tmp/ssh-key-deployer-authorized-0123456789abcdef0123456789abcdef", false]) as string
        ?? throw new InvalidOperationException("BuildRestoreAuthorizedKeysCommand did not return text.");
    AssertContains(restoreCommand, "test -f \"$txn/ready\"");
    AssertContains(restoreCommand, "cmp -s");
    AssertContains(restoreCommand, ".authorized_keys.restore.");
    AssertContains(restoreCommand, "changed concurrently");
    Assert(!restoreCommand.Contains("if test ! -e \"$txn\"; then", StringComparison.Ordinal),
        "A missing rollback snapshot is still treated as success.");

    var sudoBuilder = type.GetMethod(
        "BuildSudoPayloadCommand",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("BuildSudoPayloadCommand was not found.");
    var sudoCommand = sudoBuilder.Invoke(null, ["cat"]) as string
        ?? throw new InvalidOperationException("BuildSudoPayloadCommand did not return text.");
    AssertContains(sudoCommand, "mktemp -d");
    AssertContains(sudoCommand, "sudo -k -S");
    AssertContains(sudoCommand, "exec cat <");
    return Task.CompletedTask;
}

static Task TestSudoGuidanceAsync()
{
    var classifier = typeof(DeploymentService).GetMethod(
        "ClassifySudoAccessFailure",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException(
            "ClassifySudoAccessFailure was not found.");

    AssertEqual(
        SudoAccessFailureReason.NotAuthorized,
        InvokeKnownSudoClassifier(
            classifier,
            "sudo: spencer is not in the sudoers file."),
        "A sudoers denial was classified incorrectly.");
    AssertEqual(
        SudoAccessFailureReason.CommandUnavailable,
        InvokeKnownSudoClassifier(
            classifier,
            "sh: 1: sudo: not found"),
        "A missing sudo command was classified incorrectly.");
    AssertEqual(
        SudoAccessFailureReason.AuthenticationRejected,
        InvokeKnownSudoClassifier(
            classifier,
            "sudo: 1 incorrect password attempt"),
        "A sudo password rejection was classified incorrectly.");
    Assert(
        InvokeSudoClassifier(classifier, "unrelated remote failure") is null,
        "An unrelated remote failure was misclassified as a sudo setup problem.");

    const string diagnosticCanary = "test-only-password";
    var exception = new SudoAccessException(
        "spencer",
        SudoAccessFailureReason.NotAuthorized,
        $"spencer is not in the sudoers file. password={diagnosticCanary}");
    AssertContains(exception.Message, "SSH password login succeeded");
    AssertContains(exception.Message, "Using 'su' with the root password is different");
    AssertContains(exception.Message, "adduser spencer sudo");
    AssertContains(exception.Message, "fully sign out");
    Assert(
        !exception.Message.Contains(diagnosticCanary, StringComparison.Ordinal),
        "Sudo guidance exposed a password from the server diagnostic.");
    return Task.CompletedTask;
}

static Task TestInitialConnectionGuidanceAsync()
{
    var classifier = typeof(DeploymentService).GetMethod(
        "ClassifyInitialSshConnectionFailure",
        BindingFlags.Static | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException(
            "ClassifyInitialSshConnectionFailure was not found.");

    AssertEqual(
        InitialSshConnectionFailureReason.AuthenticationRejected,
        InvokeInitialConnectionClassifier(
            classifier,
            new SshAuthenticationException("Permission denied.")),
        "A password-authentication rejection was classified incorrectly.");
    AssertEqual(
        InitialSshConnectionFailureReason.TimedOut,
        InvokeInitialConnectionClassifier(
            classifier,
            new SshOperationTimeoutException("Connection timed out.")),
        "An SSH timeout was classified incorrectly.");
    AssertEqual(
        InitialSshConnectionFailureReason.NetworkUnavailable,
        InvokeInitialConnectionClassifier(
            classifier,
            new InvalidOperationException(
                "Wrapped network failure.",
                new SocketException((int)SocketError.ConnectionRefused))),
        "A wrapped socket failure was classified incorrectly.");
    AssertEqual(
        InitialSshConnectionFailureReason.Unknown,
        InvokeInitialConnectionClassifier(
            classifier,
            new InvalidOperationException("Unrelated connection failure.")),
        "An unknown connection failure was classified incorrectly.");

    const string passwordCanary = "password-must-not-appear";
    var exception = new InitialSshConnectionException(
        "debian.example.test",
        22,
        "spencer",
        InitialSshConnectionFailureReason.AuthenticationRejected,
        new SshAuthenticationException(passwordCanary));
    AssertContains(exception.Message, "password authentication was rejected");
    AssertContains(exception.Message, "spencer");
    Assert(
        !exception.Message.Contains(passwordCanary, StringComparison.Ordinal),
        "Initial connection guidance exposed the underlying exception text.");
    return Task.CompletedTask;
}

static InitialSshConnectionFailureReason InvokeInitialConnectionClassifier(
    MethodInfo classifier,
    Exception exception) =>
    (InitialSshConnectionFailureReason)(classifier.Invoke(null, [exception])
        ?? throw new InvalidOperationException(
            "Initial SSH connection classifier returned null."));

static async Task TestPrivateKeyPathPolicyAsync()
{
    if (!OperatingSystem.IsWindows())
    {
        return;
    }

    const string uncPath = @"\\server.example.test\keys\server_ed25519";
    Assert(
        PrivateKeyPathPolicy.IsUnsupportedWindowsNetworkPath(uncPath),
        "A UNC private-key path was accepted as a local Windows path.");
    Assert(
        !PrivateKeyPathPolicy.IsUnsupportedWindowsNetworkPath(
            Path.Combine(Path.GetTempPath(), "server_ed25519")),
        "A local Windows private-key path was rejected.");
    Assert(
        !PrivateKeyPathPolicy.IsUnsupportedWindowsNetworkPath(
            @"\\?\C:\Users\example\server_ed25519"),
        "An extended-length local Windows path was mistaken for a network path.");

    var mappedNetworkDrive = DriveInfo.GetDrives()
        .FirstOrDefault(drive => drive.DriveType == DriveType.Network);
    if (mappedNetworkDrive is not null)
    {
        var mappedPath = Path.Combine(
            mappedNetworkDrive.RootDirectory.FullName,
            "server_ed25519");
        Assert(
            PrivateKeyPathPolicy.IsUnsupportedWindowsNetworkPath(mappedPath),
            "A mapped network drive was accepted as a local Windows path.");
    }

    var validation = DeploymentRequestValidator.Validate(
        NewRequest(keyPath: uncPath),
        requireExistingKey: false);
    Assert(
        validation.Errors.Any(error =>
            error.PropertyName == nameof(DeploymentRequest.KeyPath) &&
            error.Message == PrivateKeyPathPolicy.WindowsNetworkPathErrorMessage),
        "Deployment validation did not explain the Windows network-path restriction.");

    await AssertThrowsAsync<KeyGenerationException>(
        () => new KeyGenerator().GenerateAsync(uncPath),
        "Key generation attempted to write a private key to a UNC path.");
}

static SudoAccessFailureReason? InvokeSudoClassifier(
    MethodInfo classifier,
    string diagnostic) =>
    (SudoAccessFailureReason?)classifier.Invoke(null, [diagnostic]);

static SudoAccessFailureReason InvokeKnownSudoClassifier(
    MethodInfo classifier,
    string diagnostic) =>
    InvokeSudoClassifier(classifier, diagnostic)
    ?? throw new InvalidOperationException(
        $"Known sudo diagnostic was not classified: {diagnostic}");

static async Task TestKeyLifecycleAsync()
{
    var testDirectory = Path.Combine(
        Path.GetTempPath(),
        "ssh-key-deployer-selftest",
        Guid.NewGuid().ToString("N"));
    var keyPath = Path.Combine(testDirectory, "keys", "selftest_ed25519");

    try
    {
        var generator = new KeyGenerator();
        var generated = await generator.GenerateAsync(keyPath);
        Assert(File.Exists(generated.PrivateKeyPath), "Private key was not created.");
        Assert(File.Exists(generated.PublicKeyPath), "Public key was not created.");
        Assert(generated.PublicKey.StartsWith("ssh-ed25519 ", StringComparison.Ordinal),
            "Generated public key is not Ed25519.");
        Assert(generated.Sha256Fingerprint.StartsWith("SHA256:", StringComparison.Ordinal),
            "Generated key fingerprint is not SHA256.");

        var protector = new PrivateKeyAclProtector();
        Assert(protector.IsSecure(generated.PrivateKeyPath),
            OperatingSystem.IsWindows()
                ? "Private-key ACL was not restricted to the current user and SYSTEM."
                : "Private-key mode was not restricted to owner read/write.");

        if (!OperatingSystem.IsWindows())
        {
            AssertEqual(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                File.GetUnixFileMode(Path.GetDirectoryName(generated.PrivateKeyPath)!),
                "A newly created private-key directory was not exactly 0700.");
            AssertEqual(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(generated.PrivateKeyPath),
                "Private-key mode was not exactly 0600.");

            var linkedPrivateKeyPath = Path.Combine(testDirectory, "linked_ed25519");
            File.CreateSymbolicLink(linkedPrivateKeyPath, generated.PrivateKeyPath);
            Assert(!protector.IsSecure(linkedPrivateKeyPath),
                "A symbolic-link private key was accepted as secure.");
            await AssertThrowsAsync<UnauthorizedAccessException>(
                () => Task.Run(() => protector.Protect(linkedPrivateKeyPath)),
                "A symbolic-link private key was protected instead of rejected.");
        }

        var reused = await generator.ReadExistingAsync(keyPath);
        AssertEqual(generated.Sha256Fingerprint, reused.Sha256Fingerprint,
            "Reading the existing pair changed its fingerprint.");

        await AssertThrowsAsync<KeyGenerationException>(
            () => generator.GenerateAsync(keyPath),
            "Existing key files were overwritten instead of rejected.");

        var secondKeyPath = Path.Combine(testDirectory, "second_ed25519");
        var second = await generator.GenerateAsync(secondKeyPath);
        File.Copy(second.PublicKeyPath, generated.PublicKeyPath, overwrite: true);
        await AssertThrowsAsync<KeyGenerationException>(
            () => generator.ReadExistingAsync(keyPath),
            "A mismatched private/public key pair was accepted.");
    }
    finally
    {
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }
}

static DeploymentRequest NewRequest(
    string host = "192.0.2.10",
    int port = 22,
    string username = "root",
    string password = "test-" + "only-password",
    string? keyPath = null,
    bool enableRootLogin = true,
    bool allowPasswordLogin = true) =>
    new(
        host,
        port,
        username,
        password,
        keyPath ?? Path.Combine(Path.GetTempPath(), "server_ed25519"),
        enableRootLogin,
        allowPasswordLogin);

static string RenderPolicy(MethodInfo method, DeploymentRequest request) =>
    method.Invoke(null, [request]) as string
    ?? throw new InvalidOperationException("BuildManagedConfig did not return text.");

static void AssertEffectiveSettings(
    MethodInfo method,
    string output,
    DeploymentRequest request,
    string contextUsername)
{
    try
    {
        method.Invoke(null, [output, request, contextUsername]);
    }
    catch (TargetInvocationException exception) when (exception.InnerException is not null)
    {
        throw new InvalidOperationException(
            $"Effective sshd settings were rejected for context '{contextUsername}'.",
            exception.InnerException);
    }
}

static void AssertHasError(DeploymentRequest request, string propertyName)
{
    var result = DeploymentRequestValidator.Validate(request, requireExistingKey: false);
    Assert(result.Errors.Any(error => error.PropertyName == propertyName),
        $"Expected a validation error for {propertyName}.");
}

static async Task AssertThrowsAsync<TException>(Func<Task> action, string message)
    where TException : Exception
{
    try
    {
        await action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException(message);
}

static void AssertContains(string value, string expected)
{
    Assert(value.Contains(expected, StringComparison.Ordinal),
        $"Expected policy line '{expected}'.");
}

static void AssertEqual<T>(T expected, T actual, string message)
    where T : notnull
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"{message} Expected '{expected}', got '{actual}'.");
    }
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
