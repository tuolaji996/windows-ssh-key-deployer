using System.Reflection;
using SshKeyDeployer.Core;

var tests = new (string Name, Func<Task> Run)[]
{
    ("Request normalization and password redaction", TestRequestNormalizationAsync),
    ("Deployment input validation", TestValidationAsync),
    ("SSH policy rendering", TestSshPolicyRenderingAsync),
    ("Managed drop-in path precedence", TestManagedPathAsync),
    ("Remote command safety contracts", TestRemoteCommandSafetyAsync),
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
    bool enableRootLogin = true,
    bool allowPasswordLogin = true) =>
    new(
        host,
        port,
        username,
        password,
        Path.Combine(Path.GetTempPath(), "server_ed25519"),
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
