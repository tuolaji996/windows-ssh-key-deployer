using System.Diagnostics;
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
    ("Server probe parsing and distribution detection", TestServerProbeParsingAsync),
    ("Root probe parsing", TestRootProbeParsingAsync),
    ("Privilege decision", TestPrivilegeDecisionAsync),
    ("Deployment plan building", TestPlanBuildingAsync),
    ("Distribution-aware privilege guidance", TestPrivilegeGuidanceAsync),
    ("su prompt handling and failure classification", TestSuHandlingAsync),
    ("Remote script portability and syntax", TestRemoteScriptSyntaxAsync),
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

    const string rootPasswordCanary = "self-test-root-canary";
    var withRoot = new DeploymentRequest(
        "192.0.2.10",
        22,
        "deploy",
        passwordCanary,
        Path.Combine(Path.GetTempPath(), "server_ed25519"),
        enableRootLogin: false,
        allowPasswordLogin: true,
        rootPassword: rootPasswordCanary,
        newSshPort: 2222);
    Assert(!withRoot.ToString().Contains(rootPasswordCanary, StringComparison.Ordinal),
        "DeploymentRequest.ToString exposed the root password.");
    AssertEqual(2222, withRoot.NewSshPort ?? 0, "The new SSH port was not kept.");
    AssertEqual("deploy", withRoot.TargetUsername, "The target account is wrong without root login.");
    Assert(new DeploymentRequest("h", 22, "u", "p", "/k", true, true, rootPassword: string.Empty).RootPassword is null,
        "An empty root password was not treated as absent.");
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

    var multilineRootPassword = NewRequest(rootPassword: "root-" + "one\nroot-two");
    AssertHasError(multilineRootPassword, nameof(DeploymentRequest.RootPassword));

    AssertHasError(NewRequest(newSshPort: 0), nameof(DeploymentRequest.NewSshPort));
    AssertHasError(NewRequest(newSshPort: 65536), nameof(DeploymentRequest.NewSshPort));
    AssertHasError(NewRequest(port: 2222, newSshPort: 2222), nameof(DeploymentRequest.NewSshPort));
    Assert(DeploymentRequestValidator.Validate(NewRequest(newSshPort: 2222), requireExistingKey: false).IsValid,
        "A valid new SSH port was rejected.");
    return Task.CompletedTask;
}

static Task TestSshPolicyRenderingAsync()
{
    var method = typeof(DeploymentService).GetMethod(
        "BuildManagedConfig",
        BindingFlags.Static | BindingFlags.NonPublic,
        binder: null,
        [typeof(DeploymentRequest)],
        modifiers: null)
        ?? throw new InvalidOperationException("BuildManagedConfig was not found.");
    var portMethod = typeof(DeploymentService).GetMethod(
        "BuildManagedConfig",
        BindingFlags.Static | BindingFlags.NonPublic,
        binder: null,
        [typeof(DeploymentRequest), typeof(IReadOnlyList<int>)],
        modifiers: null)
        ?? throw new InvalidOperationException("BuildManagedConfig(ports) was not found.");
    var withPorts = portMethod.Invoke(null, [NewRequest(), new[] { 22, 2222 }]) as string
        ?? throw new InvalidOperationException("BuildManagedConfig(ports) did not return text.");
    AssertContains(withPorts, "Port 22\nPort 2222\n");
    Assert(!RenderPolicy(method, NewRequest()).Contains("Port ", StringComparison.Ordinal),
        "A policy without a port change wrote Port lines.");

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
        AssertContains(command, "test ! -d \"$file\"");
        AssertContains(command, "mv -f --");
        Assert(!command.Contains("mv -fT", StringComparison.Ordinal) && !command.Contains("mv -T", StringComparison.Ordinal),
            $"{fieldName} still uses GNU-only mv -T, which BusyBox does not support.");
        AssertContains(command, "awk -v blob=");
        if (fieldName.StartsWith("Install", StringComparison.Ordinal))
        {
            AssertContains(command, "$txn/expected");
            AssertContains(command, "$txn/key.added");
            AssertContains(command, "restorecon -R");
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
    AssertContains(exception.Message, "usermod -aG sudo spencer");
    AssertContains(exception.Message, "Root password");
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

static Task TestServerProbeParsingAsync()
{
    var ubuntu = ServerInspection.ParseUnprivilegedProbe(
        "uid=1000\nid=ubuntu\nid_like=debian\npretty=Ubuntu 24.04.1 LTS\nversion=24.04\n" +
        "cmd=sudo\ncmd=su\ncmd=apt-get\ncmd=systemctl\ninit=systemd\nprobe=done\n");
    AssertEqual(1000, ubuntu.Uid ?? -1, "The UID was not parsed.");
    AssertEqual("Ubuntu 24.04.1 LTS", ubuntu.OsName, "PRETTY_NAME was not parsed.");
    AssertEqual("24.04", ubuntu.OsVersion, "VERSION_ID was not parsed.");
    AssertEqual(InitSystem.Systemd, ubuntu.InitSystem, "The init system was not parsed.");
    Assert(ubuntu.Has("sudo") && ubuntu.Has("apt-get") && !ubuntu.Has("dnf"), "Commands were not parsed.");
    AssertEqual(LinuxFamily.Debian, ServerInspection.DetectFamily(ubuntu.OsId, ubuntu.OsIdLike), "Ubuntu family.");
    AssertEqual(PackageManager.Apt, ServerInspection.SelectPackageManager(LinuxFamily.Debian, ubuntu.Commands) ?? PackageManager.Apk,
        "Ubuntu package manager.");

    var cases = new (string Id, string IdLike, LinuxFamily Family)[]
    {
        ("debian", "", LinuxFamily.Debian),
        ("rocky", "rhel centos fedora", LinuxFamily.Rhel),
        ("almalinux", "rhel centos fedora", LinuxFamily.Rhel),
        ("fedora", "", LinuxFamily.Rhel),
        ("rhel", "fedora", LinuxFamily.Rhel),
        ("opensuse-tumbleweed", "opensuse suse", LinuxFamily.Suse),
        ("opensuse-leap", "suse opensuse", LinuxFamily.Suse),
        ("sles", "suse", LinuxFamily.Suse),
        ("arch", "", LinuxFamily.Arch),
        ("endeavouros", "arch", LinuxFamily.Arch),
        ("alpine", "", LinuxFamily.Alpine),
        ("linuxmint", "ubuntu debian", LinuxFamily.Debian),
        ("somethingnew", "", LinuxFamily.Unknown)
    };
    foreach (var (id, idLike, family) in cases)
    {
        AssertEqual(family, ServerInspection.DetectFamily(id, idLike), $"Family of {id}.");
    }

    var rhelCommands = new HashSet<string>(["yum", "dnf"]);
    AssertEqual(PackageManager.Dnf, ServerInspection.SelectPackageManager(LinuxFamily.Rhel, rhelCommands) ?? PackageManager.Apt,
        "dnf must be preferred over yum.");
    AssertEqual(PackageManager.Yum, ServerInspection.SelectPackageManager(LinuxFamily.Rhel, new HashSet<string>(["yum"])) ?? PackageManager.Apt,
        "yum must be used when dnf is missing.");
    Assert(ServerInspection.SelectPackageManager(LinuxFamily.Alpine, new HashSet<string>(["apt-get"])) is null,
        "A foreign package manager was selected for a known distribution.");
    AssertEqual(PackageManager.Zypper, ServerInspection.SelectPackageManager(LinuxFamily.Unknown, new HashSet<string>(["zypper"])) ?? PackageManager.Apt,
        "An unknown distribution did not fall back to an available package manager.");

    var alpine = ServerInspection.ParseUnprivilegedProbe(
        "uid=0\nid=alpine\nid_like=\npretty=Alpine Linux v3.20\nversion=3.20.3\ncmd=su\ncmd=apk\ncmd=rc-service\ninit=openrc\nprobe=done\n");
    AssertEqual(0, alpine.Uid ?? -1, "Alpine root UID.");
    AssertEqual(InitSystem.OpenRc, alpine.InitSystem, "OpenRC was not detected.");

    try
    {
        ServerInspection.ParseUnprivilegedProbe("uid=1000\n");
        throw new InvalidOperationException("Truncated probe output was accepted.");
    }
    catch (DeploymentException)
    {
    }

    return Task.CompletedTask;
}

static Task TestRootProbeParsingAsync()
{
    var probe = ServerInspection.ParseRootProbe(
        "sshd=present\nsshd_t=ok\nport=22\nport=2200\nselinux=enforcing\nfirewall=firewalld\nsocket=1\n" +
        "main_config=/usr/etc/ssh/sshd_config\nincludes=1\nmain_port=22\nmanaged_port=2200\nsudoers_includedir=1\nprobe=done\n");
    Assert(probe.SshdAvailable && probe.SshdConfigValid, "sshd state was not parsed.");
    Assert(probe.Ports.SequenceEqual(new[] { 22, 2200 }), "Ports were not parsed.");
    Assert(probe.SelinuxEnforcing, "SELinux enforcing was not parsed.");
    AssertEqual(Firewall.Firewalld, probe.Firewall ?? Firewall.Ufw, "firewalld was not parsed.");
    Assert(probe.SocketActivated, "Socket activation was not parsed.");
    AssertEqual("/usr/etc/ssh/sshd_config", probe.MainConfigPath, "The main config path was not parsed.");
    Assert(probe.IncludesDropIns, "The Include line was not parsed.");
    Assert(probe.MainConfigPorts.SequenceEqual(new[] { 22 }), "Main config ports were not parsed.");
    Assert(probe.ManagedPorts.SequenceEqual(new[] { 2200 }), "Managed ports were not parsed.");
    AssertEqual(true, probe.SudoersIncludesDropIns ?? false, "sudoers includedir was not parsed.");

    var minimal = ServerInspection.ParseRootProbe("sshd=present\nsshd_t=ok\nport=22\nmain_config=/etc/ssh/sshd_config\nprobe=done\n");
    Assert(!minimal.IncludesDropIns, "A config without Include was reported as including drop-ins.");
    Assert(minimal.Firewall is null && !minimal.SelinuxEnforcing && !minimal.SocketActivated, "Defaults are wrong.");
    Assert(minimal.SudoersIncludesDropIns is null, "A missing sudoers file must be unknown, not false.");

    AssertContains(ServerInspection.RootProbeScript, DeploymentService.ManagedConfigPath);
    AssertContains(ServerInspection.RootProbeScript, "/usr/etc/ssh/sshd_config");
    AssertContains(ServerInspection.RootProbeScript, "ssh.socket");
    AssertContains(ServerInspection.UnprivilegedProbeScript, "/etc/os-release");

    Assert(ServerInspection.GetTransitionPorts([22], [], 2222).SequenceEqual(new[] { 22, 2222 }),
        "Transition ports must keep the old port.");
    Assert(ServerInspection.GetTransitionPorts([22], [22], 2222).SequenceEqual(new[] { 2222 }),
        "Ports from the main sshd_config must not be repeated in the drop-in.");
    Assert(ServerInspection.GetTransitionPorts([22, 2222], [], 2222).SequenceEqual(new[] { 22, 2222 }),
        "Transition ports must not contain duplicates.");
    return Task.CompletedTask;
}

static Task TestPrivilegeDecisionAsync()
{
    AssertEqual(PrivilegeMode.Root, ServerInspection.DecidePrivilege(true, false, false, false), "UID 0 must be root.");
    AssertEqual(PrivilegeMode.Sudo, ServerInspection.DecidePrivilege(false, true, true, true), "Working sudo wins over su.");
    AssertEqual(PrivilegeMode.Su, ServerInspection.DecidePrivilege(false, false, true, true), "Failed sudo with a root password falls back to su.");
    AssertEqual(PrivilegeMode.None, ServerInspection.DecidePrivilege(false, false, true, false), "No sudo and no root password.");
    AssertEqual(PrivilegeMode.None, ServerInspection.DecidePrivilege(false, false, false, true), "No su binary.");

    Assert(ServerInspection.GetRequiredPackages(PrivilegeMode.Su, false, LinuxFamily.Debian, PackageManager.Apt, false, false, false)
            .SequenceEqual(new[] { "sudo" }),
        "su mode without sudo must install sudo.");
    Assert(ServerInspection.GetRequiredPackages(PrivilegeMode.Sudo, true, LinuxFamily.Rhel, PackageManager.Dnf, true, true, false)
            .SequenceEqual(new[] { "policycoreutils-python-utils" }),
        "A port change under enforcing SELinux must install semanage.");
    Assert(ServerInspection.GetRequiredPackages(PrivilegeMode.Sudo, true, LinuxFamily.Rhel, PackageManager.Dnf, true, true, true).Count == 0,
        "Installed semanage must not be installed again.");
    Assert(ServerInspection.GetRequiredPackages(PrivilegeMode.Root, false, LinuxFamily.Alpine, PackageManager.Apk, true, false, false).Count == 0,
        "Root mode needs no sudo package.");
    try
    {
        ServerInspection.GetRequiredPackages(PrivilegeMode.Su, false, LinuxFamily.Unknown, null, false, false, false);
        throw new InvalidOperationException("Missing packages without a package manager were accepted.");
    }
    catch (DeploymentException exception)
    {
        AssertContains(exception.Message, "No server changes were made");
    }

    return Task.CompletedTask;
}

static Task TestPlanBuildingAsync()
{
    var suServer = NewServer(PrivilegeMode.Su, selinux: false, firewall: null);
    var request = NewRequest(username: "deploy", enableRootLogin: true, allowPasswordLogin: false, rootPassword: "root-" + "secret");
    var plan = ServerInspection.BuildPlan(suServer, request, ["sudo"]);
    Assert(plan.Actions[0] is InstallPackagesAction { Manager: PackageManager.Apt } install && install.Packages.SequenceEqual(new[] { "sudo" }),
        "The package installation must come first.");
    Assert(plan.Actions[0].IsPersistent, "Package installation must be flagged as persistent.");
    Assert(plan.Actions[1] is TemporarySudoViaSuAction { Account: "deploy" }, "Temporary sudo through su is missing.");
    Assert(plan.Actions.OfType<InstallPublicKeyAction>().Select(action => action.Account).SequenceEqual(new[] { "deploy", "root" }),
        "Both accounts must receive the key when root login is enabled.");
    Assert(plan.Actions.OfType<WriteSshdPolicyAction>().Single().RootLogin == RootLoginPolicy.KeyOnly,
        "The root login policy is wrong.");
    Assert(!plan.Actions.OfType<ChangePortAction>().Any(), "No port change was requested.");
    Assert(plan.Actions.Where(action => action is not InstallPackagesAction).All(action => !action.IsPersistent),
        "Only package installation is persistent.");

    var portServer = NewServer(PrivilegeMode.Sudo, selinux: true, firewall: Firewall.Firewalld);
    var portPlan = ServerInspection.BuildPlan(portServer, NewRequest(username: "deploy", enableRootLogin: false, newSshPort: 2222), []);
    Assert(!portPlan.Actions.OfType<InstallPackagesAction>().Any(), "No packages were required.");
    Assert(!portPlan.Actions.OfType<TemporarySudoViaSuAction>().Any(), "sudo mode must not grant temporary sudo.");
    var labelIndex = IndexOf<LabelSelinuxPortAction>(portPlan);
    var firewallIndex = IndexOf<OpenFirewallPortAction>(portPlan);
    var changeIndex = IndexOf<ChangePortAction>(portPlan);
    Assert(labelIndex >= 0 && firewallIndex > labelIndex && changeIndex > firewallIndex,
        "SELinux and firewall must be prepared before the port change.");
    var change = (ChangePortAction)portPlan.Actions[changeIndex];
    Assert(change.From.SequenceEqual(new[] { 22 }) && change.To == 2222, "The port change is wrong.");

    foreach (var action in portPlan.Actions.Concat(plan.Actions))
    {
        Assert(DeploymentPresentation.DescribeAction(action, english: true).Length > 0, "An action has no English text.");
        Assert(DeploymentPresentation.DescribeAction(action, english: false).Length > 0, "An action has no Chinese text.");
    }

    Assert(DeploymentPresentation.DescribeServer(portServer, english: false).Count >= 6, "Server details are incomplete.");
    var result = new DeploymentResult(
        true,
        "deploy",
        "/home/me/.ssh/ssh-key-deployer/server_ed25519",
        "SHA256:x",
        new HostKeyInfo("192.0.2.10", 22, "ssh-ed25519", 256, "SHA256:y", "MD5:z"),
        DeploymentService.ManagedConfigPath,
        RootLoginPolicy.Disabled,
        true,
        [],
        portServer,
        2222);
    AssertEqual(
        "ssh -i /home/me/.ssh/ssh-key-deployer/server_ed25519 -p 2222 deploy@192.0.2.10",
        DeploymentPresentation.BuildSshCommand(result),
        "The ssh command is wrong.");
    return Task.CompletedTask;
}

static Task TestPrivilegeGuidanceAsync()
{
    AssertContains(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Debian, "spencer", false)), "apt-get install -y sudo");
    AssertContains(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Debian, "spencer", true)), "usermod -aG sudo spencer");
    AssertContains(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Rhel, "spencer", false)), "dnf install -y sudo");
    AssertContains(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Rhel, "spencer", true)), "usermod -aG wheel spencer");
    var suse = string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Suse, "spencer", false));
    AssertContains(suse, "zypper");
    AssertContains(suse, "!targetpw");
    var arch = string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Arch, "spencer", false));
    AssertContains(arch, "pacman");
    AssertContains(arch, "%wheel ALL=(ALL:ALL) ALL");
    var alpine = string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Alpine, "spencer", false));
    AssertContains(alpine, "apk add sudo");
    AssertContains(alpine, "addgroup spencer wheel");
    AssertContains(alpine, "/etc/sudoers.d/");
    Assert(!PrivilegeGuidance.GetSudoSetupCommands(LinuxFamily.Alpine, "spencer", true).Any(command => command.Contains("apk add", StringComparison.Ordinal)),
        "sudo installation was suggested although sudo is installed.");

    var noPrivilege = new PrivilegeException("spencer", PrivilegeFailureReason.NoPrivilege, LinuxFamily.Rhel, "Rocky Linux 9.4", sudoInstalled: true);
    AssertContains(noPrivilege.Message, "usermod -aG wheel spencer");
    AssertContains(noPrivilege.Message, "root password");
    AssertContains(noPrivilege.Message, "No server changes were made");
    var chinese = DeploymentPresentation.DescribeFailure(noPrivilege, english: false)
        ?? throw new InvalidOperationException("No Chinese guidance for a missing privilege.");
    AssertContains(chinese, "usermod -aG wheel spencer");
    AssertContains(chinese, "root 密码");

    var sudoSuse = new SudoAccessException("spencer", SudoAccessFailureReason.CommandUnavailable, "sudo: not found", LinuxFamily.Suse);
    AssertContains(sudoSuse.Message, "zypper");
    AssertContains(DeploymentPresentation.DescribeFailure(sudoSuse, english: false) ?? string.Empty, "targetpw");

    var unsupported = new UnsupportedServerException(UnsupportedServerReason.SshdConfigWithoutInclude, "/etc/ssh/sshd_config");
    AssertContains(unsupported.Message, "Include /etc/ssh/sshd_config.d/*.conf");
    AssertContains(DeploymentPresentation.DescribeFailure(unsupported, english: false) ?? string.Empty, "Include /etc/ssh/sshd_config.d/*.conf");
    Assert(DeploymentPresentation.DescribeFailure(new DeploymentException("other"), english: false) is null,
        "Unrelated errors must use the generic translation.");
    return Task.CompletedTask;
}

static Task TestSuHandlingAsync()
{
    Assert(SuShell.EndsWithPasswordPrompt("Last login: today\nPassword: "), "The su password prompt was not detected.");
    Assert(SuShell.EndsWithPasswordPrompt("密码："), "A localized password prompt was not detected.");
    Assert(!SuShell.EndsWithPasswordPrompt("Your password will expire soon\n$ "), "A non-prompt was treated as a prompt.");

    AssertEqual(SuFailureKind.PasswordRejected, SuShell.ClassifyFailure("Password: \nsu: Authentication failure", true), "Wrong password.");
    AssertEqual(SuFailureKind.PasswordRejected, SuShell.ClassifyFailure("Password: \nsu: incorrect password", true), "BusyBox wrong password.");
    AssertEqual(SuFailureKind.NotPermitted, SuShell.ClassifyFailure("su: Permission denied", true), "pam_wheel denial.");
    AssertEqual(SuFailureKind.NotPermitted, SuShell.ClassifyFailure("sh: su: not found", false), "Missing su.");

    var line = SuShell.BuildSuCommandLine("0123456789abcdef0123456789abcdef");
    AssertContains(line, "su root -c ");
    Assert(!line.Contains("__SKD_ROOT_", StringComparison.Ordinal) && !line.Contains("__SKD_EXIT_", StringComparison.Ordinal),
        "Markers must not appear verbatim in the echoed command line.");
    Assert(!line.Contains("password", StringComparison.OrdinalIgnoreCase), "The su command line must not carry a password.");

    var (final, temporary) = RemoteScripts.NewSudoersPaths();
    var create = RemoteScripts.CreateSudoersDropIn("deploy", final, temporary);
    AssertContains(create, "Defaults:$user !targetpw, !rootpw, !runaspw");
    AssertContains(create, "$user ALL=(ALL:ALL) ALL");
    AssertContains(create, "visudo -cf");
    AssertContains(create, "chmod 0440");
    AssertContains(create, "includedir");
    Assert(final.StartsWith("/etc/sudoers.d/zz-ssh-key-deployer-", StringComparison.Ordinal) && !final[15..].Contains('.', StringComparison.Ordinal),
        "The active sudoers drop-in must not contain a dot, or sudo ignores it.");
    Assert(temporary[15..].Contains('.', StringComparison.Ordinal), "The temporary sudoers file must be ignored by sudo.");
    try
    {
        RemoteScripts.CreateSudoersDropIn("deploy", "/etc/sudoers", temporary);
        throw new InvalidOperationException("An arbitrary sudoers path was accepted.");
    }
    catch (ArgumentException)
    {
    }

    return Task.CompletedTask;
}

static async Task TestRemoteScriptSyntaxAsync()
{
    var scripts = RemoteScripts.SamplesForSyntaxCheck().ToList();
    var type = typeof(DeploymentService);
    foreach (var fieldName in new[] { "InstallCurrentUserKeyCommand", "InstallRootKeyCommand", "RemoveCurrentUserKeyCommand", "RemoveRootKeyCommand" })
    {
        var command = type.GetField(fieldName, BindingFlags.Static | BindingFlags.NonPublic)?.GetValue(null) as string
            ?? throw new InvalidOperationException($"{fieldName} was not found.");
        scripts.Add((fieldName, UnwrapShellCommand(command)));
    }

    const string snapshot = "/tmp/ssh-key-deployer-authorized-0123456789abcdef0123456789abcdef";
    foreach (var root in new[] { false, true })
    {
        scripts.Add(($"prepare-{root}", UnwrapShellCommand(InvokeStringBuilder(type, "BuildPrepareAuthorizedKeysBackupCommand", snapshot, root))));
        scripts.Add(($"restore-{root}", UnwrapShellCommand(InvokeStringBuilder(type, "BuildRestoreAuthorizedKeysCommand", snapshot, root))));
    }

    scripts.Add(("cleanup", UnwrapShellCommand(InvokeStringBuilder(type, "BuildCleanupAuthorizedKeysBackupCommand", snapshot))));

    foreach (var (name, script) in scripts)
    {
        Assert(!script.Contains("mv -fT", StringComparison.Ordinal) && !script.Contains("mv -T", StringComparison.Ordinal),
            $"{name} uses GNU-only mv -T.");
        Assert(!script.Contains("[[ ", StringComparison.Ordinal), $"{name} uses bash-only [[ tests.");
        Assert(!script.Contains('\r'), $"{name} contains a carriage return.");
    }

    AssertContains(RemoteScripts.Reload(false), "rc-service sshd reload");
    AssertContains(RemoteScripts.Reload(false), "kill -HUP");
    AssertContains(RemoteScripts.Reload(false), "/var/run/sshd.pid");
    AssertContains(RemoteScripts.Reload(true), "systemctl restart ssh.socket");
    AssertContains(RemoteScripts.Reload(true), "daemon-reload");

    if (OperatingSystem.IsWindows())
    {
        return;
    }

    var shells = new[] { "/bin/sh", "/bin/dash", "/usr/bin/dash", "/bin/bash" }.Where(File.Exists).ToArray();
    var directory = Path.Combine(Path.GetTempPath(), "ssh-key-deployer-syntax-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    try
    {
        foreach (var (name, script) in scripts)
        {
            var path = Path.Combine(directory, name + ".sh");
            await File.WriteAllTextAsync(path, script);
            foreach (var shell in shells)
            {
                var startInfo = new ProcessStartInfo(shell)
                {
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };
                startInfo.ArgumentList.Add("-n");
                startInfo.ArgumentList.Add(path);
                using var process = Process.Start(startInfo)
                    ?? throw new InvalidOperationException($"{shell} could not be started.");
                var error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();
                Assert(process.ExitCode == 0, $"{shell} -n rejected {name}: {error}");
            }
        }
    }
    finally
    {
        Directory.Delete(directory, recursive: true);
    }
}

static string InvokeStringBuilder(Type type, string methodName, params object[] arguments) =>
    type.GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic)?.Invoke(null, arguments) as string
    ?? throw new InvalidOperationException($"{methodName} was not found.");

static string UnwrapShellCommand(string command)
{
    const string prefix = "sh -c '";
    Assert(command.StartsWith(prefix, StringComparison.Ordinal) && command.EndsWith('\''), "Unexpected shell wrapper.");
    return command[prefix.Length..^1].Replace("'\"'\"'", "'", StringComparison.Ordinal);
}

static int IndexOf<T>(DeploymentPlan plan) where T : PlannedAction
{
    for (var index = 0; index < plan.Actions.Count; index++)
    {
        if (plan.Actions[index] is T)
        {
            return index;
        }
    }

    return -1;
}

static ServerInfo NewServer(PrivilegeMode privilege, bool selinux, Firewall? firewall) =>
    new(
        "debian",
        "Debian GNU/Linux 12 (bookworm)",
        "12",
        LinuxFamily.Debian,
        PackageManager.Apt,
        InitSystem.Systemd,
        privilege,
        SudoInstalled: privilege != PrivilegeMode.Su,
        SshdIncludesDropIns: true,
        SelinuxEnforcing: selinux,
        Firewall: firewall,
        SocketActivated: false,
        CurrentPorts: [22]);

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
    bool allowPasswordLogin = true,
    string? rootPassword = null,
    int? newSshPort = null) =>
    new(
        host,
        port,
        username,
        password,
        keyPath ?? Path.Combine(Path.GetTempPath(), "server_ed25519"),
        enableRootLogin,
        allowPasswordLogin,
        rootPassword,
        newSshPort);

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
