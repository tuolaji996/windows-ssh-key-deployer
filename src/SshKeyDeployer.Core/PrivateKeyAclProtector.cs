using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SshKeyDeployer.Core;

public sealed class PrivateKeyAclProtector
{
    public void Protect(string privateKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPath);

        var fullPath = Path.GetFullPath(privateKeyPath);
        if (OperatingSystem.IsWindows())
        {
            ProtectWindows(fullPath);
            return;
        }

        ProtectUnix(fullPath);
    }

    public bool IsSecure(string privateKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPath);

        var fullPath = Path.GetFullPath(privateKeyPath);
        return OperatingSystem.IsWindows()
            ? IsSecureWindows(fullPath)
            : IsSecureUnix(fullPath);
    }

    public void ProtectDirectory(string directoryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);

        if (OperatingSystem.IsWindows())
        {
            return;
        }

        ProtectUnixDirectory(Path.GetFullPath(directoryPath));
    }

    private static void ProtectUnix(string privateKeyPath)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Unix private-key mode protection is not available on Windows.");
        }

        var fileInfo = new FileInfo(privateKeyPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("Private-key file was not found.", privateKeyPath);
        }

        if (fileInfo.LinkTarget is not null)
        {
            throw new UnauthorizedAccessException(
                "The private-key file must not be a symbolic link.");
        }

        // OpenSSH private keys must not be readable by the group or other users.
        // Set the complete mode instead of only removing bits so inherited or
        // pre-existing execute/special bits cannot survive the protection step.
        File.SetUnixFileMode(
            privateKeyPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite);

        if (!IsSecureUnix(privateKeyPath))
        {
            throw new UnauthorizedAccessException(
                "The private-key file mode could not be restricted to owner read/write.");
        }
    }

    private static bool IsSecureUnix(string privateKeyPath)
    {
        if (OperatingSystem.IsWindows())
        {
            return false;
        }

        var fileInfo = new FileInfo(privateKeyPath);
        if (!fileInfo.Exists || fileInfo.LinkTarget is not null)
        {
            return false;
        }

        try
        {
            return File.GetUnixFileMode(privateKeyPath) ==
                   (UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static void ProtectUnixDirectory(string directoryPath)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Unix key-directory mode protection is not available on Windows.");
        }

        var directoryInfo = new DirectoryInfo(directoryPath);
        if (!directoryInfo.Exists)
        {
            throw new DirectoryNotFoundException("Private-key directory was not found.");
        }

        if (directoryInfo.LinkTarget is not null)
        {
            throw new UnauthorizedAccessException(
                "The private-key directory must not be a symbolic link.");
        }

        var secureMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        File.SetUnixFileMode(directoryPath, secureMode);
        if (File.GetUnixFileMode(directoryPath) != secureMode)
        {
            throw new UnauthorizedAccessException(
                "The private-key directory mode could not be restricted to owner access.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectWindows(string privateKeyPath)
    {
        if (!File.Exists(privateKeyPath))
        {
            throw new FileNotFoundException("Private-key file was not found.", privateKeyPath);
        }

        var currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The current Windows user has no security identifier.");
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var fileInfo = new FileInfo(privateKeyPath);
        var security = fileInfo.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new InvalidOperationException("The private-key file has no Windows owner SID.");

        if (!currentUser.Equals(owner))
        {
            RunIcacls(privateKeyPath, "/setowner", $"*{currentUser.Value}");
        }

        RunIcacls(privateKeyPath, "/inheritance:r");

        // Remove every explicit identity before granting the only two allowed SIDs.
        // icacls matches Windows OpenSSH's ACL tooling and also works with restricted
        // desktop tokens where SetAccessControl writes can be denied.
        security = fileInfo.GetAccessControl(AccessControlSections.Access);
        var identities = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(rule => (SecurityIdentifier)rule.IdentityReference)
            .Distinct()
            .ToArray();

        foreach (var identity in identities)
        {
            RunIcacls(privateKeyPath, "/remove", $"*{identity.Value}");
        }

        RunIcacls(
            privateKeyPath,
            "/grant:r",
            $"*{currentUser.Value}:(F)",
            $"*{localSystem.Value}:(F)");

        if (!IsSecureWindows(privateKeyPath))
        {
            throw new UnauthorizedAccessException(
                "The private-key ACL could not be restricted to the current user and SYSTEM.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsSecureWindows(string privateKeyPath)
    {
        if (!File.Exists(privateKeyPath))
        {
            return false;
        }

        var currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is null)
        {
            return false;
        }

        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileInfo(privateKeyPath).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);

        if (!security.AreAccessRulesProtected ||
            !currentUser.Equals(security.GetOwner(typeof(SecurityIdentifier))))
        {
            return false;
        }

        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();

        return rules.Length == 2 &&
               HasFullControlRule(rules, currentUser) &&
               HasFullControlRule(rules, localSystem);
    }

    [SupportedOSPlatform("windows")]
    private static bool HasFullControlRule(
        IEnumerable<FileSystemAccessRule> rules,
        SecurityIdentifier identity) =>
        rules.Any(rule =>
            identity.Equals(rule.IdentityReference) &&
            rule.AccessControlType == AccessControlType.Allow &&
            (rule.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl);

    [SupportedOSPlatform("windows")]
    private static void RunIcacls(string privateKeyPath, params string[] arguments)
    {
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var icaclsPath = Path.Combine(windowsDirectory, "System32", "icacls.exe");
        if (!File.Exists(icaclsPath))
        {
            throw new FileNotFoundException("Windows icacls.exe was not found.", icaclsPath);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = icaclsPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add(privateKeyPath);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        startInfo.ArgumentList.Add("/Q");

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            throw new InvalidOperationException("Windows icacls.exe could not be started.");
        }

        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(milliseconds: 15_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw new TimeoutException("Windows icacls.exe timed out while protecting the private key.");
        }

        Task.WaitAll(standardOutput, standardError);
        if (process.ExitCode != 0)
        {
            var diagnostic = string.IsNullOrWhiteSpace(standardError.Result)
                ? standardOutput.Result
                : standardError.Result;
            diagnostic = diagnostic.Trim();
            throw new UnauthorizedAccessException(
                string.IsNullOrWhiteSpace(diagnostic)
                    ? "Windows rejected the private-key ACL change."
                    : $"Windows rejected the private-key ACL change: {diagnostic}");
        }
    }
}
