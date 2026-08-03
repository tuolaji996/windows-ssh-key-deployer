using System.Diagnostics;
using System.Text;

namespace SshKeyDeployer.Core;

internal sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);

internal sealed class OpenSshTools
{
    private const int MaximumDiagnosticLength = 4_096;
    private static readonly TimeSpan ProcessTerminationTimeout = TimeSpan.FromSeconds(5);
    private readonly string _sshKeygenPath;

    public OpenSshTools(string? sshKeygenPath = null)
    {
        _sshKeygenPath = sshKeygenPath is null
            ? FindTrustedSshKeygen()
            : ValidateExplicitSshKeygenPath(sshKeygenPath);
    }

    public Task<ProcessResult> GenerateEd25519Async(
        string privateKeyPath,
        CancellationToken cancellationToken) =>
        RunAsync(
            ["-q", "-t", "ed25519", "-f", privateKeyPath, "-N", string.Empty, "-C", "ssh-key-deployer"],
            cancellationToken);

    public Task<ProcessResult> DerivePublicKeyAsync(
        string privateKeyPath,
        CancellationToken cancellationToken) =>
        RunAsync(["-y", "-f", privateKeyPath], cancellationToken);

    private async Task<ProcessResult> RunAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var startInfo = new ProcessStartInfo
        {
            FileName = _sshKeygenPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        Task<string>? standardOutputTask = null;
        Task<string>? standardErrorTask = null;
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("ssh-keygen could not be started.");
            }

            // Closing stdin prevents an overwrite or passphrase prompt from hanging unattended.
            process.StandardInput.Close();
            standardOutputTask = process.StandardOutput.ReadToEndAsync();
            standardErrorTask = process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            var standardOutput = await standardOutputTask.ConfigureAwait(false);
            var standardError = await standardErrorTask.ConfigureAwait(false);
            return new ProcessResult(
                process.ExitCode,
                LimitDiagnostic(standardOutput),
                LimitDiagnostic(standardError));
        }
        catch (OperationCanceledException)
        {
            await TerminateAndDrainAsync(
                    process,
                    standardOutputTask,
                    standardErrorTask)
                .ConfigureAwait(false);
            throw;
        }
        catch (Exception exception)
        {
            await TerminateAndDrainAsync(
                    process,
                    standardOutputTask,
                    standardErrorTask)
                .ConfigureAwait(false);
            throw new KeyGenerationException(
                "Windows OpenSSH ssh-keygen could not be executed. Install the OpenSSH Client optional feature and try again.",
                exception);
        }
    }

    private static string FindTrustedSshKeygen()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "SSH key generation and Windows ACL protection require Windows.");
        }

        var systemDirectory = Environment.SystemDirectory;
        if (string.IsNullOrWhiteSpace(systemDirectory) ||
            !Path.IsPathFullyQualified(systemDirectory))
        {
            throw new KeyGenerationException(
                "The trusted Windows System32 directory could not be resolved.");
        }

        var systemOpenSsh = Path.GetFullPath(Path.Combine(
            systemDirectory,
            "OpenSSH",
            "ssh-keygen.exe"));
        if (!File.Exists(systemOpenSsh))
        {
            throw new KeyGenerationException(
                "Windows OpenSSH ssh-keygen.exe was not found in System32. Install the OpenSSH Client optional feature and try again.");
        }

        return systemOpenSsh;
    }

    private static string ValidateExplicitSshKeygenPath(string sshKeygenPath)
    {
        if (string.IsNullOrWhiteSpace(sshKeygenPath))
        {
            throw new KeyGenerationException(
                "The explicitly configured ssh-keygen path must not be empty.");
        }

        var candidate = sshKeygenPath.Trim();
        if (!Path.IsPathFullyQualified(candidate))
        {
            throw new KeyGenerationException(
                "The explicitly configured ssh-keygen path must be absolute.");
        }

        string normalizedPath;
        try
        {
            normalizedPath = Path.GetFullPath(candidate);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new KeyGenerationException(
                "The explicitly configured ssh-keygen path is invalid.",
                exception);
        }

        if (!File.Exists(normalizedPath))
        {
            throw new KeyGenerationException(
                "The explicitly configured ssh-keygen executable was not found.");
        }

        return normalizedPath;
    }

    private static async Task TerminateAndDrainAsync(
        Process process,
        Task<string>? standardOutputTask,
        Task<string>? standardErrorTask)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
        catch (NotSupportedException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }

        try
        {
            await process
                .WaitForExitAsync(CancellationToken.None)
                .WaitAsync(ProcessTerminationTimeout)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
        catch (TimeoutException)
        {
        }

        if (standardOutputTask is null || standardErrorTask is null)
        {
            return;
        }

        try
        {
            await Task
                .WhenAll(standardOutputTask, standardErrorTask)
                .WaitAsync(ProcessTerminationTimeout)
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
        }
        catch (TimeoutException)
        {
        }
    }

    private static string LimitDiagnostic(string value)
    {
        var trimmed = value.Trim();
        return trimmed.Length <= MaximumDiagnosticLength
            ? trimmed
            : trimmed[..MaximumDiagnosticLength] + "...";
    }
}
