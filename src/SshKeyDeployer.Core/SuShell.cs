using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace SshKeyDeployer.Core;

public enum SuFailureKind
{
    /// <summary>su ran but rejected the root password.</summary>
    PasswordRejected,
    /// <summary>su is missing, or PAM/wheel rules do not allow this account to use it.</summary>
    NotPermitted
}

/// <summary>
/// Runs a POSIX sh script as root through <c>su</c> on a pseudo-terminal. The root password is written to
/// the terminal only after su prints its password prompt; it never appears on a command line.
/// </summary>
public static partial class SuShell
{
    private const string MarkerPrefix = "__SKD_";

    internal sealed record SuOutcome(bool Authenticated, bool PasswordSent, int ExitStatus, string Output, string Diagnostic);

    /// <summary>
    /// Classifies output that su printed before it exited without running the command.
    /// </summary>
    public static SuFailureKind ClassifyFailure(string transcript, bool passwordWasSent)
    {
        var text = transcript.ToLowerInvariant();
        if (text.Contains("su: not found", StringComparison.Ordinal) ||
            text.Contains("su: command not found", StringComparison.Ordinal) ||
            text.Contains("permission denied", StringComparison.Ordinal) ||
            text.Contains("not permitted", StringComparison.Ordinal) ||
            text.Contains("wheel", StringComparison.Ordinal) ||
            text.Contains("must be run from a terminal", StringComparison.Ordinal) ||
            text.Contains("cannot set groups", StringComparison.Ordinal) ||
            text.Contains("account expired", StringComparison.Ordinal) ||
            text.Contains("module is unknown", StringComparison.Ordinal))
        {
            return SuFailureKind.NotPermitted;
        }

        if (text.Contains("authentication failure", StringComparison.Ordinal) ||
            text.Contains("incorrect password", StringComparison.Ordinal) ||
            text.Contains("sorry", StringComparison.Ordinal) ||
            text.Contains("authentication token", StringComparison.Ordinal) ||
            text.Contains("bad password", StringComparison.Ordinal))
        {
            return SuFailureKind.PasswordRejected;
        }

        return passwordWasSent ? SuFailureKind.PasswordRejected : SuFailureKind.NotPermitted;
    }

    /// <summary>True when the text received so far ends with a password prompt.</summary>
    public static bool EndsWithPasswordPrompt(string text) => PasswordPromptRegex().IsMatch(text);

    /// <summary>The line typed into the PTY to start su. The script itself is sent separately on stdin.</summary>
    public static string BuildSuCommandLine(string id)
    {
        var inner = $"printf '%s%s\\n' {MarkerPrefix} 'ROOT_{id}'; eval \"$(cat)\"";
        return $"su root -c {ShellQuote(inner)}; printf '%s%s:%s\\n' {MarkerPrefix} 'EXIT_{id}' \"$?\"";
    }

    internal static async Task<SuOutcome> RunAsync(
        SshClient client,
        string rootPassword,
        string script,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var id = Guid.NewGuid().ToString("N");
        var readyMarker = $"{MarkerPrefix}READY_{id}";
        var rootMarker = $"{MarkerPrefix}ROOT_{id}";
        var exitMarker = $"{MarkerPrefix}EXIT_{id}:";

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var token = timeoutSource.Token;

        var modes = new Dictionary<TerminalModes, uint> { [TerminalModes.ECHO] = 0 };
        using var shell = client.CreateShellStream("dumb", 200, 50, 0, 0, 64 * 1024, modes);
        var transcript = new Transcript();
        var reader = Task.Run(() => ReadAll(shell, transcript), CancellationToken.None);
        using var registration = token.Register(() => shell.Dispose());

        try
        {
            // Use a known POSIX shell regardless of the account's login shell, with echo and prompts off.
            Send(shell, "exec /bin/sh\n");
            Send(shell, $"stty -echo 2>/dev/null; PS1=''; PS2=''; LC_ALL=C; export LC_ALL; printf '%s%s\\n' {MarkerPrefix} 'READY_{id}'\n");
            var readyIndex = await transcript.WaitForAsync(text => IndexAfter(text, readyMarker, 0), token)
                .ConfigureAwait(false);

            Send(shell, BuildSuCommandLine(id) + "\n");

            var passwordSent = false;
            var searchFrom = readyIndex;
            int rootIndex;
            while (true)
            {
                var (state, index) = await transcript.WaitForAsync(
                        text =>
                        {
                            var root = IndexAfter(text, rootMarker, searchFrom);
                            if (root >= 0)
                            {
                                return (1, root);
                            }

                            var exit = text.IndexOf(exitMarker, searchFrom, StringComparison.Ordinal);
                            if (exit >= 0 && text.IndexOf('\n', exit) >= 0)
                            {
                                return (2, exit);
                            }

                            return !passwordSent && EndsWithPasswordPrompt(text[searchFrom..])
                                ? (3, text.Length)
                                : (0, -1);
                        },
                        token)
                    .ConfigureAwait(false);

                if (state == 1)
                {
                    rootIndex = index;
                    break;
                }

                if (state == 2)
                {
                    var failureText = Normalize(transcript.Snapshot()[searchFrom..index]);
                    return new SuOutcome(
                        Authenticated: false,
                        PasswordSent: passwordSent,
                        ExitStatus: -1,
                        Output: string.Empty,
                        Diagnostic: Redact(failureText, rootPassword));
                }

                SendPassword(shell, rootPassword);
                passwordSent = true;
                searchFrom = index;
            }

            // Root's shell is now waiting in "cat" for the script; ^D on a new line ends it.
            Send(shell, script.Replace("\r", string.Empty, StringComparison.Ordinal) + "\n\u0004");

            var exitIndex = await transcript.WaitForAsync(
                    text =>
                    {
                        var start = text.IndexOf(exitMarker, rootIndex, StringComparison.Ordinal);
                        return start >= 0 && text.IndexOf('\n', start) >= 0 ? start : -1;
                    },
                    token)
                .ConfigureAwait(false);

            var all = transcript.Snapshot();
            var statusStart = exitIndex + exitMarker.Length;
            var statusEnd = all.IndexOf('\n', statusStart);
            var statusText = all[statusStart..statusEnd].Trim();
            if (!int.TryParse(statusText, NumberStyles.None, CultureInfo.InvariantCulture, out var exitStatus))
            {
                exitStatus = -1;
            }

            var output = Redact(Normalize(all[rootIndex..exitIndex]), rootPassword);
            try
            {
                Send(shell, "exit\n");
            }
            catch
            {
                // The session is discarded anyway.
            }

            return new SuOutcome(true, passwordSent, exitStatus, output, string.Empty);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("The su session did not respond in time.");
        }
        finally
        {
            shell.Dispose();
            try
            {
                await reader.ConfigureAwait(false);
            }
            catch
            {
                // Reader failures only matter while waiting, where they surface as timeouts.
            }
        }
    }

    private static void ReadAll(ShellStream shell, Transcript transcript)
    {
        var decoder = new UTF8Encoding(false).GetDecoder();
        var bytes = new byte[8192];
        var chars = new char[8192 + 8];
        try
        {
            while (true)
            {
                var read = shell.Read(bytes, 0, bytes.Length);
                if (read <= 0)
                {
                    break;
                }

                var count = decoder.GetChars(bytes, 0, read, chars, 0);
                transcript.Append(chars, count);
            }
        }
        catch
        {
            // Treated as end of stream.
        }
        finally
        {
            transcript.Complete();
        }
    }

    private static void Send(ShellStream shell, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        shell.Write(bytes, 0, bytes.Length);
        shell.Flush();
    }

    private static void SendPassword(ShellStream shell, string password)
    {
        var bytes = Encoding.UTF8.GetBytes(password + "\n");
        try
        {
            shell.Write(bytes, 0, bytes.Length);
            shell.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static int IndexAfter(string text, string marker, int from)
    {
        var index = text.IndexOf(marker, from, StringComparison.Ordinal);
        if (index < 0)
        {
            return -1;
        }

        var lineEnd = text.IndexOf('\n', index);
        return lineEnd < 0 ? -1 : lineEnd + 1;
    }

    private static string Normalize(string value) =>
        value.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\u0004", string.Empty, StringComparison.Ordinal)
            .Trim();

    private static string Redact(string value, string secret) =>
        string.IsNullOrEmpty(secret)
            ? value
            : value.Replace(secret, "[redacted]", StringComparison.Ordinal);

    private static string ShellQuote(string value) =>
        $"'{value.Replace("'", "'\"'\"'", StringComparison.Ordinal)}'";

    [GeneratedRegex(@"(?i)(password|passwort|mot de passe|contraseña|密码)[^\n]*[:：]\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex PasswordPromptRegex();

    private sealed class Transcript
    {
        private readonly object _sync = new();
        private readonly StringBuilder _text = new();
        private bool _completed;

        public void Append(char[] chars, int count)
        {
            lock (_sync)
            {
                _text.Append(chars, 0, count);
            }
        }

        public void Complete()
        {
            lock (_sync)
            {
                _completed = true;
            }
        }

        public string Snapshot()
        {
            lock (_sync)
            {
                return _text.ToString();
            }
        }

        public async Task<T> WaitForAsync<T>(Func<string, T> probe, CancellationToken cancellationToken)
        {
            while (true)
            {
                string text;
                bool completed;
                lock (_sync)
                {
                    text = _text.ToString();
                    completed = _completed;
                }

                var result = probe(text);
                if (!IsEmpty(result))
                {
                    return result;
                }

                if (completed)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new SshException("The su session closed unexpectedly.");
                }

                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            }
        }

        private static bool IsEmpty<T>(T value) => value switch
        {
            int number => number < 0,
            ValueTuple<int, int> pair => pair.Item1 == 0,
            _ => value is null
        };
    }
}
