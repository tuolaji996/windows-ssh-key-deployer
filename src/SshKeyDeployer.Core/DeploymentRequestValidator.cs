using System.Net;
using System.Text.RegularExpressions;

namespace SshKeyDeployer.Core;

public static partial class DeploymentRequestValidator
{
    public static ValidationResult Validate(
        DeploymentRequest? request,
        bool requireExistingKey = true)
    {
        if (request is null)
        {
            return new ValidationResult(
                [new ValidationError(nameof(request), "A deployment request is required.")]);
        }

        var errors = new List<ValidationError>();

        ValidateHost(request.Host, errors);

        if (request.Port is < 1 or > IPEndPoint.MaxPort)
        {
            errors.Add(new ValidationError(
                nameof(request.Port),
                "Port must be between 1 and 65535."));
        }

        if (!LinuxUsernameRegex().IsMatch(request.Username))
        {
            errors.Add(new ValidationError(
                nameof(request.Username),
                "Username must be a valid Debian account name (lowercase letters, digits, underscore, or hyphen; maximum 32 characters)."));
        }

        if (request.Username.Equals("root", StringComparison.Ordinal) && !request.EnableRootLogin)
        {
            errors.Add(new ValidationError(
                nameof(request.EnableRootLogin),
                "Root login cannot be disabled when the deployment account is root."));
        }

        if (request.Password.Length == 0)
        {
            errors.Add(new ValidationError(
                nameof(request.Password),
                "A password is required for the initial SSH connection and sudo authentication."));
        }
        else if (request.Password.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            errors.Add(new ValidationError(
                nameof(request.Password),
                "Password cannot contain line breaks or null characters."));
        }
        else if (request.Password.Length > 1_024)
        {
            errors.Add(new ValidationError(
                nameof(request.Password),
                "Password cannot exceed 1024 characters."));
        }

        ValidateKeyPath(request.KeyPath, requireExistingKey, errors);
        return errors.Count == 0 ? ValidationResult.Success : new ValidationResult(errors);
    }

    public static void EnsureValid(
        DeploymentRequest? request,
        bool requireExistingKey = true)
    {
        var result = Validate(request, requireExistingKey);
        if (!result.IsValid)
        {
            throw new DeploymentValidationException(result.Errors);
        }
    }

    private static void ValidateHost(string host, ICollection<ValidationError> errors)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            errors.Add(new ValidationError(nameof(DeploymentRequest.Host), "Host is required."));
            return;
        }

        if (host.Length > 253 || Uri.CheckHostName(host) == UriHostNameType.Unknown)
        {
            errors.Add(new ValidationError(
                nameof(DeploymentRequest.Host),
                "Host must be a valid DNS name or IP address without a URL scheme or port."));
        }
    }

    private static void ValidateKeyPath(
        string keyPath,
        bool requireExistingKey,
        ICollection<ValidationError> errors)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            errors.Add(new ValidationError(nameof(DeploymentRequest.KeyPath), "Private-key path is required."));
            return;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(keyPath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            errors.Add(new ValidationError(nameof(DeploymentRequest.KeyPath), "Private-key path is invalid."));
            return;
        }

        if (!Path.IsPathFullyQualified(keyPath))
        {
            errors.Add(new ValidationError(
                nameof(DeploymentRequest.KeyPath),
                "Private-key path must be absolute."));
        }

        if (fullPath.EndsWith(".pub", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add(new ValidationError(
                nameof(DeploymentRequest.KeyPath),
                "Select the private key, not the .pub file."));
        }

        if (PrivateKeyPathPolicy.IsUnsupportedWindowsNetworkPath(fullPath))
        {
            errors.Add(new ValidationError(
                nameof(DeploymentRequest.KeyPath),
                PrivateKeyPathPolicy.WindowsNetworkPathErrorMessage));
            return;
        }

        if (!requireExistingKey)
        {
            return;
        }

        if (!File.Exists(fullPath))
        {
            errors.Add(new ValidationError(
                nameof(DeploymentRequest.KeyPath),
                "Private-key file does not exist."));
        }

        if (!File.Exists(fullPath + ".pub"))
        {
            errors.Add(new ValidationError(
                nameof(DeploymentRequest.KeyPath),
                "Matching .pub file does not exist."));
        }
    }

    [GeneratedRegex("^[a-z_][a-z0-9_-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex LinuxUsernameRegex();
}
