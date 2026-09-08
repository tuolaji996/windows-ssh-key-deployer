namespace SshKeyDeployer.Core;

public static class PrivateKeyPathPolicy
{
    public const string WindowsNetworkPathErrorMessage =
        "Private keys must be stored on a local Windows drive. Windows OpenSSH cannot reliably enforce the required private-key ACL on network or mapped drives. Choose a local path under %USERPROFILE%\\.ssh, then retry.";

    public static bool IsUnsupportedWindowsNetworkPath(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path.Trim());
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        if (fullPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var drivePath = fullPath;
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            if (fullPath.Length < 7 ||
                !char.IsAsciiLetter(fullPath[4]) ||
                fullPath[5] != ':' ||
                fullPath[6] is not ('\\' or '/'))
            {
                return true;
            }

            drivePath = fullPath[4..];
        }
        else if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return true;
        }

        var root = Path.GetPathRoot(drivePath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            return new DriveInfo(root).DriveType == DriveType.Network;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
