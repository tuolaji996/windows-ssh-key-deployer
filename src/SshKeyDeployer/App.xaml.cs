using System.Windows;

namespace SshKeyDeployer;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ThemeManager.ApplySystemTheme();
    }
}
