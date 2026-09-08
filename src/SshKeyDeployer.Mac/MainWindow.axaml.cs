using System.Diagnostics;
using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Styling;
using Avalonia.Threading;
using SshKeyDeployer.Core;

namespace SshKeyDeployer.Mac;

public partial class MainWindow : Window
{
    private const string ProjectUrl = "https://github.com/tuolaji996/windows-ssh-key-deployer";

    private readonly KeyGenerator _keyGenerator = new();
    private readonly DeploymentService _deploymentService = new();
    private CancellationTokenSource? _deploymentCancellation;
    private bool _isEnglish;
    private bool _isBusy;

    public MainWindow()
    {
        InitializeComponent();
        PortTextBox.Text = "22";
        UsernameTextBox.Text = "root";
        KeyPathTextBox.Text = DefaultKeyPath();
        ApplyLanguage();
        SetProgress(0, T("等待开始。", "Waiting to start."));
    }

    private void LanguageButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        _isEnglish = !_isEnglish;
        ApplyLanguage();
    }

    private void ThemeButton_Click(object? sender, RoutedEventArgs e)
    {
        var application = Application.Current;
        if (application is null)
        {
            return;
        }

        application.RequestedThemeVariant = application.ActualThemeVariant == ThemeVariant.Dark
            ? ThemeVariant.Light
            : ThemeVariant.Dark;
    }

    private void UseDefaultKeyPathButton_Click(object? sender, RoutedEventArgs e)
    {
        if (!_isBusy)
        {
            KeyPathTextBox.Text = DefaultKeyPath();
        }
    }

    private async void GenerateKeyButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        try
        {
            SetBusy(true, cancellable: false);
            SetProgress(10, T("正在生成 Ed25519 密钥。", "Generating an Ed25519 key."));
            var result = await EnsureKeyPairAsync(CancellationToken.None);
            SetProgress(100, T("密钥已生成。", "Key generated."));
            AppendLog(T(
                $"已保存密钥：{result.PrivateKeyPath}（{result.Sha256Fingerprint}）",
                $"Key saved: {result.PrivateKeyPath} ({result.Sha256Fingerprint})"));
        }
        catch (Exception exception)
        {
            SetProgress(0, T("生成密钥失败。", "Key generation failed."));
            AppendLog(TranslateException(exception), isError: true);
        }
        finally
        {
            SetBusy(false, cancellable: false);
        }
    }

    private async void DeployButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            _deploymentCancellation?.Cancel();
            return;
        }

        DeploymentRequest request;
        try
        {
            request = CreateRequest(requireExistingKey: false);
        }
        catch (Exception exception)
        {
            SetProgress(0, T("输入有误。", "Invalid input."));
            AppendLog(TranslateException(exception), isError: true);
            return;
        }

        _deploymentCancellation = new CancellationTokenSource();
        try
        {
            SetBusy(true, cancellable: true);
            SetProgress(5, T("正在准备部署。", "Preparing deployment."));
            AppendLog(T(
                $"准备部署到 {request.Username}@{request.Host}:{request.Port}",
                $"Preparing deployment to {request.Username}@{request.Host}:{request.Port}"));

            var key = await EnsureKeyPairAsync(_deploymentCancellation.Token);
            AppendLog(T(
                $"使用密钥 {Path.GetFileName(key.PrivateKeyPath)}（{key.Sha256Fingerprint}）",
                $"Using {Path.GetFileName(key.PrivateKeyPath)} ({key.Sha256Fingerprint})"));

            request = CreateRequest(requireExistingKey: true);
            var result = await Task.Run(
                () => _deploymentService.DeployAsync(
                    request,
                    ApproveHostKeyAsync,
                    ReportProgress,
                    _deploymentCancellation.Token),
                _deploymentCancellation.Token);

            SetProgress(100, T("部署成功，密钥登录已验证。", "Deployment succeeded and key login was verified."));
            AppendLog(T(
                $"已验证 {result.VerifiedUsername} 的密钥登录。",
                $"Key login was verified for {result.VerifiedUsername}."));
        }
        catch (OperationCanceledException)
        {
            SetProgress(0, T("部署已取消。", "Deployment cancelled."));
            AppendLog(T(
                "部署已取消；如远端已开始变更，工具会尝试回滚。",
                "Deployment was cancelled; the tool attempts rollback if remote changes began."),
                isError: true);
        }
        catch (DeploymentException exception)
        {
            var rollback = exception.RollbackAttempted
                ? exception.RollbackSucceeded
                    ? T("远端配置已恢复。", "Remote configuration was restored.")
                    : T("远端回滚未确认，请立即使用现有会话或控制台检查 SSH。", "Remote rollback was not confirmed. Check SSH immediately using an existing session or server console.")
                : T("尚未修改远端 SSH 配置。", "Remote SSH configuration was not changed.");
            SetProgress(0, T("部署失败。", "Deployment failed."));
            AppendLog($"{TranslateException(exception)} {rollback}", isError: true);
        }
        catch (Exception exception)
        {
            SetProgress(0, T("部署失败。", "Deployment failed."));
            AppendLog(TranslateException(exception), isError: true);
        }
        finally
        {
            PasswordBox.Text = string.Empty;
            _deploymentCancellation?.Dispose();
            _deploymentCancellation = null;
            SetBusy(false, cancellable: false);
        }
    }

    private void OpenKeyFolderButton_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath((KeyPathTextBox.Text ?? string.Empty).Trim()));
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                throw new DirectoryNotFoundException(T("密钥文件夹尚不存在。", "The key folder does not exist yet."));
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "open",
                UseShellExecute = false
            };
            startInfo.ArgumentList.Add(directory!);
            Process.Start(startInfo);
        }
        catch (Exception exception)
        {
            AppendLog(TranslateException(exception), isError: true);
        }
    }

    private void GitHubButton_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "open",
                UseShellExecute = false
            };
            startInfo.ArgumentList.Add(ProjectUrl);
            Process.Start(startInfo);
        }
        catch (Exception exception)
        {
            AppendLog(TranslateException(exception), isError: true);
        }
    }

    private DeploymentRequest CreateRequest(bool requireExistingKey)
    {
        if (!int.TryParse(PortTextBox.Text?.Trim(), out var port))
        {
            throw new ArgumentException("Port must be a number between 1 and 65535.");
        }

        var request = new DeploymentRequest(
            HostTextBox.Text ?? string.Empty,
            port,
            UsernameTextBox.Text ?? string.Empty,
            PasswordBox.Text ?? string.Empty,
            KeyPathTextBox.Text ?? string.Empty,
            RootLoginCheckBox.IsChecked == true,
            PasswordLoginCheckBox.IsChecked == true);
        DeploymentRequestValidator.EnsureValid(request, requireExistingKey);
        return request;
    }

    private async Task<KeyGenerationResult> EnsureKeyPairAsync(CancellationToken cancellationToken)
    {
        var privateKeyPath = Path.GetFullPath((KeyPathTextBox.Text ?? string.Empty).Trim());
        var publicKeyPath = privateKeyPath + ".pub";
        if (File.Exists(privateKeyPath) && File.Exists(publicKeyPath))
        {
            return await _keyGenerator.ReadExistingAsync(privateKeyPath, cancellationToken);
        }

        if (File.Exists(privateKeyPath) || File.Exists(publicKeyPath))
        {
            throw new IOException("The private key and .pub file must exist as a pair. Choose a new filename; existing keys will not be overwritten.");
        }

        return await _keyGenerator.GenerateAsync(privateKeyPath, cancellationToken);
    }

    private async Task<bool> ApproveHostKeyAsync(HostKeyInfo hostKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        HostKeyPromptWindow? prompt = null;
        using var registration = cancellationToken.Register(() =>
        {
            completion.TrySetCanceled(cancellationToken);
            Dispatcher.UIThread.Post(() => prompt?.Close(false));
        });

        Dispatcher.UIThread.Post(async () =>
        {
            if (completion.Task.IsCompleted)
            {
                return;
            }

            try
            {
                prompt = new HostKeyPromptWindow(
                    _isEnglish,
                    hostKey.Host,
                    hostKey.Port,
                    hostKey.Algorithm,
                    hostKey.Sha256Fingerprint);
                completion.TrySetResult(await prompt.ShowDialog<bool>(this));
            }
            catch (Exception exception)
            {
                completion.TrySetException(exception);
            }
            finally
            {
                prompt = null;
            }
        });

        return await completion.Task;
    }

    private void MainWindow_Closing(object? sender, WindowClosingEventArgs e)
    {
        if (!_isBusy)
        {
            return;
        }

        e.Cancel = true;
        _deploymentCancellation?.Cancel();
        SetProgress(0, T(
            "正在取消部署并等待远端回滚。请勿强制退出应用。",
            "Cancelling deployment and waiting for remote rollback. Do not force-quit the app."));
    }

    private void ReportProgress(DeploymentProgress progress)
    {
        Dispatcher.UIThread.Post(() =>
        {
            SetProgress(Math.Clamp(progress.Percent, 0, 100), TranslateProgress(progress.Stage));
            AppendLog(TranslateProgress(progress.Stage));
        });
    }

    private void SetBusy(bool busy, bool cancellable)
    {
        _isBusy = busy;
        HostTextBox.IsEnabled = !busy;
        PortTextBox.IsEnabled = !busy;
        UsernameTextBox.IsEnabled = !busy;
        PasswordBox.IsEnabled = !busy;
        RootLoginCheckBox.IsEnabled = !busy;
        PasswordLoginCheckBox.IsEnabled = !busy;
        KeyPathTextBox.IsEnabled = !busy;
        UseDefaultKeyPathButton.IsEnabled = !busy;
        GenerateKeyButton.IsEnabled = !busy;
        LanguageButton.IsEnabled = !busy;
        DeployButton.IsEnabled = !busy || cancellable;
        DeployButton.Content = busy && cancellable
            ? T("取消部署", "Cancel deployment")
            : T("生成并一键部署", "Generate and deploy");
    }

    private void SetProgress(int percent, string text)
    {
        ProgressBar.Value = percent;
        ProgressText.Text = $"{percent}% · {text}";
    }

    private void AppendLog(string text, bool isError = false)
    {
        var prefix = isError ? "ERROR" : "INFO";
        LogTextBox.Text += $"[{DateTime.Now:HH:mm:ss}] {prefix}  {text}{Environment.NewLine}";
    }

    private void ApplyLanguage()
    {
        Title = T("SSH 密钥部署器", "SSH Key Deployer");
        TitleText.Text = T("SSH 密钥部署器", "SSH Key Deployer");
        SubtitleText.Text = T("macOS Apple Silicon · Debian 12 / 13", "macOS Apple Silicon · Debian 12 / 13");
        LanguageButton.Content = _isEnglish ? "中文" : "EN";
        ThemeButton.Content = T("深色 / 浅色", "Dark / light");

        ConnectionSectionText.Text = T("服务器连接", "Server connection");
        HostLabelText.Text = T("服务器 IP 或域名", "Server IP or host name");
        HostTextBox.Watermark = T("例如 149.56.14.95", "For example 149.56.14.95");
        PortLabelText.Text = T("SSH 端口", "SSH port");
        UsernameLabelText.Text = T("账户", "Account");
        PasswordLabelText.Text = T("当前密码", "Current password");
        PasswordMemoryHintText.Text = T("密码仅用于本次连接，不会保存到磁盘或日志。", "The password is used only for this connection and is never written to disk or logs.");

        PolicySectionText.Text = T("SSH 登录策略", "SSH login policy");
        RootLoginCheckBox.Content = T("允许 root 登录", "Allow root login");
        PasswordLoginCheckBox.Content = T("允许密码登录", "Allow password login");
        PolicyHintText.Text = T("部署前请保留现有 SSH 会话或服务器控制台，直到密钥回连验证成功。", "Keep an existing SSH session or server console open until key-login verification succeeds.");

        KeySectionText.Text = T("本机密钥", "Local key");
        KeyPathLabelText.Text = T("私钥保存位置", "Private-key location");
        UseDefaultKeyPathButton.Content = T("使用默认位置", "Use default location");
        KeyPathHintText.Text = T("默认位置在 ~/.ssh/ssh-key-deployer；私钥仅保留在这台 Mac 上。", "The default is ~/.ssh/ssh-key-deployer; keep the private key only on this Mac.");
        GenerateKeyButton.Content = T("仅生成密钥", "Generate key only");
        OpenKeyFolderButton.Content = T("打开文件夹", "Open folder");
        DeployButton.Content = _isBusy
            ? T("取消部署", "Cancel deployment")
            : T("生成并一键部署", "Generate and deploy");

        ProgressSectionText.Text = T("部署进度", "Deployment progress");
        AboutSectionText.Text = T("关于", "About");
        AboutText.Text = T(
            $"版本 {VersionText()} · 开源软件\n生成 Ed25519 密钥、确认主机指纹、安装 authorized_keys、配置 sshd，并验证密钥登录。",
            $"Version {VersionText()} · Open source\nGenerate Ed25519 keys, confirm host fingerprints, install authorized_keys, configure sshd, and verify key login.");
        GitHubButton.Content = T("打开 GitHub 项目", "Open GitHub project");
        FooterText.Text = T("Copyright (c) 2026 tuolaji996 · GitHub Project", "Copyright (c) 2026 tuolaji996 · GitHub Project");
    }

    private string T(string chinese, string english) => _isEnglish ? english : chinese;

    private string TranslateException(Exception exception)
    {
        if (exception is InitialSshConnectionException connectionException)
        {
            var endpoint = $"{connectionException.Host}:{connectionException.Port}";
            return connectionException.Reason switch
            {
                InitialSshConnectionFailureReason.AuthenticationRejected => T(
                    $"已经连接到 SSH 服务器 {endpoint}，但服务器拒绝账户“{connectionException.Username}”的密码登录。请检查账户名和该账户当前密码（不是 root 密码），并确认服务器允许该账户使用密码认证。",
                    connectionException.Message),
                InitialSshConnectionFailureReason.TimedOut => T(
                    $"连接 SSH 服务器 {endpoint} 超时。请检查 IP 或域名、端口、防火墙、VPN / 局域网连接，并确认 sshd 正在运行。",
                    connectionException.Message),
                InitialSshConnectionFailureReason.NetworkUnavailable => T(
                    $"无法建立到 SSH 服务器 {endpoint} 的连接。请检查 IP 或域名、端口、防火墙、VPN / 局域网连接，并确认 sshd 正在运行。",
                    connectionException.Message),
                _ => T(
                    "初始 SSH 密码连接失败。请检查服务器地址、端口、账户、当前账户密码以及 SSH 服务。",
                    connectionException.Message)
            };
        }

        if (exception is SudoAccessException sudoException)
        {
            var username = sudoException.Username;
            return sudoException.Reason switch
            {
                SudoAccessFailureReason.NotAuthorized => T(
                    $"SSH 密码登录已经成功，但账户“{username}”没有 sudo 权限。能用 su 输入 root 密码，并不等于该账户拥有 sudo 权限。\n\n请在 root 终端执行：\nadduser {username} sudo\n\n然后完全退出“{username}”的所有会话，重新登录，运行 sudo -k true 验证后再试。",
                    sudoException.Message),
                SudoAccessFailureReason.CommandUnavailable => T(
                    $"SSH 密码登录已经成功，但服务器没有安装 sudo。\n\n请在 root 终端执行：\napt-get update\napt-get install -y sudo\nadduser {username} sudo\n\n然后完全退出“{username}”的所有会话，重新登录后再试。",
                    sudoException.Message),
                SudoAccessFailureReason.AuthenticationRejected => T(
                    $"SSH 密码登录已经成功，但 sudo 拒绝了账户“{username}”的密码。sudo 通常需要当前账户的密码，而不是 root 密码。\n\n请重新登录“{username}”，先运行 sudo -k true 验证，再回到本工具重试。",
                    sudoException.Message),
                _ => sudoException.Message
            };
        }

        var message = exception.Message;
        if (_isEnglish)
        {
            return message;
        }

        return message
            .Replace("Port must be a number between 1 and 65535.", "端口必须是 1 到 65535 之间的数字。", StringComparison.Ordinal)
            .Replace("Host is required.", "请输入服务器 IP 或域名。", StringComparison.Ordinal)
            .Replace("Username must be a valid Debian account name (lowercase letters, digits, underscore, or hyphen; maximum 32 characters).", "账户必须是有效的 Debian 用户名。", StringComparison.Ordinal)
            .Replace("Root login cannot be disabled when the deployment account is root.", "使用 root 账户部署时，必须开启 root 登录。", StringComparison.Ordinal)
            .Replace("A password is required for the initial SSH connection and sudo authentication.", "请输入当前 SSH 密码。", StringComparison.Ordinal)
            .Replace("Private-key path is required.", "请选择私钥保存位置。", StringComparison.Ordinal)
            .Replace("Private-key path must be absolute.", "密钥保存位置必须是完整路径。", StringComparison.Ordinal)
            .Replace("The private key and .pub file must exist as a pair. Choose a new filename; existing keys will not be overwritten.", "私钥和 .pub 文件必须成对存在。请选择新文件名，工具不会覆盖已有密钥。", StringComparison.Ordinal);
    }

    private string TranslateProgress(DeploymentStage stage) => stage switch
    {
        DeploymentStage.Validating => T("正在检查部署设置", "Validating deployment settings"),
        DeploymentStage.SecuringPrivateKey => T("正在加固并校验私钥", "Securing and validating the private key"),
        DeploymentStage.Connecting => T("正在使用密码连接服务器", "Connecting with password authentication"),
        DeploymentStage.AwaitingHostKeyApproval => T("等待确认服务器主机指纹", "Waiting for server host-key approval"),
        DeploymentStage.CheckingPrivileges => T("正在检查 Debian、sshd 和 sudo 权限", "Checking Debian, sshd, and sudo access"),
        DeploymentStage.InstallingPublicKey => T("正在安装公钥", "Installing the public key"),
        DeploymentStage.WritingSshdConfiguration => T("正在备份并写入 SSH 配置", "Backing up and writing SSH configuration"),
        DeploymentStage.ValidatingSshdConfiguration => T("正在验证 sshd 语法和生效值", "Validating sshd syntax and effective settings"),
        DeploymentStage.ReloadingSsh => T("正在平滑重载 SSH 服务", "Reloading the SSH service"),
        DeploymentStage.VerifyingEffectiveConfiguration => T("正在复核重载后的配置", "Verifying settings after reload"),
        DeploymentStage.VerifyingKeyLogin => T("正在使用新私钥回连验证", "Verifying key login with the new private key"),
        DeploymentStage.RollingBack => T("正在恢复服务器原配置", "Rolling back server changes"),
        DeploymentStage.Completed => T("部署和密钥登录验证完成", "Deployment and key-login verification complete"),
        _ => T("正在处理", "Working")
    };

    private static string DefaultKeyPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".ssh",
        "ssh-key-deployer",
        "server_ed25519");

    private static string VersionText() => typeof(App).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
        .InformationalVersion
        .Split('+')[0] ?? "1.2.1";
}
