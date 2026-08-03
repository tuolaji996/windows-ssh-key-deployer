using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using SshKeyDeployer.Core;

namespace SshKeyDeployer;

public partial class MainWindow : Window
{
    private readonly KeyGenerator _keyGenerator = new();
    private readonly DeploymentService _deploymentService = new();
    private CancellationTokenSource? _deploymentCancellation;
    private bool _isBusy;

    public MainWindow()
    {
        InitializeComponent();
        KeyPathTextBox.Text = FindAvailableDefaultKeyPath();
        UpdateKeyDisplays();
    }

    private void NavigationButton_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || DeployPage is null)
        {
            return;
        }

        DeployPage.Visibility = sender == DeployNavigationButton ? Visibility.Visible : Visibility.Collapsed;
        KeysPage.Visibility = sender == KeysNavigationButton ? Visibility.Visible : Visibility.Collapsed;
        AboutPage.Visibility = sender == AboutNavigationButton ? Visibility.Visible : Visibility.Collapsed;
        PageTitleText.Text = sender == KeysNavigationButton
            ? "密钥文件"
            : sender == AboutNavigationButton
                ? "关于"
                : "一键部署";
        MainScrollViewer.ScrollToTop();
        UpdateKeyDisplays();
    }

    private void ThemeButton_Click(object sender, RoutedEventArgs e)
    {
        ThemeManager.Toggle();
    }

    private void BrowseKeyPathButton_Click(object sender, RoutedEventArgs e)
    {
        var current = KeyPathTextBox.Text.Trim();
        var dialog = new SaveFileDialog
        {
            Title = "选择私钥保存位置",
            FileName = string.IsNullOrWhiteSpace(current) ? "server_ed25519" : Path.GetFileName(current),
            InitialDirectory = ResolveInitialDirectory(current),
            Filter = "SSH 私钥|*|所有文件|*.*",
            AddExtension = false,
            CheckFileExists = false,
            OverwritePrompt = false
        };

        if (dialog.ShowDialog(this) == true)
        {
            KeyPathTextBox.Text = dialog.FileName.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)
                ? dialog.FileName[..^4]
                : dialog.FileName;
            UpdateKeyDisplays();
        }
    }

    private async void GenerateOnlyButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            return;
        }

        try
        {
            SetBusy(true, "正在生成密钥", allowCancel: false);
            ResetProgress();
            SetStepState(ValidateStepDot, StepState.Completed);
            SetStepState(KeyStepDot, StepState.Active);
            AppendLog("正在生成 Ed25519 密钥...");

            var result = await EnsureKeyPairAsync(CancellationToken.None);
            SetStepState(KeyStepDot, StepState.Completed);
            ProgressSummaryText.Text = "密钥已生成";
            SetStatus("密钥已生成", success: true);
            AppendLog($"密钥已保存，指纹 {result.Sha256Fingerprint}");
            UpdateKeyDisplays();

            MessageBox.Show(
                this,
                $"密钥生成完成。\n\n私钥：{result.PrivateKeyPath}\n公钥：{result.PublicKeyPath}\n\n请勿分享私钥文件。",
                "密钥已生成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            AppendLog("操作已取消。");
        }
        catch (Exception exception)
        {
            MarkFailure("生成密钥失败", exception.Message);
        }
        finally
        {
            SetBusy(false, "就绪", allowCancel: false);
        }
    }

    private async void DeployButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy)
        {
            _deploymentCancellation?.Cancel();
            return;
        }

        ResetProgress();
        DeploymentRequest request;
        try
        {
            SetStepState(ValidateStepDot, StepState.Active);
            request = CreateRequest(requireExistingKey: false);
            DeploymentRequestValidator.EnsureValid(request, requireExistingKey: false);
            SetStepState(ValidateStepDot, StepState.Completed);
        }
        catch (Exception exception)
        {
            SetStepState(ValidateStepDot, StepState.Failed);
            MarkFailure("输入有误", TranslateValidationMessage(exception.Message));
            return;
        }

        _deploymentCancellation = new CancellationTokenSource();
        try
        {
            SetBusy(true, "部署中", allowCancel: true);
            AppendLog($"准备部署到 {request.Username}@{request.Host}:{request.Port}");

            SetStepState(KeyStepDot, StepState.Active);
            var keyResult = await EnsureKeyPairAsync(_deploymentCancellation.Token);
            SetStepState(KeyStepDot, StepState.Completed);
            AppendLog($"使用密钥 {Path.GetFileName(keyResult.PrivateKeyPath)} ({keyResult.Sha256Fingerprint})");

            request = CreateRequest(requireExistingKey: true);
            var result = await _deploymentService.DeployAsync(
                request,
                ApproveHostKeyAsync,
                ReportProgress,
                _deploymentCancellation.Token);

            SetAllSteps(StepState.Completed);
            ProgressSummaryText.Text = "部署成功";
            SetStatus("部署成功", success: true);
            AppendLog($"完成：已验证 {result.VerifiedUsername} 的密钥登录。");
            PasswordInput.Clear();
            UpdateKeyDisplays();

            MessageBox.Show(
                this,
                $"部署完成，已用新私钥成功登录。\n\n验证账户：{result.VerifiedUsername}\n公钥指纹：{result.PublicKeyFingerprint}\nSSH 配置：{result.ManagedConfigPath}",
                "部署成功",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            ProgressSummaryText.Text = "已取消";
            SetStatus("已取消", success: false);
            AppendLog("部署已取消。若远端配置已开始修改，工具会先执行回滚。", isError: true);
        }
        catch (DeploymentException exception)
        {
            var rollback = exception.RollbackAttempted
                ? exception.RollbackSucceeded ? "远端配置已恢复。" : "远端回滚未确认，请立即使用现有会话或控制台检查 SSH。"
                : "尚未修改远端 SSH 配置。";
            MarkFailure("部署失败", $"{exception.Message}\n\n{rollback}");
        }
        catch (Exception exception)
        {
            MarkFailure("部署失败", exception.Message);
        }
        finally
        {
            PasswordInput.Clear();
            _deploymentCancellation?.Dispose();
            _deploymentCancellation = null;
            SetBusy(false, HeaderStatusText.Text, allowCancel: false);
        }
    }

    private DeploymentRequest CreateRequest(bool requireExistingKey)
    {
        if (!int.TryParse(PortTextBox.Text.Trim(), out var port))
        {
            throw new ArgumentException("端口必须是 1 到 65535 之间的数字。");
        }

        var request = new DeploymentRequest(
            HostTextBox.Text,
            port,
            UserNameTextBox.Text,
            PasswordInput.Password,
            KeyPathTextBox.Text,
            AllowRootLoginCheckBox.IsChecked == true,
            AllowPasswordLoginCheckBox.IsChecked == true);

        DeploymentRequestValidator.EnsureValid(request, requireExistingKey);
        return request;
    }

    private async Task<KeyGenerationResult> EnsureKeyPairAsync(CancellationToken cancellationToken)
    {
        var privateKeyPath = Path.GetFullPath(KeyPathTextBox.Text.Trim());
        var publicKeyPath = privateKeyPath + ".pub";
        if (File.Exists(privateKeyPath) && File.Exists(publicKeyPath))
        {
            return await _keyGenerator.ReadExistingAsync(privateKeyPath, cancellationToken);
        }

        if (File.Exists(privateKeyPath) || File.Exists(publicKeyPath))
        {
            throw new IOException("私钥和 .pub 必须成对存在。请选择新的文件名，工具不会覆盖已有密钥。");
        }

        return await _keyGenerator.GenerateAsync(privateKeyPath, cancellationToken);
    }

    private async Task<bool> ApproveHostKeyAsync(HostKeyInfo hostKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await Dispatcher.InvokeAsync(() =>
        {
            var dialog = new HostKeyPromptWindow(
                hostKey.Host,
                hostKey.Port,
                hostKey.Algorithm,
                hostKey.Sha256Fingerprint)
            {
                Owner = this
            };
            return dialog.ShowDialog() == true;
        });
    }

    private void ReportProgress(DeploymentProgress progress)
    {
        Dispatcher.Invoke(() =>
        {
            var message = TranslateProgress(progress);
            ProgressSummaryText.Text = $"{Math.Clamp(progress.Percent, 0, 100)}% · {message}";
            AppendLog(message);

            switch (progress.Stage)
            {
                case DeploymentStage.Validating:
                case DeploymentStage.SecuringPrivateKey:
                    SetStepState(KeyStepDot, StepState.Active);
                    break;
                case DeploymentStage.Connecting:
                case DeploymentStage.AwaitingHostKeyApproval:
                case DeploymentStage.CheckingPrivileges:
                    SetStepState(ConnectStepDot, StepState.Active);
                    break;
                case DeploymentStage.InstallingPublicKey:
                case DeploymentStage.WritingSshdConfiguration:
                case DeploymentStage.ValidatingSshdConfiguration:
                case DeploymentStage.ReloadingSsh:
                case DeploymentStage.VerifyingEffectiveConfiguration:
                    SetStepState(ConnectStepDot, StepState.Completed);
                    SetStepState(ConfigureStepDot, StepState.Active);
                    break;
                case DeploymentStage.VerifyingKeyLogin:
                    SetStepState(ConfigureStepDot, StepState.Completed);
                    SetStepState(VerifyStepDot, StepState.Active);
                    break;
                case DeploymentStage.Completed:
                    SetAllSteps(StepState.Completed);
                    break;
                case DeploymentStage.RollingBack:
                    SetStepState(ConfigureStepDot, StepState.Failed);
                    break;
            }
        });
    }

    private void SetBusy(bool busy, string status, bool allowCancel)
    {
        _isBusy = busy;
        HostTextBox.IsEnabled = !busy;
        PortTextBox.IsEnabled = !busy;
        UserNameTextBox.IsEnabled = !busy;
        PasswordInput.IsEnabled = !busy;
        AllowRootLoginCheckBox.IsEnabled = !busy;
        AllowPasswordLoginCheckBox.IsEnabled = !busy;
        BrowseKeyPathButton.IsEnabled = !busy;
        GenerateOnlyButton.IsEnabled = !busy;
        DeployButton.IsEnabled = !busy || allowCancel;
        DeployButton.Content = busy && allowCancel ? "取消部署" : "生成并一键部署";
        DeployButton.Tag = busy && allowCancel ? "\uE71A" : "\uE768";
        if (busy)
        {
            SetStatus(status, success: false);
        }
    }

    private void SetStatus(string text, bool success)
    {
        HeaderStatusText.Text = text;
        NavStatusText.Text = text;
        var brush = (Brush)FindResource(success ? "AccentBrush" : "NeutralStatusBrush");
        NavStatusDot.Background = brush;
        HeaderStatusBadge.Background = brush;
    }

    private void ResetProgress()
    {
        DeploymentLogTextBox.Clear();
        ProgressSummaryText.Text = "正在准备";
        SetAllSteps(StepState.Pending);
    }

    private void SetAllSteps(StepState state)
    {
        SetStepState(ValidateStepDot, state);
        SetStepState(KeyStepDot, state);
        SetStepState(ConnectStepDot, state);
        SetStepState(ConfigureStepDot, state);
        SetStepState(VerifyStepDot, state);
    }

    private void SetStepState(Border border, StepState state)
    {
        var backgroundKey = state switch
        {
            StepState.Active => "InfoBrush",
            StepState.Completed => "AccentBrush",
            StepState.Failed => "DangerBrush",
            _ => "SurfaceAltBrush"
        };
        var borderKey = state == StepState.Pending ? "BorderBrush" : state switch
        {
            StepState.Active => "InfoBrush",
            StepState.Completed => "AccentBrush",
            _ => "DangerBrush"
        };
        border.SetResourceReference(Border.BackgroundProperty, backgroundKey);
        border.SetResourceReference(Border.BorderBrushProperty, borderKey);

        if (border.Child is TextBlock label)
        {
            label.SetResourceReference(
                TextBlock.ForegroundProperty,
                state == StepState.Pending ? "TextBrush" : "AccentForegroundBrush");
            if (state is StepState.Completed or StepState.Failed)
            {
                label.Text = state == StepState.Completed ? "\uE73E" : "\uE711";
                label.FontFamily = (FontFamily)FindResource("IconFont");
            }
            else
            {
                label.Text = GetStepNumber(border);
                label.FontFamily = new FontFamily("Segoe UI Variable Text, Microsoft YaHei UI, Segoe UI");
            }
        }
    }

    private void AppendLog(string message, bool isError = false)
    {
        var sanitized = message.Replace("\r", " ").Replace("\n", " ");
        DeploymentLogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {(isError ? "错误：" : string.Empty)}{sanitized}{Environment.NewLine}");
        DeploymentLogTextBox.ScrollToEnd();
    }

    private void MarkFailure(string title, string message)
    {
        ProgressSummaryText.Text = title;
        SetStatus(title, success: false);
        AppendLog(message, isError: true);
        MessageBox.Show(this, message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void UpdateKeyDisplays()
    {
        if (PrivateKeyDisplayTextBox is null)
        {
            return;
        }

        var privatePath = KeyPathTextBox.Text.Trim();
        PrivateKeyDisplayTextBox.Text = privatePath;
        PublicKeyDisplayTextBox.Text = string.IsNullOrWhiteSpace(privatePath) ? string.Empty : privatePath + ".pub";
    }

    private void OpenKeyFolderButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(KeyPathTextBox.Text.Trim()));
            if (directory is null || !Directory.Exists(directory))
            {
                throw new DirectoryNotFoundException("密钥文件夹尚不存在。");
            }

            Process.Start(new ProcessStartInfo("explorer.exe", directory) { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法打开文件夹", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CopyPublicKeyButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var publicPath = Path.GetFullPath(KeyPathTextBox.Text.Trim()) + ".pub";
            var publicKey = File.ReadAllText(publicPath).Trim();
            Clipboard.SetText(publicKey);
            FooterStatusText.Text = "公钥已复制";
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "无法复制公钥", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OpenGitHubButton_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo(
            "https://github.com/tuolaji996/windows-ssh-key-deployer")
        { UseShellExecute = true });
    }

    protected override void OnClosed(EventArgs e)
    {
        _deploymentCancellation?.Cancel();
        _deploymentCancellation?.Dispose();
        base.OnClosed(e);
    }

    private static string ResolveInitialDirectory(string current)
    {
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(current));
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
            {
                return directory;
            }
        }
        catch
        {
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    }

    private static string FindAvailableDefaultKeyPath()
    {
        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "SSH Keys");
        var candidate = Path.Combine(directory, "server_ed25519");
        if (!File.Exists(candidate) && !File.Exists(candidate + ".pub"))
        {
            return candidate;
        }

        for (var number = 2; number < 1000; number++)
        {
            candidate = Path.Combine(directory, $"server_ed25519_{number}");
            if (!File.Exists(candidate) && !File.Exists(candidate + ".pub"))
            {
                return candidate;
            }
        }

        return Path.Combine(directory, $"server_ed25519_{DateTime.Now:yyyyMMddHHmmss}");
    }

    private static string TranslateValidationMessage(string message) =>
        message
            .Replace("Host is required.", "请输入服务器 IP 或域名。", StringComparison.Ordinal)
            .Replace("Host must be a valid DNS name or IP address without a URL scheme or port.", "服务器地址应为 IP 或域名，不要包含 ssh:// 或端口。", StringComparison.Ordinal)
            .Replace("Port must be between 1 and 65535.", "端口必须在 1 到 65535 之间。", StringComparison.Ordinal)
            .Replace("Username must be a valid Debian account name (lowercase letters, digits, underscore, or hyphen; maximum 32 characters).", "账户必须是有效的 Debian 用户名。", StringComparison.Ordinal)
            .Replace("Root login cannot be disabled when the deployment account is root.", "使用 root 账户部署时，必须开启 root 登录。", StringComparison.Ordinal)
            .Replace("A password is required for the initial SSH connection and sudo authentication.", "请输入当前 SSH 密码。", StringComparison.Ordinal)
            .Replace("Password cannot contain line breaks or null characters.", "密码不能包含换行或空字符。", StringComparison.Ordinal)
            .Replace("Password cannot exceed 1024 characters.", "密码长度不能超过 1024 个字符。", StringComparison.Ordinal)
            .Replace("Private-key path is required.", "请选择私钥保存位置。", StringComparison.Ordinal)
            .Replace("Private-key path must be absolute.", "密钥保存位置必须是完整路径。", StringComparison.Ordinal);

    private static string TranslateProgress(DeploymentProgress progress) => progress.Stage switch
    {
        DeploymentStage.Validating => "正在检查部署设置",
        DeploymentStage.SecuringPrivateKey => "正在加固并校验私钥",
        DeploymentStage.Connecting => "正在使用密码连接服务器",
        DeploymentStage.AwaitingHostKeyApproval => "等待确认服务器主机指纹",
        DeploymentStage.CheckingPrivileges => "正在检查 Debian、sshd 和 sudo 权限",
        DeploymentStage.InstallingPublicKey => progress.Percent >= 39
            ? "正在改配置前验证当前账户的密钥登录"
            : "正在安装公钥",
        DeploymentStage.WritingSshdConfiguration => "正在备份并写入 SSH 配置",
        DeploymentStage.ValidatingSshdConfiguration => "正在验证 sshd 语法和生效值",
        DeploymentStage.ReloadingSsh => "正在平滑重载 SSH 服务",
        DeploymentStage.VerifyingEffectiveConfiguration => "正在复核重载后的配置",
        DeploymentStage.VerifyingKeyLogin => "正在使用新私钥回连验证",
        DeploymentStage.RollingBack => "正在恢复服务器原配置",
        DeploymentStage.Completed => "部署和密钥登录验证完成",
        _ => progress.Message
    };

    private static string GetStepNumber(Border border) => border.Name switch
    {
        nameof(ValidateStepDot) => "1",
        nameof(KeyStepDot) => "2",
        nameof(ConnectStepDot) => "3",
        nameof(ConfigureStepDot) => "4",
        nameof(VerifyStepDot) => "5",
        _ => string.Empty
    };

    private enum StepState
    {
        Pending,
        Active,
        Completed,
        Failed
    }
}
