using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Navigation;
using Microsoft.Win32;
using SshKeyDeployer.Core;

namespace SshKeyDeployer;

public partial class MainWindow : Window
{
    private const string ProjectUrl = "https://github.com/tuolaji996/windows-ssh-key-deployer";

    private readonly KeyGenerator _keyGenerator = new();
    private readonly DeploymentService _deploymentService = new();
    private readonly List<DeploymentLogEntry> _deploymentLogs = [];
    private CancellationTokenSource? _deploymentCancellation;
    private LocalizedText _statusText = new("就绪", "Ready");
    private LocalizedText _navigationStatusText = new("等待部署", "Waiting to deploy");
    private LocalizedText _progressSummary = new("尚未开始", "Not started");
    private LocalizedText _footerStatusText = new("密码不会保存到磁盘", "Passwords are not saved to disk");
    private int? _progressPercent;
    private bool _allowCancel;
    private bool _isBusy;
    private bool _statusSuccess;
    private bool _languageRefreshPending;

    public MainWindow()
    {
        UiLanguage.Current = AppLanguage.SimplifiedChinese;
        InitializeComponent();
        UiLanguage.Changed += UiLanguage_Changed;
        KeyPathTextBox.Text = FindAvailableDefaultKeyPath();
        UpdateKeyDisplays();
        ApplyLanguage();
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
        UpdatePageTitle();
        MainScrollViewer.ScrollToTop();
        UpdateKeyDisplays();
    }

    private void ThemeButton_Click(object sender, RoutedEventArgs e)
    {
        ThemeManager.Toggle();
    }

    private void LanguageButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_isBusy)
        {
            UiLanguage.Toggle();
        }
    }

    private void UiLanguage_Changed(object? sender, EventArgs e)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(ApplyLanguageWhenIdle);
            return;
        }

        ApplyLanguageWhenIdle();
    }

    private void ApplyLanguageWhenIdle()
    {
        if (_isBusy)
        {
            _languageRefreshPending = true;
            return;
        }

        _languageRefreshPending = false;
        ApplyLanguage();
    }

    private void BrowseKeyPathButton_Click(object sender, RoutedEventArgs e)
    {
        var current = KeyPathTextBox.Text.Trim();
        var dialog = new SaveFileDialog
        {
            Title = T("选择私钥保存位置", "Choose a private key location"),
            FileName = string.IsNullOrWhiteSpace(current) ? "server_ed25519" : Path.GetFileName(current),
            InitialDirectory = ResolveInitialDirectory(current),
            Filter = T("SSH 私钥|*|所有文件|*.*", "SSH private key|*|All files|*.*"),
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
            SetBusy(true, "正在生成密钥", "Generating key", allowCancel: false);
            ResetProgress();
            SetStepState(ValidateStepDot, StepState.Completed);
            SetStepState(KeyStepDot, StepState.Active);
            AppendLog("正在生成 Ed25519 密钥...", "Generating Ed25519 key...");

            var result = await EnsureKeyPairAsync(CancellationToken.None);
            SetStepState(KeyStepDot, StepState.Completed);
            SetProgressSummary("密钥已生成", "Key generated");
            SetStatus("密钥已生成", "Key generated", success: true);
            AppendLog(
                $"密钥已保存，指纹 {result.Sha256Fingerprint}",
                $"Key saved. Fingerprint: {result.Sha256Fingerprint}");
            UpdateKeyDisplays();

            MessageBox.Show(
                this,
                T(
                    $"密钥生成完成。\n\n私钥：{result.PrivateKeyPath}\n公钥：{result.PublicKeyPath}\n\n请勿分享私钥文件。",
                    $"Key generation complete.\n\nPrivate key: {result.PrivateKeyPath}\nPublic key: {result.PublicKeyPath}\n\nDo not share the private key file."),
                T("密钥已生成", "Key generated"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            AppendLog("操作已取消。", "Operation cancelled.");
        }
        catch (Exception exception)
        {
            MarkFailure("生成密钥失败", "Key generation failed", TranslateExceptionMessage(exception.Message));
        }
        finally
        {
            SetBusy(false);
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
            MarkFailure("输入有误", "Invalid input", TranslateValidationMessage(exception.Message));
            return;
        }

        _deploymentCancellation = new CancellationTokenSource();
        try
        {
            SetBusy(true, "部署中", "Deploying", allowCancel: true);
            AppendLog(
                $"准备部署到 {request.Username}@{request.Host}:{request.Port}",
                $"Preparing deployment to {request.Username}@{request.Host}:{request.Port}");

            SetStepState(KeyStepDot, StepState.Active);
            var keyResult = await EnsureKeyPairAsync(_deploymentCancellation.Token);
            SetStepState(KeyStepDot, StepState.Completed);
            AppendLog(
                $"使用密钥 {Path.GetFileName(keyResult.PrivateKeyPath)} ({keyResult.Sha256Fingerprint})",
                $"Using key {Path.GetFileName(keyResult.PrivateKeyPath)} ({keyResult.Sha256Fingerprint})");

            request = CreateRequest(requireExistingKey: true);
            var result = await _deploymentService.DeployAsync(
                request,
                ApproveHostKeyAsync,
                ReportProgress,
                _deploymentCancellation.Token);

            SetAllSteps(StepState.Completed);
            SetProgressSummary("部署成功", "Deployment succeeded");
            SetStatus("部署成功", "Deployment succeeded", success: true);
            AppendLog(
                $"完成：已验证 {result.VerifiedUsername} 的密钥登录。",
                $"Complete: key login for {result.VerifiedUsername} was verified.");
            PasswordInput.Clear();
            UpdateKeyDisplays();

            MessageBox.Show(
                this,
                T(
                    $"部署完成，已用新私钥成功登录。\n\n验证账户：{result.VerifiedUsername}\n公钥指纹：{result.PublicKeyFingerprint}\nSSH 配置：{result.ManagedConfigPath}",
                    $"Deployment complete. Login with the new private key succeeded.\n\nVerified account: {result.VerifiedUsername}\nPublic key fingerprint: {result.PublicKeyFingerprint}\nSSH configuration: {result.ManagedConfigPath}"),
                T("部署成功", "Deployment succeeded"),
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            SetProgressSummary("已取消", "Cancelled");
            SetStatus("已取消", "Cancelled", success: false);
            AppendLog(
                "部署已取消。若远端配置已开始修改，工具会先执行回滚。",
                "Deployment cancelled. If remote configuration changes began, the tool attempted a rollback first.",
                isError: true);
        }
        catch (DeploymentException exception)
        {
            var rollback = exception.RollbackAttempted
                ? exception.RollbackSucceeded
                    ? new LocalizedText("远端配置已恢复。", "Remote configuration was restored.")
                    : new LocalizedText(
                        "远端回滚未确认，请立即使用现有会话或控制台检查 SSH。",
                        "Remote rollback was not confirmed. Check SSH immediately from an existing session or the server console.")
                : new LocalizedText("尚未修改远端 SSH 配置。", "Remote SSH configuration was not changed.");
            MarkFailure(
                "部署失败",
                "Deployment failed",
                new LocalizedText(
                    $"{exception.Message}\n\n{rollback.Chinese}",
                    $"{exception.Message}\n\n{rollback.English}"));
        }
        catch (Exception exception)
        {
            MarkFailure("部署失败", "Deployment failed", TranslateExceptionMessage(exception.Message));
        }
        finally
        {
            PasswordInput.Clear();
            _deploymentCancellation?.Dispose();
            _deploymentCancellation = null;
            SetBusy(false);
        }
    }

    private DeploymentRequest CreateRequest(bool requireExistingKey)
    {
        if (!int.TryParse(PortTextBox.Text.Trim(), out var port))
        {
            throw new ArgumentException("Port must be a number between 1 and 65535.");
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
            throw new IOException(
                "The private key and .pub file must exist as a pair. Choose a new filename; existing keys will not be overwritten.");
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
            SetProgressSummary(message, Math.Clamp(progress.Percent, 0, 100));
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

    private void SetBusy(
        bool busy,
        string? statusChinese = null,
        string? statusEnglish = null,
        bool allowCancel = false)
    {
        _isBusy = busy;
        _allowCancel = busy && allowCancel;
        HostTextBox.IsEnabled = !busy;
        PortTextBox.IsEnabled = !busy;
        UserNameTextBox.IsEnabled = !busy;
        PasswordInput.IsEnabled = !busy;
        AllowRootLoginCheckBox.IsEnabled = !busy;
        AllowPasswordLoginCheckBox.IsEnabled = !busy;
        BrowseKeyPathButton.IsEnabled = !busy;
        GenerateOnlyButton.IsEnabled = !busy;
        LanguageButton.IsEnabled = !busy;
        DeployButton.IsEnabled = !busy || _allowCancel;
        UpdateActionButtons();
        if (busy && statusChinese is not null && statusEnglish is not null)
        {
            SetStatus(statusChinese, statusEnglish, success: false);
        }

        if (!busy && _languageRefreshPending)
        {
            _languageRefreshPending = false;
            ApplyLanguage();
        }
    }

    private void UpdateActionButtons()
    {
        GenerateOnlyButton.Content = T("仅生成密钥", "Generate key only");
        DeployButton.Content = _isBusy && _allowCancel
            ? T("取消部署", "Cancel deployment")
            : T("生成并一键部署", "Generate and deploy");
        DeployButton.Tag = _isBusy && _allowCancel ? "\uE71A" : "\uE768";
    }

    private void SetStatus(string chinese, string english, bool success) =>
        SetStatus(new LocalizedText(chinese, english), success);

    private void SetStatus(LocalizedText text, bool success)
    {
        _statusText = text;
        _navigationStatusText = text;
        _statusSuccess = success;
        RefreshStatus();
    }

    private void RefreshStatus()
    {
        HeaderStatusText.Text = _statusText.Value;
        NavStatusText.Text = _navigationStatusText.Value;
        var brush = (Brush)FindResource(_statusSuccess ? "AccentBrush" : "NeutralStatusBrush");
        NavStatusDot.Background = brush;
        HeaderStatusBadge.Background = brush;
    }

    private void ResetProgress()
    {
        _deploymentLogs.Clear();
        _progressPercent = null;
        SetProgressSummary("正在准备", "Preparing");
        RefreshDeploymentLog();
        SetAllSteps(StepState.Pending);
    }

    private void SetProgressSummary(string chinese, string english, int? percent = null) =>
        SetProgressSummary(new LocalizedText(chinese, english), percent);

    private void SetProgressSummary(LocalizedText text, int? percent = null)
    {
        _progressSummary = text;
        _progressPercent = percent;
        RefreshProgressSummary();
    }

    private void RefreshProgressSummary()
    {
        var message = _progressSummary.Value;
        ProgressSummaryText.Text = _progressPercent is int percent
            ? $"{percent}% · {message}"
            : message;
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

    private void AppendLog(string chinese, string english, bool isError = false) =>
        AppendLog(new LocalizedText(chinese, english), isError);

    private void AppendLog(LocalizedText message, bool isError = false)
    {
        var entry = new DeploymentLogEntry(DateTime.Now, message, isError);
        _deploymentLogs.Add(entry);

        if (_deploymentLogs.Count == 1)
        {
            DeploymentLogTextBox.Clear();
        }

        AppendLogEntry(entry);
        DeploymentLogTextBox.ScrollToEnd();
    }

    private void RefreshDeploymentLog()
    {
        DeploymentLogTextBox.Clear();
        if (_deploymentLogs.Count == 0)
        {
            DeploymentLogTextBox.Text = T("等待开始...", "Waiting to start...");
            return;
        }

        foreach (var entry in _deploymentLogs)
        {
            AppendLogEntry(entry);
        }

        DeploymentLogTextBox.ScrollToEnd();
    }

    private void AppendLogEntry(DeploymentLogEntry entry)
    {
        var sanitized = entry.Message.Value.Replace("\r", " ").Replace("\n", " ");
        var errorPrefix = entry.IsError ? T("错误：", "Error: ") : string.Empty;
        DeploymentLogTextBox.AppendText(
            $"[{entry.Timestamp:HH:mm:ss}] {errorPrefix}{sanitized}{Environment.NewLine}");
    }

    private void MarkFailure(string titleChinese, string titleEnglish, LocalizedText message)
    {
        var title = new LocalizedText(titleChinese, titleEnglish);
        SetProgressSummary(title);
        SetStatus(title, success: false);
        AppendLog(message, isError: true);
        MessageBox.Show(this, message.Value, title.Value, MessageBoxButton.OK, MessageBoxImage.Error);
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
                throw new DirectoryNotFoundException("Key folder does not exist yet.");
            }

            Process.Start(new ProcessStartInfo("explorer.exe", directory) { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            var detail = TranslateExceptionMessage(exception.Message);
            var message = new LocalizedText(
                $"无法打开密钥文件夹。\n\n{detail.Chinese}",
                $"Could not open the key folder.\n\n{detail.English}");
            MessageBox.Show(
                this,
                message.Value,
                T("无法打开文件夹", "Could not open folder"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void CopyPublicKeyButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var publicPath = Path.GetFullPath(KeyPathTextBox.Text.Trim()) + ".pub";
            var publicKey = File.ReadAllText(publicPath).Trim();
            Clipboard.SetText(publicKey);
            SetFooterStatus("公钥已复制", "Public key copied");
        }
        catch (Exception exception)
        {
            var detail = TranslateExceptionMessage(exception.Message);
            var message = new LocalizedText(
                $"无法复制公钥。\n\n{detail.Chinese}",
                $"Could not copy the public key.\n\n{detail.English}");
            MessageBox.Show(
                this,
                message.Value,
                T("无法复制公钥", "Could not copy public key"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void OpenGitHubButton_Click(object sender, RoutedEventArgs e)
    {
        OpenProjectUrl();
    }

    private void ProjectLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        e.Handled = true;
        OpenProjectUrl();
    }

    private void OpenProjectUrl()
    {
        try
        {
            Process.Start(new ProcessStartInfo(ProjectUrl) { UseShellExecute = true });
        }
        catch (Exception exception)
        {
            var message = new LocalizedText(
                $"无法打开 GitHub 项目页面。\n\n{exception.Message}",
                $"Could not open the GitHub project page.\n\n{exception.Message}");
            MessageBox.Show(
                this,
                message.Value,
                T("无法打开 GitHub", "Could not open GitHub"),
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        UiLanguage.Changed -= UiLanguage_Changed;
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

    private void ApplyLanguage()
    {
        var english = UiLanguage.IsEnglish;

        BrandSubtitleText.Text = T("一键部署工具", "One-click SSH deployment");
        DeployNavigationText.Text = T("一键部署", "Deploy");
        KeysNavigationText.Text = T("密钥文件", "Key files");
        AboutNavigationText.Text = T("关于", "About");
        AutomationProperties.SetName(DeployNavigationButton, T("一键部署", "Deploy"));
        AutomationProperties.SetName(KeysNavigationButton, T("密钥文件", "Key files"));
        AutomationProperties.SetName(AboutNavigationButton, T("关于", "About"));
        UpdatePageTitle();

        LanguageButton.Content = english ? "中文" : "EN";
        var languageAction = english ? "切换至中文" : "Switch to English";
        LanguageButton.ToolTip = languageAction;
        AutomationProperties.SetName(LanguageButton, languageAction);

        var themeAction = T("切换亮色 / 深色主题", "Switch light / dark theme");
        ThemeButton.ToolTip = themeAction;
        AutomationProperties.SetName(ThemeButton, themeAction);

        DeployLeadText.Text = T(
            "输入 Debian 服务器信息，生成独立 Ed25519 密钥并完成安装、配置校验和回连验证。",
            "Enter Debian server details to generate a standalone Ed25519 key, install it, validate the configuration, and verify key login.");
        ConnectionSectionTitleText.Text = T("服务器连接", "Server connection");
        HostLabelText.Text = T("IP 或域名", "IP address or hostname");
        PortLabelText.Text = T("端口", "Port");
        AccountLabelText.Text = T("账户", "Account");
        PasswordLabelText.Text = T("当前密码", "Current password");
        AutomationProperties.SetName(HostTextBox, T("服务器 IP 或域名", "Server IP address or hostname"));
        AutomationProperties.SetName(PortTextBox, T("SSH 端口", "SSH port"));
        AutomationProperties.SetName(UserNameTextBox, T("SSH 账户", "SSH account"));
        AutomationProperties.SetName(PasswordInput, T("SSH 密码", "SSH password"));

        SshPolicySectionTitleText.Text = T("SSH 登录策略", "SSH login policy");
        RootLoginLabelText.Text = T("允许 root 登录", "Allow root login");
        RootLoginDescriptionText.Text = T("关闭后会写入 PermitRootLogin no", "Writes PermitRootLogin no when disabled");
        PasswordLoginLabelText.Text = T("允许密码登录", "Allow password login");
        PasswordLoginDescriptionText.Text = T("建议确认密钥可用后再关闭", "Turn it off only after confirming key login");
        PolicyWarningText.Text = T(
            "配置写入前会备份；语法或回连验证失败时自动恢复。",
            "The configuration is backed up before writing and restored automatically if syntax or key-login verification fails.");
        AutomationProperties.SetName(AllowRootLoginCheckBox, T("允许 root 登录", "Allow root login"));
        AutomationProperties.SetName(AllowPasswordLoginCheckBox, T("允许密码登录", "Allow password login"));

        KeyFileSectionTitleText.Text = T("密钥文件", "Key files");
        KeyFileDescriptionText.Text = T(
            "选择私钥保存位置；公钥会自动使用相同文件名并加上 .pub。",
            "Choose where to save the private key. The public key uses the same filename with .pub appended.");
        BrowseKeyPathButton.Content = T("选择位置", "Choose location");
        AutomationProperties.SetName(KeyPathTextBox, T("私钥保存路径", "Private key save path"));
        AutomationProperties.SetName(BrowseKeyPathButton, T("选择私钥保存位置", "Choose private key location"));
        PrivacyText.Text = T("密码仅用于本次连接，不会保存。", "The password is used only for this connection and is never saved.");
        UpdateActionButtons();
        AutomationProperties.SetName(GenerateOnlyButton, T("仅生成密钥", "Generate key only"));
        AutomationProperties.SetName(DeployButton, _isBusy && _allowCancel
            ? T("取消部署", "Cancel deployment")
            : T("生成并一键部署", "Generate and deploy"));

        DeploymentProgressTitleText.Text = T("部署进度", "Deployment progress");
        ValidateStepLabelText.Text = T("检查输入", "Validate");
        KeyStepLabelText.Text = T("生成密钥", "Generate key");
        ConnectStepLabelText.Text = T("连接服务器", "Connect");
        ConfigureStepLabelText.Text = T("安装与配置", "Install & configure");
        VerifyStepLabelText.Text = T("密钥回连", "Verify key");

        KeysPageLeadText.Text = T(
            "查看本机密钥文件。私钥只应保留在你的 Windows 电脑上。",
            "View local key files. The private key must remain on your Windows PC.");
        CurrentKeysTitleText.Text = T("当前密钥", "Current keys");
        PrivateKeyLabelText.Text = T("私钥", "Private key");
        PublicKeyLabelText.Text = T("公钥", "Public key");
        OpenKeyFolderButton.Content = T("打开文件夹", "Open folder");
        CopyPublicKeyButton.Content = T("复制公钥", "Copy public key");
        AutomationProperties.SetName(OpenKeyFolderButton, T("打开密钥文件夹", "Open key folder"));
        AutomationProperties.SetName(CopyPublicKeyButton, T("复制公钥", "Copy public key"));

        AboutSubtitleText.Text = T("Windows 到 Debian 的 SSH 密钥部署工具", "An SSH key deployment tool for Windows to Debian");
        AboutDescriptionText.Text = T(
            "生成 Ed25519 密钥，安装 authorized_keys，安全修改 sshd 配置并验证密钥登录。",
            "Generates Ed25519 keys, installs authorized_keys, safely manages sshd configuration, and verifies key login.");
        AboutVersionText.Text = T("版本 1.0.0 · 开源软件", "Version 1.0.0 · Open source software");
        AboutCopyrightPrefixRun.Text = T("版权所有 (c) 2026 tuolaji996 · ", "Copyright (c) 2026 tuolaji996 · ");
        FooterCopyrightPrefixRun.Text = T("版权所有 (c) 2026 tuolaji996 · ", "Copyright (c) 2026 tuolaji996 · ");
        SetHyperlinkText(AboutProjectHyperlink, T("GitHub 项目", "GitHub Project"));
        SetHyperlinkText(FooterProjectHyperlink, T("GitHub 项目", "GitHub Project"));
        var projectLinkName = T("打开 GitHub 项目", "Open GitHub project");
        AboutProjectHyperlink.ToolTip = projectLinkName;
        FooterProjectHyperlink.ToolTip = projectLinkName;
        AutomationProperties.SetName(AboutProjectHyperlink, projectLinkName);
        AutomationProperties.SetName(FooterProjectHyperlink, projectLinkName);
        OpenGitHubButton.Content = T("打开 GitHub", "Open GitHub");
        AutomationProperties.SetName(OpenGitHubButton, projectLinkName);

        RefreshStatus();
        RefreshProgressSummary();
        RefreshFooterStatus();
        RefreshDeploymentLog();
    }

    private void UpdatePageTitle()
    {
        PageTitleText.Text = KeysNavigationButton.IsChecked == true
            ? T("密钥文件", "Key files")
            : AboutNavigationButton.IsChecked == true
                ? T("关于", "About")
                : T("一键部署", "Deploy");
    }

    private void SetFooterStatus(string chinese, string english)
    {
        _footerStatusText = new LocalizedText(chinese, english);
        RefreshFooterStatus();
    }

    private void RefreshFooterStatus() => FooterStatusText.Text = _footerStatusText.Value;

    private static void SetHyperlinkText(Hyperlink hyperlink, string text)
    {
        hyperlink.Inlines.Clear();
        hyperlink.Inlines.Add(text);
    }

    private string T(string chinese, string english) => UiLanguage.IsEnglish ? english : chinese;

    private static LocalizedText TranslateValidationMessage(string message)
    {
        var chinese = message
            .Replace("A deployment request is required.", "需要部署请求。", StringComparison.Ordinal)
            .Replace("Host is required.", "请输入服务器 IP 或域名。", StringComparison.Ordinal)
            .Replace("Host must be a valid DNS name or IP address without a URL scheme or port.", "服务器地址应为 IP 或域名，不要包含 ssh:// 或端口。", StringComparison.Ordinal)
            .Replace("Port must be a number between 1 and 65535.", "端口必须是 1 到 65535 之间的数字。", StringComparison.Ordinal)
            .Replace("Port must be between 1 and 65535.", "端口必须在 1 到 65535 之间。", StringComparison.Ordinal)
            .Replace("Username must be a valid Debian account name (lowercase letters, digits, underscore, or hyphen; maximum 32 characters).", "账户必须是有效的 Debian 用户名。", StringComparison.Ordinal)
            .Replace("Root login cannot be disabled when the deployment account is root.", "使用 root 账户部署时，必须开启 root 登录。", StringComparison.Ordinal)
            .Replace("A password is required for the initial SSH connection and sudo authentication.", "请输入当前 SSH 密码。", StringComparison.Ordinal)
            .Replace("Password cannot contain line breaks or null characters.", "密码不能包含换行或空字符。", StringComparison.Ordinal)
            .Replace("Password cannot exceed 1024 characters.", "密码长度不能超过 1024 个字符。", StringComparison.Ordinal)
            .Replace("Private-key path is required.", "请选择私钥保存位置。", StringComparison.Ordinal)
            .Replace("Private-key path is invalid.", "私钥保存路径无效。", StringComparison.Ordinal)
            .Replace("Private-key path must be absolute.", "密钥保存位置必须是完整路径。", StringComparison.Ordinal)
            .Replace("Select the private key, not the .pub file.", "请选择私钥文件，而不是 .pub 文件。", StringComparison.Ordinal)
            .Replace("Private-key file does not exist.", "私钥文件不存在。", StringComparison.Ordinal)
            .Replace("Matching .pub file does not exist.", "匹配的 .pub 文件不存在。", StringComparison.Ordinal)
            .Replace("Host:", "服务器：", StringComparison.Ordinal)
            .Replace("Port:", "端口：", StringComparison.Ordinal)
            .Replace("Username:", "账户：", StringComparison.Ordinal)
            .Replace("EnableRootLogin:", "root 登录：", StringComparison.Ordinal)
            .Replace("Password:", "密码：", StringComparison.Ordinal)
            .Replace("KeyPath:", "私钥文件：", StringComparison.Ordinal);
        return new LocalizedText(chinese, message);
    }

    private static LocalizedText TranslateExceptionMessage(string message)
    {
        var chinese = message
            .Replace("The private key and .pub file must exist as a pair. Choose a new filename; existing keys will not be overwritten.", "私钥和 .pub 文件必须成对存在。请选择新的文件名，工具不会覆盖已有密钥。", StringComparison.Ordinal)
            .Replace("Key folder does not exist yet.", "密钥文件夹尚不存在。", StringComparison.Ordinal);
        return new LocalizedText(chinese, message);
    }

    private static LocalizedText TranslateProgress(DeploymentProgress progress) => progress.Stage switch
    {
        DeploymentStage.Validating => new LocalizedText("正在检查部署设置", "Validating deployment settings"),
        DeploymentStage.SecuringPrivateKey => new LocalizedText("正在加固并校验私钥", "Securing and validating the private key"),
        DeploymentStage.Connecting => new LocalizedText("正在使用密码连接服务器", "Connecting with password authentication"),
        DeploymentStage.AwaitingHostKeyApproval => new LocalizedText("等待确认服务器主机指纹", "Waiting for server host-key approval"),
        DeploymentStage.CheckingPrivileges => new LocalizedText("正在检查 Debian、sshd 和 sudo 权限", "Checking Debian, sshd, and sudo access"),
        DeploymentStage.InstallingPublicKey => progress.Percent >= 39
            ? new LocalizedText("正在改配置前验证当前账户的密钥登录", "Verifying current-account key login before configuration changes")
            : new LocalizedText("正在安装公钥", "Installing the public key"),
        DeploymentStage.WritingSshdConfiguration => new LocalizedText("正在备份并写入 SSH 配置", "Backing up and writing SSH configuration"),
        DeploymentStage.ValidatingSshdConfiguration => new LocalizedText("正在验证 sshd 语法和生效值", "Validating sshd syntax and effective settings"),
        DeploymentStage.ReloadingSsh => new LocalizedText("正在平滑重载 SSH 服务", "Reloading the SSH service"),
        DeploymentStage.VerifyingEffectiveConfiguration => new LocalizedText("正在复核重载后的配置", "Verifying settings after reload"),
        DeploymentStage.VerifyingKeyLogin => new LocalizedText("正在使用新私钥回连验证", "Verifying key login with the new private key"),
        DeploymentStage.RollingBack => new LocalizedText("正在恢复服务器原配置", "Rolling back server changes"),
        DeploymentStage.Completed => new LocalizedText("部署和密钥登录验证完成", "Deployment and key-login verification complete"),
        _ => new LocalizedText(progress.Message, progress.Message)
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

    private readonly record struct LocalizedText(string Chinese, string English)
    {
        public string Value => UiLanguage.IsEnglish ? English : Chinese;
    }

    private sealed record DeploymentLogEntry(DateTime Timestamp, LocalizedText Message, bool IsError);
}
