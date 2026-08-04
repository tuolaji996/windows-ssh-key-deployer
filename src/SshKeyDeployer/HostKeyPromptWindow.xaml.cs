using System.Windows;
using System.Windows.Automation;

namespace SshKeyDeployer;

public partial class HostKeyPromptWindow : Window
{
    public HostKeyPromptWindow(string host, int port, string algorithm, string fingerprint)
    {
        InitializeComponent();
        HostValueText.Text = $"{host}:{port}";
        AlgorithmValueText.Text = algorithm;
        FingerprintValueTextBox.Text = fingerprint;
        ApplyLanguage();
        UiLanguage.Changed += UiLanguage_Changed;
        Closed += (_, _) => UiLanguage.Changed -= UiLanguage_Changed;
    }

    private void UiLanguage_Changed(object? sender, EventArgs e)
    {
        if (Dispatcher.CheckAccess())
        {
            ApplyLanguage();
            return;
        }

        Dispatcher.Invoke(ApplyLanguage);
    }

    private void ApplyLanguage()
    {
        var english = UiLanguage.IsEnglish;

        Title = english ? "Confirm Server Identity" : "确认服务器身份";
        PromptTitleText.Text = english
            ? "Confirm this server's host key fingerprint"
            : "确认这台服务器的主机指纹";
        PromptLeadText.Text = english
            ? "Before the first connection, compare this fingerprint with the one shown in your server console."
            : "首次连接前，请与服务器控制台中显示的指纹核对。";
        ServerLabelText.Text = english ? "Server" : "服务器";
        AlgorithmLabelText.Text = english ? "Algorithm" : "算法";

        var copyFingerprint = english ? "Copy fingerprint" : "复制指纹";
        CopyFingerprintButton.ToolTip = copyFingerprint;
        AutomationProperties.SetName(CopyFingerprintButton, copyFingerprint);

        MismatchWarningText.Text = english
            ? "If this fingerprint does not match your server console, select Cancel."
            : "如果指纹与服务器控制台不一致，请选择取消。";
        CancelButton.Content = english ? "Cancel" : "取消";
        ApproveButton.Content = english ? "Trust and continue" : "信任并继续";
    }

    private void CopyFingerprintButton_Click(object sender, RoutedEventArgs e)
    {
        Clipboard.SetText(FingerprintValueTextBox.Text);
    }

    private void ApproveButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
