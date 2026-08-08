using Avalonia.Controls;
using Avalonia.Interactivity;

namespace SshKeyDeployer.Mac;

public partial class HostKeyPromptWindow : Window
{
    public HostKeyPromptWindow()
    {
        InitializeComponent();
    }

    public HostKeyPromptWindow(
        bool english,
        string host,
        int port,
        string algorithm,
        string fingerprint)
        : this()
    {
        var t = english
            ? new Func<string, string, string>((_, value) => value)
            : new Func<string, string, string>((value, _) => value);

        Title = t("确认服务器身份", "Confirm Server Identity");
        TitleText.Text = t("确认这台服务器的主机指纹", "Confirm this server's host-key fingerprint");
        LeadText.Text = t(
            "首次连接前，请与服务器控制台中显示的指纹核对。",
            "Before the first connection, compare this fingerprint with the one shown in your server console.");
        ServerLabelText.Text = t("服务器", "Server");
        AlgorithmLabelText.Text = t("算法", "Algorithm");
        ServerValueText.Text = $"{host}:{port}";
        AlgorithmValueText.Text = algorithm;
        FingerprintTextBox.Text = fingerprint;
        WarningText.Text = t(
            "如果指纹与服务器控制台不一致，请取消。",
            "If this fingerprint does not match your server console, select Cancel.");
        CancelButton.Content = t("取消", "Cancel");
        ApproveButton.Content = t("信任并继续", "Trust and continue");
    }

    private void ApproveButton_Click(object? sender, RoutedEventArgs e)
    {
        Close(true);
    }

    private void CancelButton_Click(object? sender, RoutedEventArgs e)
    {
        Close(false);
    }

}
