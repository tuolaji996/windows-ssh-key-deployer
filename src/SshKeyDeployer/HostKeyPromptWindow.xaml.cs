using System.Windows;

namespace SshKeyDeployer;

public partial class HostKeyPromptWindow : Window
{
    public HostKeyPromptWindow(string host, int port, string algorithm, string fingerprint)
    {
        InitializeComponent();
        HostValueText.Text = $"{host}:{port}";
        AlgorithmValueText.Text = algorithm;
        FingerprintValueTextBox.Text = fingerprint;
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
