using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using SshKeyDeployer.Core;

namespace SshKeyDeployer.Mac;

public partial class PlanApprovalWindow : Window
{
    public PlanApprovalWindow()
    {
        InitializeComponent();
    }

    public PlanApprovalWindow(bool english, DeploymentPlan plan)
        : this()
    {
        string T(string chinese, string englishText) => english ? englishText : chinese;

        Title = T("确认部署计划", "Confirm Deployment Plan");
        TitleText.Text = T("请确认将在服务器上执行的变更", "Review what will change on this server");
        LeadText.Text = T(
            "目前尚未做任何修改。确认与预期的服务器一致后再继续。",
            "Nothing has been changed yet. Continue only if this matches the server you expect.");
        ServerSectionText.Text = T("检测到的服务器", "Detected server");
        ActionsSectionText.Text = T("计划执行的操作", "Planned actions");

        var rows = DeploymentPresentation.DescribeServer(plan.Server, english);
        for (var index = 0; index < rows.Count; index++)
        {
            ServerDetailsGrid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var label = new TextBlock { Text = rows[index].Label, Opacity = 0.72 };
            var value = new TextBlock
            {
                Text = rows[index].Value,
                FontWeight = FontWeight.SemiBold,
                TextWrapping = TextWrapping.Wrap
            };
            Grid.SetRow(label, index);
            Grid.SetRow(value, index);
            Grid.SetColumn(value, 1);
            ServerDetailsGrid.Children.Add(label);
            ServerDetailsGrid.Children.Add(value);
        }

        var number = 1;
        foreach (var action in plan.Actions)
        {
            var row = new StackPanel { Spacing = 4 };
            row.Children.Add(new TextBlock
            {
                Text = $"{number++}. {DeploymentPresentation.DescribeAction(action, english)}",
                TextWrapping = TextWrapping.Wrap
            });
            if (action.IsPersistent)
            {
                row.Children.Add(new Border
                {
                    Margin = new Avalonia.Thickness(18, 0, 0, 0),
                    Padding = new Avalonia.Thickness(6, 2),
                    CornerRadius = new Avalonia.CornerRadius(4),
                    Background = new SolidColorBrush(Color.FromArgb(0x33, 0xE0, 0xA0, 0x00)),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Child = new TextBlock
                    {
                        Text = T("持久变更：即使回滚也会保留", "Persistent: kept even if the deployment rolls back"),
                        FontSize = 11,
                        FontWeight = FontWeight.SemiBold
                    }
                });
            }

            ActionsPanel.Children.Add(row);
        }

        NoteText.Text = T(
            "每一步都会验证；任一检查失败时会自动回滚（标记为持久变更的项目除外）。请保持一个现有 SSH 会话或服务器控制台处于打开状态。",
            "Every step is verified; if any check fails, the server is rolled back automatically (except items marked persistent). Keep an existing SSH session or the server console open.");
        CancelButton.Content = T("取消", "Cancel");
        ApproveButton.Content = T("批准并部署", "Approve and deploy");
        Opened += (_, _) => CancelButton.Focus();
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
