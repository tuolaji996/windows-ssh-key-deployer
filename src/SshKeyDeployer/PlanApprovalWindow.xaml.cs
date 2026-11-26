using System.Windows;
using System.Windows.Controls;
using SshKeyDeployer.Core;

namespace SshKeyDeployer;

public partial class PlanApprovalWindow : Window
{
    private readonly DeploymentPlan _plan;

    public PlanApprovalWindow(DeploymentPlan plan)
    {
        _plan = plan;
        InitializeComponent();
        ApplyLanguage();
        UiLanguage.Changed += UiLanguage_Changed;
        Closed += (_, _) => UiLanguage.Changed -= UiLanguage_Changed;
        Loaded += (_, _) => CancelButton.Focus();
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
        Title = english ? "Confirm Deployment Plan" : "确认部署计划";
        PromptTitleText.Text = english
            ? "Review what will change on this server"
            : "请确认将在服务器上执行的变更";
        PromptLeadText.Text = english
            ? "Nothing has been changed yet. Continue only if this matches the server you expect."
            : "目前尚未做任何修改。确认与预期的服务器一致后再继续。";
        ServerSectionText.Text = english ? "Detected server" : "检测到的服务器";
        ActionsSectionText.Text = english ? "Planned actions" : "计划执行的操作";

        ServerDetailsGrid.Children.Clear();
        ServerDetailsGrid.RowDefinitions.Clear();
        var rows = DeploymentPresentation.DescribeServer(_plan.Server, english);
        for (var index = 0; index < rows.Count; index++)
        {
            ServerDetailsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var label = new TextBlock
            {
                Text = rows[index].Label,
                Style = (Style)FindResource("FieldLabelStyle"),
                Margin = new Thickness(0, index == 0 ? 0 : 6, 12, 0)
            };
            var value = new TextBlock
            {
                Text = rows[index].Value,
                FontWeight = FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, index == 0 ? 0 : 6, 0, 0)
            };
            Grid.SetRow(label, index);
            Grid.SetRow(value, index);
            Grid.SetColumn(value, 1);
            ServerDetailsGrid.Children.Add(label);
            ServerDetailsGrid.Children.Add(value);
        }

        ActionsPanel.Children.Clear();
        var number = 1;
        foreach (var action in _plan.Actions)
        {
            var text = $"{number++}. {DeploymentPresentation.DescribeAction(action, english)}";
            var row = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
            row.Children.Add(new TextBlock
            {
                Text = text,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 13
            });
            if (action.IsPersistent)
            {
                var badge = new Border
                {
                    Margin = new Thickness(18, 4, 0, 0),
                    Padding = new Thickness(6, 2, 6, 2),
                    CornerRadius = new CornerRadius(4),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Child = new TextBlock
                    {
                        Text = english ? "Persistent: kept even if the deployment rolls back" : "持久变更：即使回滚也会保留",
                        FontSize = 11,
                        FontWeight = FontWeights.SemiBold
                    }
                };
                badge.SetResourceReference(Border.BackgroundProperty, "WarningSurfaceBrush");
                ((TextBlock)badge.Child).SetResourceReference(TextBlock.ForegroundProperty, "WarningBrush");
                row.Children.Add(badge);
            }

            ActionsPanel.Children.Add(row);
        }

        NoteText.Text = english
            ? "Every step is verified; if any check fails, the server is rolled back automatically (except items marked persistent). Keep an existing SSH session or the server console open."
            : "每一步都会验证；任一检查失败时会自动回滚（标记为持久变更的项目除外）。请保持一个现有 SSH 会话或服务器控制台处于打开状态。";
        CancelButton.Content = english ? "Cancel" : "取消";
        ApproveButton.Content = english ? "Approve and deploy" : "批准并部署";
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
