namespace SshKeyDeployer;

public enum AppLanguage
{
    SimplifiedChinese,
    English
}

public static class UiLanguage
{
    private static AppLanguage _current = AppLanguage.SimplifiedChinese;

    public static AppLanguage Current
    {
        get => _current;
        set
        {
            if (_current == value)
            {
                return;
            }

            _current = value;
            Changed?.Invoke(null, EventArgs.Empty);
        }
    }

    public static bool IsEnglish => Current == AppLanguage.English;

    public static event EventHandler? Changed;

    public static void Toggle()
    {
        Current = IsEnglish ? AppLanguage.SimplifiedChinese : AppLanguage.English;
    }
}
