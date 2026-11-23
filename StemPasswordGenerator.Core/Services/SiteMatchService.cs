using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class SiteMatchService
{
    public static string Host(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return string.Empty;
        }

        var trimmed = url.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            return NormalizeHost(uri.Host);
        }

        if (Uri.TryCreate("https://" + trimmed.TrimStart('/'), UriKind.Absolute, out uri))
        {
            return NormalizeHost(uri.Host);
        }

        return NormalizeHost(trimmed);
    }

    public static string DisplayName(string? url)
    {
        var host = Host(url);
        if (string.IsNullOrEmpty(host))
        {
            return "this site";
        }

        return host.StartsWith("www.", StringComparison.Ordinal) ? host[4..] : host;
    }

    public static IReadOnlyList<VaultItem> Match(IReadOnlyList<VaultItem> items, string? url)
    {
        if (items.Count == 0)
        {
            return [];
        }

        var host = Host(url);
        if (string.IsNullOrEmpty(host))
        {
            return [];
        }

        return items
            .Select(item => (item, score: IsLogin(item) ? Score(item, host) : 0))
            .Where(static pair => pair.score > 0)
            .OrderByDescending(static pair => pair.score)
            .ThenBy(static pair => pair.item.Title, StringComparer.OrdinalIgnoreCase)
            .Select(static pair => pair.item)
            .ToList();
    }

    public static VaultItem? BestMatch(IReadOnlyList<VaultItem> items, string? url) => Match(items, url).FirstOrDefault();

    public static IReadOnlyList<VaultItem> MatchForVaultInsight(IReadOnlyList<VaultItem> items, string? url)
    {
        var matches = Match(items, url);
        if (matches.Count > 0)
        {
            return matches;
        }

        var host = Host(url);
        var dot = host.IndexOf('.');
        if (dot < 4)
        {
            return [];
        }

        var label = host[..dot];
        return items
            .Where(item => IsLogin(item)
                && string.IsNullOrEmpty(Host(item.Url))
                && item.Title.Equals(label, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public static VaultItem? BestMatchForHint(IReadOnlyList<VaultItem> items, string? hint)
    {
        if (string.IsNullOrWhiteSpace(hint) || items.Count == 0)
        {
            return null;
        }

        VaultItem? best = null;
        var bestScore = 0;
        foreach (var item in items)
        {
            if (!IsLogin(item))
            {
                continue;
            }

            var score = HintScore(item, hint);
            if (score > bestScore)
            {
                bestScore = score;
                best = item;
            }
        }

        return bestScore > 0 ? best : null;
    }

    public static bool HostsMatch(string left, string right)
    {
        var a = Host(left);
        var b = Host(right);
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
        {
            return false;
        }

        return a == b || IsSubdomainOf(a, b) || IsSubdomainOf(b, a);
    }

    private static bool IsLogin(VaultItem item) => item.Kind is VaultItemKind.Login or VaultItemKind.Alias or "";

    private static int Score(VaultItem item, string host)
    {
        var itemHost = Host(item.Url);
        if (string.IsNullOrEmpty(itemHost) || !itemHost.Contains('.', StringComparison.Ordinal))
        {
            return 0;
        }

        if (itemHost == host)
        {
            return 10;
        }

        if (IsSubdomainOf(host, itemHost) || IsSubdomainOf(itemHost, host))
        {
            return 8;
        }

        return 0;
    }

    private static bool IsSubdomainOf(string host, string parent)
    {
        return parent.Contains('.', StringComparison.Ordinal)
            && host.Length > parent.Length + 1
            && host.EndsWith('.' + parent, StringComparison.Ordinal);
    }

    private static int HintScore(VaultItem item, string hint)
    {
        var hostScore = Score(item, Host(hint));
        if (hostScore > 0)
        {
            return hostScore + 2;
        }

        var score = 0;
        if (item.Title.Trim().Length >= 4 && Contains(hint, item.Title))
        {
            score += 5;
        }

        if (Contains(hint, item.HostLabel) || Contains(item.HostLabel, hint))
        {
            score += 4;
        }

        if (Contains(hint, item.Url))
        {
            score += 3;
        }

        if (Contains(hint, item.Username))
        {
            score += 1;
        }

        return score;
    }

    private static bool Contains(string haystack, string needle)
    {
        return !string.IsNullOrWhiteSpace(needle)
            && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeHost(string host)
    {
        host = host.Trim().Trim('.').ToLowerInvariant();
        if (host.StartsWith("www.", StringComparison.Ordinal))
        {
            host = host[4..];
        }

        return host;
    }
}
