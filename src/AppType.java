package dpi;
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;
    public String toDisplayString() {
        switch (this) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;

        String s = sni.toLowerCase();

        // YouTube (check before Google since ytimg etc. are YouTube-specific)
        if (s.contains("youtube") || s.contains("ytimg") ||
            s.contains("youtu.be") || s.contains("yt3.ggpht")) {
            return YOUTUBE;
        }

        // Google
        if (s.contains("google") || s.contains("gstatic") ||
            s.contains("googleapis") || s.contains("ggpht") ||
            s.contains("gvt1")) {
            return GOOGLE;
        }

        // Instagram (check before Facebook since it's separate)
        if (s.contains("instagram") || s.contains("cdninstagram")) {
            return INSTAGRAM;
        }

        // WhatsApp (check before Facebook)
        if (s.contains("whatsapp") || s.contains("wa.me")) {
            return WHATSAPP;
        }

        // Facebook/Meta
        if (s.contains("facebook") || s.contains("fbcdn") ||
            s.contains("fb.com") || s.contains("fbsbx") ||
            s.contains("meta.com")) {
            return FACEBOOK;
        }

        // Twitter/X — use full domain patterns only to avoid false positives
        if (s.equals("twitter.com") || s.endsWith(".twitter.com") ||
            s.contains("twimg") ||
            s.equals("x.com") || s.endsWith(".x.com") ||
            s.equals("t.co")) {
            return TWITTER;
        }

        // Netflix — explicit check before any generic substring
        if (s.contains("netflix") || s.contains("nflxvideo") ||
            s.contains("nflximg")) {
            return NETFLIX;
        }

        // Microsoft — explicit check
        if (s.contains("microsoft") || s.contains("msn.com") ||
            s.contains("office") || s.contains("azure") ||
            s.contains("live.com") || s.contains("outlook") ||
            s.contains("bing")) {
            return MICROSOFT;
        }

        // Amazon
        if (s.contains("amazon") || s.contains("amazonaws") ||
            s.contains("cloudfront") || s.contains("aws")) {
            return AMAZON;
        }

        // Apple
        if (s.contains("apple") || s.contains("icloud") ||
            s.contains("mzstatic") || s.contains("itunes")) {
            return APPLE;
        }

        // Telegram
        if (s.contains("telegram") || s.equals("t.me") || s.endsWith(".t.me")) {
            return TELEGRAM;
        }

        // TikTok
        if (s.contains("tiktok") || s.contains("tiktokcdn") ||
            s.contains("musical.ly") || s.contains("bytedance")) {
            return TIKTOK;
        }

        // Spotify
        if (s.contains("spotify") || s.contains("scdn.co")) {
            return SPOTIFY;
        }

        // Zoom
        if (s.contains("zoom")) {
            return ZOOM;
        }

        // Discord
        if (s.contains("discord") || s.contains("discordapp")) {
            return DISCORD;
        }

        // GitHub
        if (s.contains("github") || s.contains("githubusercontent")) {
            return GITHUB;
        }

        // Cloudflare
        if (s.contains("cloudflare") || s.contains("cf-")) {
            return CLOUDFLARE;
        }

        // SNI present but not recognized — still HTTPS
        return HTTPS;
    }
}
