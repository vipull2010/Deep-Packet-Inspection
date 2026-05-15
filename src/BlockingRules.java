package dpi;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
public class BlockingRules {

    private final Set<Integer>  blockedIps     = new HashSet<>();
    private final Set<AppType>  blockedApps    = new HashSet<>();
    private final List<String>  blockedDomains = new ArrayList<>();
    public void blockIp(String ip) {
        int addr = FiveTuple.parseIp(ip);
        blockedIps.add(addr);
        System.out.println("[Rules] Blocked IP: " + ip);
    }
    public void blockApp(String appName) {
        for (AppType type : AppType.values()) {
            if (type.toDisplayString().equalsIgnoreCase(appName)) {
                blockedApps.add(type);
                System.out.println("[Rules] Blocked app: " + appName);
                return;
            }
        }
        System.err.println("[Rules] Unknown app: " + appName);
    }
    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domain);
    }
    public boolean isBlocked(int srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedApps.contains(app))  return true;
        String lowerSni = sni.toLowerCase();
        for (String domain : blockedDomains) {
            if (lowerSni.contains(domain)) return true;
        }
        return false;
    }
}
