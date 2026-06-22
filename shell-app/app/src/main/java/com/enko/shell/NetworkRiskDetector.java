package com.enko.shell;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.ProxyInfo;
import android.os.Build;
import java.net.NetworkInterface;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

final class NetworkRiskDetector {

    /** Well-known packet-capture / MITM proxy app package names. */
    private static final String[] CAPTURE_PACKAGES = {
            /* Charles Proxy */
            "com.xk72.charles",
            /* HttpCanary */
            "com.guoshi.httpcanary",
            "com.guoshi.httpcanary.premium",
            /* Packet Capture */
            "app.greyshirts.sslcapture",
            /* Debug Proxy */
            "com.minhui.networkcapture.pro",
            "com.minhui.networkcapture",
            /* Fiddler Everywhere (companion) */
            "com.telerik.fiddler",
            /* NetCapture */
            "com.cy8018.tool.netcapture",
            /* tPacketCapture */
            "jp.co.taosoftware.android.packetcapture",
            /* HTTP Toolkit */
            "tech.httptoolkit.android.v1",
            /* MITM Proxy (Reqable) */
            "com.reqable.android",
            /* PCAPdroid */
            "com.emanuelef.remote_capture",
            "com.emanuelef.remote_capture.debug",
    };

    /** Network interface names commonly created by VPN-based capture tools. */
    private static final String[] VPN_INTERFACE_PREFIXES = {
            "tun", "ppp", "tap", "utun", "gpd", "ccmni",
    };

    private NetworkRiskDetector() {
    }

    /**
     * Run all network-related risk checks.
     *
     * @param context         application context
     * @param detectProxyVpn  master switch from config; if false, all checks are skipped
     * @return list of risk reason strings (empty = clean)
     */
    static List<String> detectNetworkRisk(Context context, boolean detectProxyVpn) {
        List<String> reasons = new ArrayList<>();
        if (!detectProxyVpn) {
            return reasons;
        }

        /* ---- 1. System-property proxies (http / https / socks) ---- */
        if (hasPropertyProxy("http.proxyHost", "http.proxyPort")) {
            reasons.add("http-proxy-detected");
        }
        if (hasPropertyProxy("https.proxyHost", "https.proxyPort")) {
            reasons.add("https-proxy-detected");
        }
        if (hasPropertyProxy("socksProxyHost", "socksProxyPort")) {
            reasons.add("socks-proxy-detected");
        }

        /* ---- 2. WiFi / system-level proxy (ConnectivityManager) ---- */
        if (hasSystemProxy(context)) {
            reasons.add("system-proxy-detected");
        }

        /* ---- 3. VPN transport ---- */
        if (isVpnTransportActive(context)) {
            reasons.add("vpn-detected");
        }

        /* ---- 4. VPN / tunnel network interfaces (tun0, ppp0, ...) ---- */
        if (hasVpnInterface()) {
            reasons.add("vpn-interface-detected");
        }

        /* ---- 5. User-installed CA certificates ---- */
        if (hasUserCaCertificates()) {
            reasons.add("user-ca-detected");
        }

        /* ---- 6. Known capture apps installed ---- */
        List<String> captureApps = detectCaptureApps(context);
        if (!captureApps.isEmpty()) {
            reasons.add("capture-app-detected:" + join(captureApps));
        }

        return reasons;
    }

    /* ================================================================
     * System-property proxy detection
     * ================================================================ */

    private static boolean hasPropertyProxy(String hostKey, String portKey) {
        String host = System.getProperty(hostKey);
        if (host != null && !host.trim().isEmpty()) {
            return true;
        }
        String port = System.getProperty(portKey);
        return port != null && !port.trim().isEmpty() && !"0".equals(port.trim());
    }

    /* ================================================================
     * System-level / WiFi proxy via ConnectivityManager.getDefaultProxy()
     * Catches Charles / Fiddler configured through WiFi settings.
     * ================================================================ */

    private static boolean hasSystemProxy(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ProxyInfo proxy = cm.getDefaultProxy();
                if (proxy != null) {
                    String host = proxy.getHost();
                    return host != null && !host.trim().isEmpty();
                }
            }
        } catch (Throwable ignored) {
            /* SecurityException on some ROMs. */
        }
        return false;
    }

    /* ================================================================
     * VPN transport via ConnectivityManager (API 23+)
     * ================================================================ */

    private static boolean isVpnTransportActive(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                    context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Network active = cm.getActiveNetwork();
                if (active == null) {
                    return false;
                }
                NetworkCapabilities caps = cm.getNetworkCapabilities(active);
                return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            }
            @SuppressWarnings("deprecation")
            NetworkInfo vpn = cm.getNetworkInfo(ConnectivityManager.TYPE_VPN);
            return vpn != null && vpn.isConnected();
        } catch (Throwable ignored) {
            return false;
        }
    }

    /* ================================================================
     * Network interface scan — detect tun/ppp/tap interfaces
     * VPN-based capture tools (HttpCanary, Packet Capture) create these.
     * ================================================================ */

    private static boolean hasVpnInterface() {
        try {
            List<NetworkInterface> interfaces =
                    Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface ni : interfaces) {
                if (!ni.isUp()) {
                    continue;
                }
                String name = ni.getName();
                if (name == null) {
                    continue;
                }
                String lower = name.toLowerCase(Locale.US);
                for (String prefix : VPN_INTERFACE_PREFIXES) {
                    if (lower.startsWith(prefix)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
            /* SocketException on some devices. */
        }
        return false;
    }

    /* ================================================================
     * User-installed CA certificates
     * ================================================================ */

    private static boolean hasUserCaCertificates() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
            keyStore.load(null);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias != null && alias.startsWith("user:")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }

    /* ================================================================
     * Known packet-capture / MITM app detection
     * ================================================================ */

    private static List<String> detectCaptureApps(Context context) {
        List<String> found = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        for (String pkg : CAPTURE_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                found.add(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
                /* Not installed — good. */
            } catch (Throwable ignored) {
                /* Unexpected — skip silently. */
            }
        }
        return found;
    }

    /* ================================================================
     * Utility
     * ================================================================ */

    private static String join(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append('+');
            sb.append(items.get(i));
        }
        return sb.toString();
    }
}
