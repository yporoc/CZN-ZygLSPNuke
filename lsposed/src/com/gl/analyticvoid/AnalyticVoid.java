package com.gl.analyticvoid;

import android.util.Log;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;

 



















public class AnalyticVoid implements IXposedHookLoadPackage {

    public static final String TAG = "ANAVOID";

    private static final String[] PKG_HINTS = {"chaoszero", "smilegate", "com.tencent.czn"};
    private static final String[] CLS_SINGULAR_CAND = {
            "kr.supercreative.ssr.SuperSingular",
            "kr.supercreative.ssr.SingularBridge",
            "kr.supercreative.stovesdk.SuperSingular",
            "com.smilegate.stovesdk.SuperSingular"
    };
    private static final String[] CLS_STOVE_CAND = {
            "kr.supercreative.stovesdk.SuperStove",
            "kr.supercreative.ssr.SuperStove",
            "com.smilegate.stovesdk.SuperStove"
    };
     
    private static final String[] HOOK_METHOD_PATTERNS = {"customevent", "singularcustomevent"};
     
    private static final String[] SECURITY_EVENT_MARKERS = {
            "stove_security", "security_gcs", "security_sui", "security_start",
            "gcs_start", "gcs_end", "sui_start", "sui_end", "rh_security", "anticheat"
    };

    private static final java.util.Set<String> sHooked = new java.util.HashSet<>();
    private static boolean sInstalled = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!matchPkg(lp.packageName)) return;
        if (sInstalled) return;
        sInstalled = true;
        log("ATTACH pid=" + android.os.Process.myPid() + " pkg=" + lp.packageName);
        ClassLoader cl = lp.classLoader;
        int n = 0;
        for (String cn : CLS_SINGULAR_CAND) n += hookClass(cn, cl);
        for (String cn : CLS_STOVE_CAND) n += hookClass(cn, cl);
        log("installed " + n + " security-event void hook(s)");
    }

    private int hookClass(String cn, ClassLoader cl) {
        Class<?> c = load(cn, cl);
        if (c == null) { log("class not found: " + cn); return 0; }
        int n = 0;
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        for (Class<?> k = c; k != null && k != Object.class; k = k.getSuperclass()) {
            Method[] ms;
            try { ms = k.getDeclaredMethods(); } catch (Throwable t) { continue; }
            for (Method m : ms) {
                String mn = m.getName();
                String low = mn.toLowerCase();
                boolean hit = false;
                for (String hm : HOOK_METHOD_PATTERNS) if (low.contains(hm)) { hit = true; break; }
                if (!hit) continue;
                Class<?> dc = m.getDeclaringClass();
                if (!appClass(dc.getName())) continue;
                String key = dc.getName() + "#" + mn;
                if (!seen.add(key)) continue;
                if (!sHooked.add(key)) continue;
                try {
                    XposedBridge.hookAllMethods(dc, mn, new SecurityEventVoid(mn));
                    log("hook " + key);
                    n++;
                } catch (Throwable t) {
                    log("E hook " + key + " " + t);
                }
            }
        }
        return n;
    }

     
    public static class SecurityEventVoid extends XC_MethodHook {
        private final String name;
        public SecurityEventVoid(String n) { this.name = n; }
        @Override
        protected void beforeHookedMethod(MethodHookParam p) {
            try {
                if (p.args == null || p.args.length == 0 || p.args[0] == null) return;
                String ev = String.valueOf(p.args[0]).toLowerCase();
                for (String marker : SECURITY_EVENT_MARKERS) {
                    if (ev.contains(marker)) {
                        p.setResult(null);    
                        log("VOID " + name + "(" + p.args[0] + ")");
                        return;
                    }
                }
                 
            } catch (Throwable t) {
                log("E SecurityEventVoid " + t);
            }
        }
    }

    static boolean matchPkg(String pkg) {
        if (pkg == null) return false;
        String p = pkg.toLowerCase();
        for (String h : PKG_HINTS) if (p.contains(h)) return true;
        return false;
    }

    static boolean appClass(String n) {
        return n.startsWith("kr.supercreative.") || n.startsWith("com.smilegate.")
                || n.startsWith("com.stove.") || n.startsWith("com.tencent.czn");
    }

    static Class<?> load(String name, ClassLoader cl) {
        try { return Class.forName(name, false, cl); } catch (Throwable t) { return null; }
    }

    static void log(String s) { Log.i(TAG, s); }
}
