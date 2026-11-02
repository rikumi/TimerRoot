package com.kpgc.timerroot;

import android.os.Build;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runs inside the process that Shizuku starts as the shell user (uid 2000,
 * u:r:shell:s0), which is what the exploit needs for tracefs.
 */
public class UserService extends IUserService.Stub {

    private static final String TAG = "TimerRootService";

    private static final String BIN = "/data/local/tmp/timer";
    private static final String LOG = "/data/local/tmp/timer.log";
    private static final String CONF_DIR = "/data/local/tmp/timer-conf";
    /** Sub-directory of CONF_DIR holding profiles for "dirty" kernel builds. */
    private static final String DIRTY_CONF_SUBDIR = "dirty";
    private static final int MAX_OUTPUT = 20000;

    /**
     * Log markers that prove the exploit cannot succeed.  It exits (or the
     * stage script ends) right after printing one of these, so waiting for a
     * success marker such as uid=0(root) is pointless.
     */
    private static final String[] FATAL_MARKERS = {
        "base calibration failed",
        "page event ids not found",
        "cred leak failed",
        "ksud missing",
        "KSU_MISSING",
    };

    private static boolean hasFatalMarker(String text) {
        for (String marker : FATAL_MARKERS) {
            if (text.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private volatile boolean readingRootLog;
    private final StringBuilder rootOutput = new StringBuilder();
    private Process rootProcess;
    private BufferedWriter rootInput;
    private final BlockingQueue<String> rootLines = new LinkedBlockingQueue<>();

    public UserService() {
    }

    public UserService(android.content.Context context) {
    }

    @Override
    public void destroy() {
        closeRootInternal();
        System.exit(0);
    }

    @Override
    public void exit() {
        destroy();
    }

    @Override
    public String install(String apk) {
        try {
            int confCount = 0;
            try (ZipFile zf = new ZipFile(apk)) {
                ZipEntry entry = zf.getEntry("assets/timer");
                if (entry == null) {
                    return "assets/timer not found in " + apk;
                }
                String tmp = BIN + ".new";
                try (InputStream in = zf.getInputStream(entry);
                     FileOutputStream out = new FileOutputStream(tmp)) {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                    }
                }
                // The old binary may still be mapped by a parked process; rename
                // over it instead of writing in place (ETXTBSY).
                Process move = Runtime.getRuntime().exec(new String[]{"/system/bin/sh",
                        "-c", "chmod 755 " + tmp + " && mv -f " + tmp + " " + BIN});
                if (move.waitFor() != 0) {
                    return "install failed: could not publish timer binary";
                }

                // Extract the per-kernel conf files next to the binary. Wipe the
                // directory first: a stale flat conf would otherwise keep matching
                // by release alone and bypass the dirty/ identity checks.
                File confDir = new File(CONF_DIR);
                deleteRecursively(confDir);
                confDir.mkdirs();
                java.util.Enumeration<? extends ZipEntry> entries = zf.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry e = entries.nextElement();
                    if (e.isDirectory() || !e.getName().startsWith("assets/conf/")) {
                        continue;
                    }
                    String name = e.getName().substring("assets/conf/".length());
                    if (!name.endsWith(".conf")) {
                        continue;
                    }
                    File dst = new File(confDir, name);
                    File parent = dst.getParentFile();
                    if (parent != null) {
                        parent.mkdirs();
                    }
                    try (InputStream in = zf.getInputStream(e);
                         FileOutputStream out = new FileOutputStream(dst)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = in.read(buf)) > 0) {
                            out.write(buf, 0, n);
                        }
                    }
                    confCount++;
                }
            }
            return "installed " + new File(BIN).length() + " bytes, " + confCount
                    + " confs (uid=" + android.system.Os.getuid() + ")";
        } catch (Throwable t) {
            return "install failed: " + t;
        }
    }

    /**
     * Returns "--conf &lt;path&gt;" for the conf that applies to this device, or
     * "" when none matches.
     *
     * Two tiers:
     *  - confs directly under CONF_DIR match on {@code release == uname -r}
     *    alone; their release strings are unique enough (stock GKI builds).
     *  - confs under CONF_DIR/dirty/ match on {@code release} <em>and</em> on
     *    the identity fields ({@code device_model}, {@code android_release},
     *    optional {@code sdk_int}) checked against the device. A dirty build's
     *    release string ("-maybe-dirty") is not unique to one vendor build, so
     *    the extra check guards against applying another device's constants.
     *
     * Identity fields use AOSP-standard properties only (Build.MODEL /
     * Build.VERSION.RELEASE / Build.VERSION.SDK_INT), never vendor build
     * strings such as a Flyme version.
     */
    private String confArg() {
        String release = execOut("uname -r");
        File dir = new File(CONF_DIR);
        for (File f : listConfFiles(dir)) {
            if (release.equals(readRelease(f))) {
                Log.i(TAG, "using conf " + f);
                return "--conf " + f.getAbsolutePath();
            }
        }
        File dirtyDir = new File(dir, DIRTY_CONF_SUBDIR);
        for (File f : listConfFiles(dirtyDir)) {
            if (!release.equals(readRelease(f))) {
                continue;
            }
            if (!deviceIdentityMatches(f)) {
                Log.w(TAG, "skipping dirty conf " + f + ": device identity mismatch");
                continue;
            }
            Log.i(TAG, "using dirty conf " + f);
            return "--conf " + f.getAbsolutePath();
        }
        Log.w(TAG, "no conf matched uname -r = " + release);
        return "";
    }

    /** Regular .conf files directly inside {@code dir} (no recursion). */
    private static File[] listConfFiles(File dir) {
        File[] files = dir.listFiles((d, name) -> name.endsWith(".conf"));
        if (files == null) {
            return new File[0];
        }
        ArrayList<File> out = new ArrayList<>();
        for (File f : files) {
            if (f.isFile()) {
                out.add(f);
            }
        }
        return out.toArray(new File[0]);
    }

    /**
     * Identity gate for dirty confs. {@code device_model} and
     * {@code android_release} are required; {@code sdk_int} is compared when
     * present. A conf that omits a required field is rejected rather than
     * trusted, so an incomplete profile can never be selected.
     */
    private static boolean deviceIdentityMatches(File conf) {
        Map<String, String> fields = readConfFields(conf);
        String wantModel = fields.get("device_model");
        String wantRelease = fields.get("android_release");
        String wantSdk = fields.get("sdk_int");
        if (TextUtils.isEmpty(wantModel) || TextUtils.isEmpty(wantRelease)) {
            return false;
        }
        if (!wantModel.equals(Build.MODEL)) {
            return false;
        }
        if (!wantRelease.equals(Build.VERSION.RELEASE)) {
            return false;
        }
        return TextUtils.isEmpty(wantSdk)
                || wantSdk.equals(String.valueOf(Build.VERSION.SDK_INT));
    }

    /**
     * Minimal conf reader: {@code key = value} lines with {@code #} and
     * {@code //} comments stripped and surrounding quotes removed.
     */
    private static Map<String, String> readConfFields(File f) {
        Map<String, String> out = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(f)))) {
            String line;
            while ((line = r.readLine()) != null) {
                int hash = line.indexOf('#');
                if (hash >= 0) {
                    line = line.substring(0, hash);
                }
                int dsl = line.indexOf("//");
                if (dsl >= 0) {
                    line = line.substring(0, dsl);
                }
                int eq = line.indexOf('=');
                if (eq < 0) {
                    continue;
                }
                String key = line.substring(0, eq).trim();
                String val = line.substring(eq + 1).trim();
                if (val.length() >= 2 && val.startsWith("\"") && val.endsWith("\"")) {
                    val = val.substring(1, val.length() - 1);
                }
                if (!key.isEmpty() && !val.isEmpty()) {
                    out.put(key, val);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private String readRelease(File f) {
        return readConfFields(f).getOrDefault("release", "");
    }

    private static void deleteRecursively(File f) {
        File[] kids = f.listFiles();
        if (kids != null) {
            for (File k : kids) {
                deleteRecursively(k);
            }
        }
        f.delete();
    }

    @Override
    public String run(String args) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c", BIN + " " + confArg() + " " + args + " 2>&1");
            pb.directory(new File("/data/local/tmp"));
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String text = readAll(p.getInputStream());
            if (!p.waitFor(90, TimeUnit.SECONDS)) {
                return text + "\n[timeout] still running after 90s - do not kill it,"
                        + " reboot to clean up";
            }
            return text;
        } catch (Throwable t) {
            return "run failed: " + t;
        }
    }

    @Override
    public String runDetached(String args) {
        try {
            readingRootLog = false;
            try (FileOutputStream ignored = new FileOutputStream(LOG)) { }
            String cmd = "cd /data/local/tmp && setsid " + BIN + " " + confArg()
                    + " " + args + " >" + LOG + " 2>&1 </dev/null &";
            Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            Thread.sleep(2000);
            return readLog();
        } catch (Throwable t) {
            return "start failed: " + t;
        }
    }

    @Override
    public String readLog() {
        if (readingRootLog) {
            synchronized (rootOutput) { return rootOutput.toString(); }
        }
        try (FileInputStream in = new FileInputStream(LOG)) {
            return readAll(in);
        } catch (Throwable t) {
            return "";
        }
    }

    @Override
    public String openRoot() {
        if (rootProcess != null && rootProcess.isAlive()) {
            return "root shell already open\n" + execRoot("id");
        }
        try {
            synchronized (rootOutput) { rootOutput.setLength(0); }
            readingRootLog = true;
            ProcessBuilder pb = new ProcessBuilder(
                    "/system/bin/sh", "-c", BIN + " " + confArg() + " shell");
            pb.directory(new File("/data/local/tmp"));
            pb.redirectErrorStream(true);
            rootProcess = pb.start();
            rootInput = new BufferedWriter(
                    new OutputStreamWriter(rootProcess.getOutputStream()));
            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(rootProcess.getInputStream()));
            rootLines.clear();
            // Ask the interactive shell for proof of its identity.
            rootInput.write("id\n");
            rootInput.flush();
            Thread pump = new Thread(() -> {
                try {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (rootOutput) { rootOutput.append(line).append('\n'); }
                        rootLines.offer(line);
                    }
                } catch (IOException ignored) {
                }
            });
            pump.setDaemon(true);
            pump.start();
            Thread.sleep(6000);
            String out = new String();
            long deadline = System.currentTimeMillis() + 20000;
            while (System.currentTimeMillis() < deadline) {
                String line = rootLines.poll(100, TimeUnit.MILLISECONDS);
                if (line == null) {
                    continue;
                }
                out += line + "\n";
                if (line.contains("uid=0(root)") || hasFatalMarker(line)) {
                    break;
                }
            }
            return "root shell started\n" + out.trim();
        } catch (Throwable t) {
            return "openRoot failed: " + t;
        }
    }

    @Override
    public String execRoot(String cmd) {
        if (rootProcess == null || !rootProcess.isAlive()) {
            return "root shell not open";
        }
        try {
            rootInput.write(cmd + " 2>&1\necho __END__\n");
            rootInput.flush();
            StringBuilder sb = new StringBuilder();
            long deadline = System.currentTimeMillis() + 30000;
            while (System.currentTimeMillis() < deadline) {
                String line = rootLines.poll(200, TimeUnit.MILLISECONDS);
                if (line == null) {
                    continue;
                }
                if (line.equals("__END__")) {
                    break;
                }
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            return "execRoot failed: " + t;
        }
    }

    @Override
    public String closeRoot() {
        closeRootInternal();
        return "root shell closed";
    }

    /** SELinux / Seccomp / ksud, as shown on the home card. */
    @Override
    public String info() {
        String selinux = execOut("getenforce");
        String seccomp = execOut("grep -m1 Seccomp /proc/self/status | awk '{print $2}'");
        String ksud = "not loaded";
        Matcher m = Pattern.compile("version=(ksud[^\\n]*)").matcher(readLog());
        if (m.find()) {
            ksud = m.group(1).trim();
        } else if (selinux.contains("Permissive")) {
            ksud = "missing";
        }
        String ksu = execOut("/system/bin/su -c id").contains("u:r:ksu:s0")
                ? "active" : "not loaded";
        return "selinux=" + selinux + "\nseccomp=" + seccomp + "\nksud=" + ksud
                + "\nksu=" + ksu + "\n";
    }

    @Override
    public String rebootDevice() {
        int rc = execCode("/system/bin/svc power reboot");
        if (rc != 0) {
            rc = execCode("/system/bin/su -c reboot");
        }
        if (rc != 0) {
            rc = execCode("/system/bin/reboot");
        }
        return rc == 0 ? "rebooting" : "reboot failed (rc=" + rc + ")";
    }

    private int execCode(String cmd) {
        try {
            Process p = new ProcessBuilder("/system/bin/sh", "-c", cmd)
                    .redirectErrorStream(true).start();
            return p.waitFor();
        } catch (Throwable t) {
            return -1;
        }
    }

    private String execOut(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String text = readAll(p.getInputStream()).trim();
            p.waitFor();
            return text.isEmpty() ? "unknown" : text;
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private void closeRootInternal() {
        try {
            if (rootInput != null) {
                rootInput.write("exit\n");
                rootInput.flush();
            }
        } catch (IOException ignored) {
        }
        if (rootProcess != null) {
            rootProcess.destroy();
            rootProcess = null;
        }
        rootInput = null;
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        int total = 0;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
            total += n;
            if (total > MAX_OUTPUT) {
                break;
            }
        }
        return bos.toString("UTF-8");
    }
}
