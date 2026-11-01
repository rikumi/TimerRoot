package com.kpgc.timerroot;

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

    private static final String BIN = "/data/local/tmp/timer";
    private static final String LOG = "/data/local/tmp/timer.log";
    private static final String CONF_DIR = "/data/local/tmp/timer-conf";
    private static final int MAX_OUTPUT = 20000;

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

                // Extract the per-kernel conf files next to the binary.
                File confDir = new File(CONF_DIR);
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

    /** Returns "--conf <path>" for the conf whose `release` matches uname -r,
     *  or "" when none matches. */
    private String confArg() {
        String release = execOut("uname -r");
        File dir = new File(CONF_DIR);
        File[] files = dir.listFiles();
        if (files == null) {
            return "";
        }
        for (File f : files) {
            if (!f.getName().endsWith(".conf")) {
                continue;
            }
            if (release.equals(readRelease(f))) {
                return "--conf " + f.getAbsolutePath();
            }
        }
        return "";
    }

    private String readRelease(File f) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new FileInputStream(f)))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (!line.startsWith("release")) {
                    continue;
                }
                int i = line.indexOf('"');
                int j = line.lastIndexOf('"');
                if (i >= 0 && j > i) {
                    return line.substring(i + 1, j);
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
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
                if (line.contains("uid=0(root)")) {
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
