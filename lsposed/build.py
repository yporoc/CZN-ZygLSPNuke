#!/usr/bin/env python3
"""Build the LSPosed module (no gradle).

Requirements (environment variables):
  ANDROID_HOME   - Android SDK root (needs build-tools and a platform android.jar)
  JAVAC          - javac path (default: javac on PATH)
  KSTORE / KSPASS- optional signing keystore; if absent a debug keystore is generated

The Xposed API stubs are expected under ./stubs (not bundled here to avoid
shipping third-party API copies). Provide de/robv/android/xposed/*.java there,
or set XPOSED_STUBS to an existing stub source directory.
"""
import os, glob, shutil, subprocess, sys, zipfile, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))

def die(msg, code=1):
    print("[!] " + msg, file=sys.stderr); sys.exit(code)

def run(cmd):
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        print(r.stdout.decode("utf-8", "replace")[-2000:], file=sys.stderr)
        print(r.stderr.decode("utf-8", "replace")[-2000:], file=sys.stderr)
        die("command failed: %s" % cmd[0])
    return r

def main():
    sdk = os.environ.get("ANDROID_HOME") or die("set ANDROID_HOME")
    bt_dir = os.environ.get("BUILD_TOOLS") or os.path.join(sdk, "build-tools")
    if not os.path.isdir(bt_dir):
        die("build-tools not found: " + bt_dir)
    bt = sorted(os.listdir(bt_dir))[-1]
    BT = os.path.join(bt_dir, bt)
    jar = os.environ.get("ANDROID_JAR")
    if not jar:
        plats = os.path.join(sdk, "platforms")
        jar = os.path.join(plats, sorted(os.listdir(plats))[-1], "android.jar")
    stubs = os.environ.get("XPOSED_STUBS") or os.path.join(HERE, "stubs")
    javac = os.environ.get("JAVAC", "javac")
    for p in (jar, stubs):
        if not os.path.exists(p):
            die("missing: " + p)

    out = os.path.join(HERE, "build")
    os.makedirs(out, exist_ok=True)
    srcs = sorted(glob.glob(os.path.join(HERE, "src", "**", "*.java"), recursive=True))
    if not srcs: die("no sources")

    run([javac, "--release", "11", "-nowarn", "-cp", jar,
         "-sourcepath", stubs + os.pathsep + os.path.join(HERE, "src"),
         "-d", os.path.join(out, "classes")] + srcs)

    cls = []
    for s in srcs:
        rel = os.path.relpath(s, os.path.join(HERE, "src"))[:-5]
        c = os.path.join(out, "classes", rel + ".class")
        if not os.path.exists(c): die("no class for " + s)
        cls.append(c)
        cls += glob.glob(c[:-6] + "$*.class")

    jarfile = os.path.join(out, "classes.jar")
    with zipfile.ZipFile(jarfile, "w", zipfile.ZIP_DEFLATED) as z:
        for c in cls:
            z.write(c, os.path.relpath(c, os.path.join(out, "classes")).replace(os.sep, "/"))

    run([os.path.join(BT, "d8.bat" if os.name == "nt" else "d8"), "--release",
         "--lib", jar, "--min-api", "26", "--output", out, jarfile])
    dex = os.path.join(out, "classes.dex")
    if not os.path.isfile(dex): die("d8 produced no dex")

    base = os.path.join(out, "base.apk")
    run([os.path.join(BT, "aapt2.exe" if os.name == "nt" else "aapt2"),
         "link", "-I", jar, "--manifest", os.path.join(HERE, "AndroidManifest.xml"), "-o", base])

    apk = os.path.join(HERE, "analyticvoid.apk")
    with zipfile.ZipFile(base) as zin, zipfile.ZipFile(apk, "w") as zout:
        for it in zin.infolist():
            zout.writestr(it, zin.read(it.filename))
        zout.writestr("classes.dex", open(dex, "rb").read(), zipfile.ZIP_DEFLATED)
        zout.writestr("assets/xposed_init",
                      open(os.path.join(HERE, "assets", "xposed_init"), "rb").read(),
                      zipfile.ZIP_STORED)

    print("[+] built", apk, os.path.getsize(apk), "bytes")
    print("[+] sha256", hashlib.sha256(open(apk, "rb").read()).hexdigest())

if __name__ == "__main__":
    main()
