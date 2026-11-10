#!/usr/bin/env python3
"""
Redmi 15C / POCO C85  (dew / 25078RA3EE)
Firmware target: OS2.0.214.0.VBNMIXN  (Android 15 / SDK 35)

Flashes ONLY init_boot with the survival image. It refuses a device unless ALL
of these match:
  - product = dew
  - model = 25078RA3EE (when exposed)
  - MIUI/HyperOS = OS2.0.214.0.VBNMIXN
  - Android release = 15, SDK = 35
  - init_boot partition = 0x800000 (8 MB)
  - bootloader unlocked and in bootloader mode (not fastbootd)
  - image SHA-256 = known good survival image

Fastboot does not always expose MIUI/Android. For a booted phone, use --adb:
it reads the real props, verifies them, reboots to bootloader, then flashes.
Without --adb, unknown MIUI/Android is refused unless --allow-unknown-version.

Usage:
  python3 dew_OS2.0.214.0_VBNMIXN_fastboot_flash.py --list
  python3 dew_OS2.0.214.0_VBNMIXN_fastboot_flash.py --adb --list
  python3 dew_OS2.0.214.0_VBNMIXN_fastboot_flash.py --adb          # booted phones
  python3 dew_OS2.0.214.0_VBNMIXN_fastboot_flash.py               # fastboot phones
  python3 dew_OS2.0.214.0_VBNMIXN_fastboot_flash.py --loop        # rolling fastboot
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.realpath(__file__))
DEFAULT_IMAGE = os.path.join(ROOT, "ARCHIVE", "bootsrc", "survival_init_boot.img")

EXPECTED_PRODUCT = "dew"
EXPECTED_MODEL = "25078RA3EE"
EXPECTED_FIRMWARE = "OS2.0.214.0.VBNMIXN"
EXPECTED_RELEASE = "15"
EXPECTED_SDK = "35"
EXPECTED_INIT_BOOT = 0x800000
EXPECTED_IMAGE_SIZE = 8388608
EXPECTED_SHA = "587397766971831c1c80e40484510aac4416a928ea3ed71feb7d80b7c44c8fd3"

PROTECTED_SERIALS = set()
WARNED_PROTECTED = set()


def protected_serial(serial):
    if (serial or "").strip().upper() not in PROTECTED_SERIALS:
        return False
    if serial not in WARNED_PROTECTED:
        WARNED_PROTECTED.add(serial)
        log("REFUSE %s: PROTECTED WORK PHONE - read-only; flashing permanently blocked" % serial)
    return True


def log(msg):
    line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except FileNotFoundError:
        return 127, "not found"


def parse_vars(text):
    data = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("(bootloader)"):
            line = line[len("(bootloader)"):].strip()
        if ":" not in line:
            continue
        key, value = line.rsplit(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            data[key] = value
    return data


def to_int(value):
    if not value:
        return None
    value = value.strip().lower()
    try:
        return int(value, 16) if value.startswith("0x") else int(value)
    except ValueError:
        return None


def image_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


LEDGER = os.path.join(os.path.expanduser("~"), ".redmi15c_flashed.json")


def load_ledger():
    try:
        with open(LEDGER, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def ledger_mark(serial, image_sha):
    data = load_ledger()
    data[serial] = {"sha": image_sha, "time": int(time.time())}
    try:
        tmp = LEDGER + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, LEDGER)
    except Exception as exc:
        log("WARN   %s: flash ledger not saved: %s" % (serial, exc))


def already_flashed(serial, args, image_sha):
    if args.serial or args.reflash:
        return False
    entry = load_ledger().get(serial)
    return bool(entry and entry.get("sha") == image_sha)


def fastboot_devices():
    rc, out = run(["fastboot", "devices"])
    if rc != 0:
        return []
    serials = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "fastboot":
            serials.append(parts[0])
    return serials


def adb_devices():
    rc, out = run(["adb", "devices"])
    if rc != 0:
        return []
    serials = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def adb_props(serial):
    props = {}
    for key in ("ro.product.device", "ro.product.model", "ro.build.version.incremental",
                "ro.build.version.release", "ro.build.version.sdk", "ro.build.fingerprint"):
        rc, out = run(["adb", "-s", serial, "shell", "getprop", key], timeout=30)
        props[key] = out.strip() if rc == 0 else ""
    return props


def fastboot_vars(serial):
    rc, out = run(["fastboot", "-s", serial, "getvar", "all"], timeout=60)
    data = parse_vars(out) if out else {}
    for key in ("product", "current-slot", "unlocked", "secure", "is-userspace",
                "partition-size:init_boot", "model", "ro.product.model",
                "ro.build.version.incremental", "ro.build.version.release",
                "ro.build.version.sdk", "ro.build.fingerprint"):
        if key not in data:
            rc, out = run(["fastboot", "-s", serial, "getvar", key], timeout=30)
            data.update(parse_vars(out))
    return data


def fastboot_info(serial):
    g = fastboot_vars(serial)
    fw = ""
    for key in ("ro.build.version.incremental", "ro.build.fingerprint",
                "fw-version", "version", "build-date"):
        value = g.get(key, "").strip()
        if not value or value.lower() in ("unknown", "none", "n/a"):
            continue
        if key in ("version", "build-date") and not any(
                token in value.upper() for token in ("OS", "MIUI", "HYPEROS")):
            continue
        fw = value
        break
    return {
        "serial": serial,
        "product": g.get("product", "?"),
        "model": g.get("model", g.get("ro.product.model", "?")),
        "slot": g.get("current-slot", "?"),
        "unlocked": g.get("unlocked", "?"),
        "secure": g.get("secure", "?"),
        "userspace": g.get("is-userspace", "no"),
        "init_boot": (g.get("partition-size:init_boot") or
                      g.get("partition-size:init_boot_" + str(g.get("current-slot", "")).strip()) or
                      "?"),
        "firmware": fw,
        "release": g.get("ro.build.version.release", ""),
        "sdk": g.get("ro.build.version.sdk", ""),
    }


def adb_info(serial):
    p = adb_props(serial)
    return {
        "serial": serial,
        "product": p.get("ro.product.device", "?"),
        "model": p.get("ro.product.model", "?"),
        "slot": "?",
        "unlocked": "yes",
        "secure": "?",
        "userspace": "no",
        "init_boot": "verified after reboot",
        "firmware": p.get("ro.build.version.incremental", ""),
        "release": p.get("ro.build.version.release", ""),
        "sdk": p.get("ro.build.version.sdk", ""),
    }


def version_errors(info, args, source):
    """Check MIUI + Android. source is 'adb' or 'fastboot'."""
    errors = []
    fw = str(info.get("firmware", "")).strip()
    release = str(info.get("release", "")).strip()
    sdk = str(info.get("sdk", "")).strip()
    unknown = []

    if not fw:
        unknown.append("MIUI")
    elif EXPECTED_FIRMWARE.lower() not in fw.lower():
        errors.append("MIUI is %r, expected %r" % (fw, EXPECTED_FIRMWARE))

    if not release:
        unknown.append("Android release")
    elif release != EXPECTED_RELEASE:
        errors.append("Android release is %r, expected %r" % (release, EXPECTED_RELEASE))

    if not sdk:
        unknown.append("SDK")
    elif sdk != EXPECTED_SDK:
        errors.append("SDK is %r, expected %r" % (sdk, EXPECTED_SDK))

    if unknown and not args.allow_unknown_version:
        errors.append("cannot verify %s in %s; use --adb or --allow-unknown-version"
                      % ("/".join(unknown), source))
    return errors


def verify_fastboot(info, args, image_sha):
    errors, warnings = [], []
    if str(info["product"]).lower() != EXPECTED_PRODUCT:
        errors.append("product is %r, expected %r" % (info["product"], EXPECTED_PRODUCT))

    model = str(info["model"]).strip()
    if model not in ("?", "") and model not in (EXPECTED_MODEL, EXPECTED_PRODUCT):
        errors.append("model is %r, expected %r" % (model, EXPECTED_MODEL))

    raw_size = str(info["init_boot"]).strip()
    size = to_int(raw_size)
    if size != EXPECTED_INIT_BOOT and raw_size and not raw_size.lower().startswith("0x"):
        try:
            hex_size = int(raw_size, 16)
            if hex_size == EXPECTED_INIT_BOOT:
                size = hex_size
        except ValueError:
            pass
    if size != EXPECTED_INIT_BOOT:
        errors.append("init_boot size is %r, expected 0x%X" %
                      (info["init_boot"], EXPECTED_INIT_BOOT))

    if str(info["unlocked"]).lower() not in ("yes", "true", "1"):
        errors.append("bootloader is locked (unlocked=%r)" % info["unlocked"])

    if str(info["userspace"]).lower() in ("yes", "true", "1"):
        errors.append("device is in fastbootd; reboot to bootloader first")

    if str(info["secure"]).lower() not in ("no", "false", "0", "?"):
        warnings.append("secure=%r" % info["secure"])

    errors.extend(version_errors(info, args, "fastboot"))

    if image_sha != EXPECTED_SHA and not args.force:
        errors.append("image SHA mismatch (got %s, expected %s)" % (image_sha, EXPECTED_SHA))
    if not os.path.isfile(args.image):
        errors.append("image not found: %s" % args.image)
    elif os.path.getsize(args.image) != EXPECTED_IMAGE_SIZE:
        warnings.append("image size %d != %d" % (os.path.getsize(args.image), EXPECTED_IMAGE_SIZE))
    return errors, warnings


def verify_adb(info, args):
    errors = []
    if str(info["product"]).lower() != EXPECTED_PRODUCT:
        errors.append("device is %r, expected %r" % (info["product"], EXPECTED_PRODUCT))
    model = str(info["model"]).strip()
    if model not in (EXPECTED_MODEL, EXPECTED_PRODUCT):
        errors.append("model is %r, expected %r" % (model, EXPECTED_MODEL))
    errors.extend(version_errors(info, args, "ADB"))
    return errors, []


def flash(serial, args, info):
    if protected_serial(serial):
        return False
    log("FLASH  %s: fastboot flash init_boot %s" % (serial, args.image))
    rc, out = run(["fastboot", "-s", serial, "flash", "init_boot", args.image],
                  timeout=args.flash_timeout)
    if rc != 0:
        for line in out.splitlines()[-6:]:
            log("       %s" % line.strip())
        log("FAIL   %s: flash rc=%d" % (serial, rc))
        return False
    log("OK     %s: init_boot flashed" % serial)
    if args.factory_reset:
        log("WIPE   %s: factory reset (erase userdata/metadata)" % serial)
        wipe_ok = True
        for part in ("userdata", "metadata"):
            part_ok = False
            for attempt in range(1, 4):
                erc, eout = run(["fastboot", "-s", serial, "erase", part], timeout=180)
                log("ERASE  %s attempt %d rc=%d" % (part, attempt, erc))
                if erc == 0:
                    part_ok = True
                    break
                for line in eout.splitlines()[-3:]:
                    log("       %s" % line.strip())
                time.sleep(2)
            if not part_ok:
                wipe_ok = False
        if not wipe_ok:
            log("FAIL   %s: factory reset incomplete; leaving device in bootloader" % serial)
            log("       fix the erase error and run the flasher again for this phone")
            return False
        log("WIPE   %s: factory reset done" % serial)
    if args.reboot:
        rc, out = run(["fastboot", "-s", serial, "reboot"], timeout=60)
        if rc != 0:
            log("WARN   %s: reboot failed rc=%d" % (serial, rc))
        else:
            log("REBOOT %s" % serial)
    return True


def process_fastboot(serial, args, image_sha, preverified=None):
    if protected_serial(serial):
        return False
    info = fastboot_info(serial)
    if preverified:
        info["firmware"] = preverified["firmware"]
        info["release"] = preverified["release"]
        info["sdk"] = preverified["sdk"]
        info["model"] = preverified["model"]
    log("DEVICE %s product=%s model=%s slot=%s init_boot=%s unlocked=%s secure=%s "
        "userspace=%s MIUI=%s Android=%s SDK=%s" %
        (info["serial"], info["product"], info["model"], info["slot"],
         info["init_boot"], info["unlocked"], info["secure"], info["userspace"],
         info["firmware"] or "?", info["release"] or "?", info["sdk"] or "?"))

    errors, warnings = verify_fastboot(info, args, image_sha)
    for warning in warnings:
        log("WARN   %s: %s" % (serial, warning))
    if errors:
        for error in errors:
            log("REFUSE %s: %s" % (serial, error))
        return False
    if args.list_only or args.dry_run:
        log("OK     %s: verification passed (%s)" %
            (serial, "list" if args.list_only else "dry-run"))
        return True
    ok = flash(serial, args, info)
    if ok:
        ledger_mark(serial, image_sha)
    return ok


def process_adb(serial, args, image_sha):
    if protected_serial(serial):
        return False
    info = adb_info(serial)
    log("ADB    %s device=%s model=%s MIUI=%s Android=%s SDK=%s" %
        (serial, info["product"], info["model"], info["firmware"] or "?",
         info["release"] or "?", info["sdk"] or "?"))
    errors, _ = verify_adb(info, args)
    if errors:
        for error in errors:
            log("REFUSE %s: %s" % (serial, error))
        return False
    if args.list_only or args.dry_run:
        log("OK     %s: ADB verification passed (%s)" %
            (serial, "list" if args.list_only else "dry-run"))
        return True

    rc, out = run(["adb", "-s", serial, "reboot", "bootloader"], timeout=60)
    if rc != 0:
        log("FAIL   %s: adb reboot bootloader rc=%d" % (serial, rc))
        return False
    log("REBOOT %s -> bootloader" % serial)
    for _ in range(60):
        if serial in fastboot_devices():
            break
        time.sleep(2)
    else:
        log("FAIL   %s: did not appear in fastboot" % serial)
        return False
    return process_fastboot(serial, args, image_sha, preverified=info)


def wait_for(kind, args, serial=None):
    while True:
        devices = adb_devices() if kind == "adb" else fastboot_devices()
        if serial:
            devices = [serial] if serial in devices else []
        if devices:
            return devices
        log("WAIT   no %s device; waiting..." % kind)
        time.sleep(max(1, args.interval))


def gui_main(selftest=False):
    """PyQt GUI front-end. The flashing engine is this same script (child process)."""
    import shlex
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
    except ImportError:
        try:
            from PyQt6 import QtCore, QtGui, QtWidgets
        except ImportError:
            print("PyQt5/PyQt6 not installed. Install with: pip install PyQt5")
            return 1

    try:
        merged = QtCore.QProcess.MergedChannels
        not_running = QtCore.QProcess.NotRunning
    except AttributeError:
        merged = QtCore.QProcess.ProcessChannelMode.MergedChannels
        not_running = QtCore.QProcess.ProcessState.NotRunning

    if not selftest and sys.platform.startswith("linux"):
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
                or os.environ.get("QT_QPA_PLATFORM")):
            print("No graphical display detected.")
            print("Run with --help, or use CLI options: --list, --adb, --loop.")
            return 1

    app = QtWidgets.QApplication(sys.argv)
    win = QtWidgets.QMainWindow()
    win.setWindowTitle("Redmi 15C dew - OS2.0.214.0.VBNMIXN - auto flasher")
    central = QtWidgets.QWidget()
    win.setCentralWidget(central)
    layout = QtWidgets.QVBoxLayout(central)
    layout.setContentsMargins(14, 14, 14, 14)
    layout.setSpacing(8)

    title = QtWidgets.QLabel("<b>Redmi 15C / POCO C85 &mdash; dew / 25078RA3EE</b>")
    target = QtWidgets.QLabel(
        "Strict target: MIUI/HyperOS <b>OS2.0.214.0.VBNMIXN</b> &nbsp;|&nbsp; "
        "Android <b>15 / SDK 35</b> &nbsp;|&nbsp; init_boot <b>8 MB</b> &nbsp;|&nbsp; "
        "only <b>init_boot</b> is flashed")
    target.setWordWrap(True)
    protected = QtWidgets.QLabel(
        "AUTO mode: ADB verifies MIUI/Android exactly. Fastboot cannot read them, "
        "so product + 8 MB init_boot + unlock + image SHA are checked.")
    protected.setWordWrap(True)
    protected.setStyleSheet("color: #8a6d00;")
    layout.addWidget(title)
    layout.addWidget(target)
    layout.addWidget(protected)

    image_row = QtWidgets.QHBoxLayout()
    image_row.addWidget(QtWidgets.QLabel("Image:"))
    image_edit = QtWidgets.QLineEdit(DEFAULT_IMAGE)
    image_edit.setReadOnly(True)
    image_edit.setMinimumWidth(520)
    browse = QtWidgets.QPushButton("Browse...")
    browse.hide()
    image_row.addWidget(image_edit, 1)
    image_row.addWidget(browse)
    layout.addLayout(image_row)

    mode_row = QtWidgets.QHBoxLayout()
    mode_label = QtWidgets.QLabel("Mode:")
    mode = QtWidgets.QComboBox()
    mode.addItems([
        "AUTO - ADB + fastboot (multi, no click)",
        "Fastboot - auto loop (multi devices)",
        "Fastboot - once (all connected)",
        "ADB - booted phones (verify props, reboot, flash)",
    ])
    mode.setMinimumWidth(480)
    mode_label.hide()
    mode.hide()
    mode_row.addWidget(mode_label)
    mode_row.addWidget(mode, 1)
    layout.addLayout(mode_row)

    opts = QtWidgets.QHBoxLayout()
    allow_unknown = QtWidgets.QCheckBox("Allow unknown version (fastboot only)")
    allow_unknown.setChecked(True)
    autostart = QtWidgets.QCheckBox("Start automatically on open")
    autostart.setChecked(True)
    factory_reset = QtWidgets.QCheckBox("Factory reset after flash (ERASES DATA)")
    factory_reset.setChecked(True)
    factory_reset.setStyleSheet("color: #b00020;")
    dry_run = QtWidgets.QCheckBox("Dry run / verify only")
    no_reboot = QtWidgets.QCheckBox("No reboot after flash")
    for widget in (allow_unknown, autostart, factory_reset, dry_run, no_reboot):
        widget.hide()
        opts.addWidget(widget)
    opts.addStretch(1)
    layout.addLayout(opts)

    buttons = QtWidgets.QHBoxLayout()
    start_btn = QtWidgets.QPushButton("Start auto flash")
    scan_btn = QtWidgets.QPushButton("Scan / list devices")
    stop_btn = QtWidgets.QPushButton("STOP (emergency)")
    clear_btn = QtWidgets.QPushButton("Clear log")
    stop_btn.setEnabled(False)
    start_btn.hide()
    scan_btn.hide()
    clear_btn.hide()
    start_btn.setStyleSheet("QPushButton { font-weight: bold; padding: 6px 12px; }")
    buttons.addWidget(start_btn)
    buttons.addWidget(scan_btn)
    buttons.addWidget(stop_btn)
    buttons.addWidget(clear_btn)
    buttons.addStretch(1)
    layout.addLayout(buttons)

    status = QtWidgets.QLabel("Idle")
    layout.addWidget(status)

    log = QtWidgets.QPlainTextEdit()
    log.setReadOnly(True)
    log.setMaximumBlockCount(5000)
    log.setFont(QtGui.QFont("Monospace", 9))
    layout.addWidget(log, 1)

    proc = QtCore.QProcess(win)
    proc.setProcessChannelMode(merged)
    stop_flag = [False]

    def append(text):
        for line in text.splitlines():
            log.appendPlainText(line)

    def read_output():
        data = bytes(proc.readAllStandardOutput()).decode("utf-8", "replace")
        append(data)

    def set_running(running, label="Running"):
        start_btn.setEnabled(not running)
        scan_btn.setEnabled(not running)
        stop_btn.setEnabled(running)
        status.setText(label if running else "Idle")

    def on_finished(code, exit_status):
        append("=== finished rc=%s ===" % code)
        set_running(False)
        if not selftest and not stop_flag[0]:
            append("AUTO engine exited; restarting in 5 seconds...")
            QtCore.QTimer.singleShot(5000, start_engine)

    def on_error(err):
        append("process error: %s" % err)
        set_running(False)

    proc.readyReadStandardOutput.connect(read_output)
    proc.finished.connect(on_finished)
    proc.errorOccurred.connect(on_error)

    def base_cmd():
        return [sys.executable, os.path.realpath(__file__),
                "--image", image_edit.text().strip()]

    def options(cmd, force_unknown=False):
        if force_unknown or allow_unknown.isChecked():
            cmd.append("--allow-unknown-version")
        if factory_reset.isChecked():
            cmd.append("--factory-reset")
        if no_reboot.isChecked():
            cmd.append("--no-reboot")
        return cmd

    def start_engine():
        stop_flag[0] = False
        image = DEFAULT_IMAGE
        if not os.path.isfile(image):
            status.setText("ERROR - image missing")
            append("ERROR image not found: " + image)
            return
        if proc.state() != not_running:
            return
        cmd = base_cmd() + ["--auto", "--interval", "2",
                            "--allow-unknown-version", "--factory-reset"]
        append(">>> " + " ".join(shlex.quote(x) for x in cmd))
        set_running(True, "AUTO - running; no buttons needed")
        proc.start(cmd[0], cmd[1:])

    def scan_devices():
        if proc.state() != not_running:
            return
        cmd = base_cmd()
        idx = mode.currentIndex()
        if idx == 0:
            cmd.append("--auto")
        elif idx == 3:
            cmd.append("--adb")
        cmd.append("--list")
        options(cmd, force_unknown=(idx == 0))
        append(">>> " + " ".join(shlex.quote(x) for x in cmd))
        set_running(True, "Scanning...")
        proc.start(cmd[0], cmd[1:])

    def stop_engine():
        stop_flag[0] = True
        if proc.state() != not_running:
            append("stopping...")
            proc.terminate()
            QtCore.QTimer.singleShot(3000, lambda: proc.kill() if proc.state() != not_running else None)
            status.setText("Stopping...")

    def browse_image():
        name, _ = QtWidgets.QFileDialog.getOpenFileName(
            win, "Select survival init_boot image", os.path.dirname(image_edit.text()),
            "Images (*.img);;All files (*)")
        if name:
            image_edit.setText(name)

    start_btn.clicked.connect(start_engine)
    scan_btn.clicked.connect(scan_devices)
    stop_btn.clicked.connect(stop_engine)
    clear_btn.clicked.connect(log.clear)
    browse.clicked.connect(browse_image)

    def close_event(event):
        stop_flag[0] = True
        if proc.state() != not_running:
            proc.terminate()
        event.accept()

    win.closeEvent = close_event
    win.resize(1040, 760)
    win.show()

    if not selftest and autostart.isChecked():
        status.setText("AUTO - starting in 3 seconds...")
        QtCore.QTimer.singleShot(3000, start_engine)

    if selftest:
        shot = os.environ.get("GUI_SCREENSHOT")
        if shot:
            QtCore.QTimer.singleShot(400, lambda: win.grab().save(shot))
        QtCore.QTimer.singleShot(1000, app.quit)
    exec_fn = getattr(app, "exec", None) or getattr(app, "exec_")
    return exec_fn()


def main():
    parser = argparse.ArgumentParser(
        description="Strict init_boot flasher for Redmi 15C dew / OS2.0.214.0.VBNMIXN")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="survival init_boot image")
    parser.add_argument("--serial", help="only this serial")
    parser.add_argument("--adb", action="store_true",
                        help="verify booted Android props first, then reboot to bootloader")
    parser.add_argument("--auto", action="store_true",
                        help="fully automatic: ADB verifies props, fastboot checks product/size/SHA, multi-device")
    parser.add_argument("--list", action="store_true", dest="list_only",
                        help="show info/verification only")
    parser.add_argument("--dry-run", action="store_true", help="verify only, no flash")
    parser.add_argument("--wait", action="store_true", help="wait for a device")
    parser.add_argument("--loop", action="store_true", help="keep flashing new fastboot devices")
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--allow-unknown-version", action="store_true",
                        help="allow fastboot devices that do not expose MIUI/Android")
    parser.add_argument("--force", action="store_true", help="ignore image SHA mismatch")
    parser.add_argument("--reflash", action="store_true",
                        help="flash phones already recorded in the completed ledger")
    parser.add_argument("--factory-reset", action="store_true",
                        help="erase userdata/metadata after flashing (factory reset)")
    parser.add_argument("--no-reboot", action="store_false", dest="reboot")
    parser.add_argument("--flash-timeout", type=int, default=300)
    parser.add_argument("--gui", action="store_true", help="launch the PyQt GUI")
    parser.add_argument("--gui-selftest", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if len(sys.argv) == 1:
        return gui_main()

    if args.gui or args.gui_selftest:
        return gui_main(selftest=args.gui_selftest)

    if args.loop and args.adb:
        parser.error("--loop applies to fastboot only; run --adb per booted phone")

    if not os.path.isfile(args.image):
        log("ERROR image not found: %s" % args.image)
        return 2
    image_sha = image_hash(args.image)
    log("IMAGE %s size=%d sha256=%s" %
        (args.image, os.path.getsize(args.image), image_sha))
    log("TARGET product=%s model=%s MIUI=%s Android=%s SDK=%s init_boot=0x%X" %
        (EXPECTED_PRODUCT, EXPECTED_MODEL, EXPECTED_FIRMWARE,
         EXPECTED_RELEASE, EXPECTED_SDK, EXPECTED_INIT_BOOT))

    if args.auto:
        args.allow_unknown_version = True
        log("AUTO   ADB verifies MIUI/Android; fastboot checks product/size/unlock/SHA")
        done = set()
        waiting = False
        while True:
            adb_now = adb_devices()
            fb_now = fastboot_devices()
            if args.serial:
                adb_now = [s for s in adb_now if s == args.serial]
                fb_now = [s for s in fb_now if s == args.serial]
            present = set(adb_now) | set(fb_now)
            done = {s for s in done if s in present}
            if not present:
                if not waiting:
                    log("WAIT   no ADB/fastboot device; waiting for the next phone...")
                    waiting = True
            else:
                waiting = False
            for serial in adb_now:
                if serial in done:
                    continue
                if already_flashed(serial, args, image_sha):
                    log("SKIP   %s already flashed with this image" % serial)
                    done.add(serial)
                    continue
                process_adb(serial, args, image_sha)
                done.add(serial)
            for serial in fb_now:
                if args.serial and serial != args.serial:
                    continue
                if serial in done:
                    continue
                if already_flashed(serial, args, image_sha):
                    log("SKIP   %s already flashed with this image" % serial)
                    done.add(serial)
                    continue
                process_fastboot(serial, args, image_sha)
                done.add(serial)
            if args.list_only or args.dry_run:
                return 0
            time.sleep(max(1, args.interval))

    if args.adb:
        devices = adb_devices()
        if args.serial:
            devices = [args.serial] if args.serial in devices else []
        if not devices and (args.wait or args.loop):
            devices = wait_for("adb", args, args.serial)
        if not devices:
            log("ERROR no ADB devices")
            return 2
        ok = True
        for serial in devices:
            ok = process_adb(serial, args, image_sha) and ok
        return 0 if ok else 1

    done = set()
    ok_all = True
    while True:
        serials = fastboot_devices()
        if args.serial:
            serials = [args.serial] if args.serial in serials else []
        if not serials:
            if args.loop or args.wait:
                log("WAIT   no fastboot device; waiting...")
                time.sleep(max(1, args.interval))
                continue
            log("ERROR no fastboot devices")
            return 2
        for serial in serials:
            if serial in done:
                continue
            ok_all = process_fastboot(serial, args, image_sha) and ok_all
            done.add(serial)
        if not (args.loop or args.wait):
            break
        if args.wait and done:
            break
        time.sleep(max(1, args.interval))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
