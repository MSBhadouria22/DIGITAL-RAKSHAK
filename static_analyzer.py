# static_analyzer.py
import os
import subprocess
import re
from xml.etree import ElementTree

# --- IMPORTANT ---
# UPDATE THIS PATH TO WHERE YOU SAVED APKTOOL
APKTOOL_PATH = 'apktool_2.12.0.jar' 

def decompile_apk(apk_path, output_dir):
    """Decompiles an APK using apktool."""
    print(f"Decompiling {apk_path}...")
    cmd = ['java', '-jar', APKTOOL_PATH, 'd', '--force', apk_path, '-o', output_dir]
    try:
        # Use a timeout to prevent getting stuck on large/complex APKs
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60)
        print("Decompilation successful.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error during decompilation: {e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        print("Error: Decompilation timed out.")
        return False

def analyze_manifest(output_dir):
    """Parses AndroidManifest.xml for suspicious permissions."""
    manifest_path = os.path.join(output_dir, 'AndroidManifest.xml')
    permissions = []
    suspicious_permissions = [
        "android.permission.SEND_SMS", "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.READ_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION"
    ]
    try:
        tree = ElementTree.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        for perm in root.findall('uses-permission'):
            perm_name = perm.get(f"{{{ns['android']}}}name")
            if perm_name in suspicious_permissions:
                permissions.append(perm_name)
    except Exception as e:
        print(f"Error parsing manifest: {e}")
    return permissions

def find_urls(output_dir):
    """Scans decompiled files for URLs."""
    urls = set()
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    for root_dir, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith(('.smali', '.xml', '.java')):
                try:
                    with open(os.path.join(root_dir, file), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        found_urls = url_pattern.findall(content)
                        urls.update(found_urls)
                except Exception:
                    continue
    return list(urls)