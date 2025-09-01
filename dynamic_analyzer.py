# dynamic_analyzer.py (Upgraded Version)
import subprocess
import time
import re

def get_package_name(apk_path):
    """Extracts package name from APK using aapt."""
    try:
        result = subprocess.run(['aapt', 'dump', 'badging', apk_path], check=True, capture_output=True, text=True)
        match = re.search(r"package: name='([^']+)'", result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"Error getting package name: {e}")
    return None

def run_dynamic_analysis(apk_path):
    """Installs, runs, monitors, and uninstalls the APK on an active emulator."""
    findings = {
        "network_traffic": [],
        "errors": []
    }
    
    package_name = get_package_name(apk_path)
    if not package_name:
        findings["errors"].append("Could not determine package name from APK.")
        return findings

    try:
        print("Starting dynamic analysis...")
        subprocess.run(['adb', 'install', '-r', apk_path], check=True, timeout=30)
        subprocess.run(['adb', 'logcat', '-c'], check=True)
        subprocess.run(['adb', 'shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1'], check=True)
        
        print("Monitoring app for 30 seconds...")
        time.sleep(30)
        logcat_output = subprocess.run(['adb', 'logcat', '-d'], check=True, capture_output=True, text=True).stdout
        
        subprocess.run(['adb', 'shell', 'am', 'force-stop', package_name], check=True)
        subprocess.run(['adb', 'uninstall', package_name], check=True)
        print("Dynamic analysis complete.")

        # --- UPGRADED LOGIC ---
        # Look for a broader set of network-related keywords
        network_keywords = ["http", "okhttp", "urlconnection", "socket", "network", "connectivity"]
        
        for line in logcat_output.splitlines():
            # Check if any keyword exists in the line (case-insensitive)
            if any(keyword in line.lower() for keyword in network_keywords):
                findings["network_traffic"].append(line)
        
    except subprocess.CalledProcessError as e:
        findings["errors"].append(f"An ADB command failed: {e}")
        if package_name:
            subprocess.run(['adb', 'uninstall', package_name])
    except Exception as e:
        findings["errors"].append(f"An unexpected error occurred: {e}")
        
    return findings