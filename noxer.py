
import os
import subprocess
import psutil
import re
import requests
from OpenSSL import crypto
from requests.exceptions import ConnectionError

NOXER_BANNER = """\033[38;5;208m  
 __    _  _______  __   __  _______  ______   
|  |  | ||       ||  |_|  ||       ||    _ |  
|   |_| ||   _   ||       ||    ___||   | ||  
|       ||  | |  ||       ||   |___ |   |_||_ 
|  _    ||  |_|  | |     | |    ___||    __  |
| | |   ||       ||   _   ||   |___ |   |  | |
|_|  |__||_______||__| |__||_______||___|  |_|
____________NoX Player for GEEKZ______________
           Github: AggressiveUser
                                    Ver-1.22_β
\033[0m"""
print(NOXER_BANNER)

NOX_ADB_PORTS = [62001, 62025, 62026]
BURP_CERT_URL = "http://127.0.0.1:8080/cert"
CERT_DER_FILE = "cacert.der"
CERT_PEM_FILE = "9a5ba575.0"
FRIPTS_DIR = "./Fripts"

def is_tool_installed(tool):
    try:
        subprocess.run([tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def install_tool(tool):
    subprocess.run(['pip', 'install', tool])

def find_nox_installation_path():
    for process in psutil.process_iter(['pid', 'name', 'exe']):
        if 'Nox.exe' in process.info['name']:
            return os.path.dirname(process.info['exe'])
    return None

def connect_to_nox_adb(ip='127.0.0.1', port=62001):
    if nox_installation_path:
        adb_command = f'\"{nox_installation_path}\\nox_adb.exe\" connect {ip}:{port}'
        result = subprocess.run(adb_command, shell=True, text=True, capture_output=True)
        return result.stdout.strip()
    else:
        return "Nox player not installed."

def download_and_convert_cert():
    try:
        response = requests.get(BURP_CERT_URL)
        if response.status_code == 200:
            with open(CERT_DER_FILE, "wb") as certificate_file:
                certificate_file.write(response.content)
            print("Burp Suite certificate downloaded successfully.")

            with open(CERT_DER_FILE, "rb") as der_file:
                der_data = der_file.read()
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_data)

            with open(CERT_PEM_FILE, "wb") as pem_file:
                pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                pem_file.write(pem_data)
            return True
        else:
            print("Error: Unable to download the certificate from the specified URL.")
            return False
    except ConnectionError:
        print("Error: Burp Suite is not running or the proxy server is not on 127.0.0.1:8080.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return False

def install_burp_cert():
    if download_and_convert_cert():
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" root')
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" remount')
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" push {CERT_PEM_FILE} /system/etc/security/cacerts/')
        os.system(f'\"{nox_installation_path}\\nox_adb.exe\" shell chmod 644 /system/etc/security/cacerts/{CERT_PEM_FILE}')
        print("\x1b[1;32mBurpSuite Certificate Install Successfully in Nox Player\x1b[0m")
        print("")

def open_adb_shell_from_nox():
    if nox_installation_path:
        adb_shell_command = f'\"{nox_installation_path}\\nox_adb.exe\" shell -t su'
        print("\x1b[1;32mOpening ADB Shell. Type 'exit' to return to the main menu.\x1b[0m")
        subprocess.run(adb_shell_command, shell=True)
    else:
        print("\033[91mNox player not installed.\033[0m")

def frida_server_install():
    print("Checking Installed Frida-Tools Version")
    frida_version_output = subprocess.check_output("frida --version 2>&1", shell=True, stderr=subprocess.STDOUT, text=True)
    if re.search(r'(\d+\.\d+\.\d+)', frida_version_output):
        frida_version = re.search(r'(\d+\.\d+\.\d+)', frida_version_output).group(1)
        print(f"Frida-Tools Version: {frida_version}")
        
        noxarch = f'\"{nox_installation_path}\\nox_adb.exe\"  shell getprop ro.product.cpu.abi'
        noxarchre = subprocess.run(noxarch, shell=True, text=True, check=True, capture_output=True)
        noxarchresult = noxarchre.stdout.strip()
        print(f"CPU Architecture of Nox Emulator: {noxarchresult}")
        
        print("Downloading Frida-Server With Same Version")
        frida_server_url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{noxarchresult}.xz"
        
        downloadfridaserver = f'\"{nox_installation_path}\\nox_adb.exe\"  shell curl -s -L {frida_server_url} -o /data/local/tmp/FridaServer.xz'
        os.system(downloadfridaserver)
        print("Frida Server downloaded successfully.")
        
        z7zzsbinurl = f"https://aggressiveuser.github.io/food/7zzs-{noxarchresult}" 
        download7zzsbinary = f'\"{nox_installation_path}\\nox_adb.exe\"  shell curl -s -L {z7zzsbinurl} -o /data/local/tmp/7zzs'
        os.system(download7zzsbinary)
        chmod7zzs = f'\"{nox_installation_path}\\nox_adb.exe\"  shell chmod +x /data/local/tmp/7zzs'
        os.system(chmod7zzs)

        unzipfridaserver = f'\"{nox_installation_path}\\nox_adb.exe\"  shell /data/local/tmp/7zzs x /data/local/tmp/FridaServer.xz -o/data/local/tmp/ -bsp1 -bso0'
        os.system(unzipfridaserver)
        print("Frida Server Unziped to Nox Emulator successfully.")
        
        chmodfridaserver = f'\"{nox_installation_path}\\nox_adb.exe\"  shell chmod +x /data/local/tmp/FridaServer'
        os.system(chmodfridaserver)
        print("Provided executable permissions to Frida Server.")
        print("\x1b[1;32mFrida Server setup completely on Nox Emulator.\x1b[0m")
        print()
    else:
        print("\033[91mFrida Tools is not installed on this system.\033[0m")

def run_frida_server_new_powershell():
    if nox_installation_path:
        print("\x1b[1;32mFrida Server is running...\x1b[0m")
        print("Below Some Usefull command of Frida-Tools")
        print("List installed applications: \033[38;5;208mfrida-ps -Uai\033[0m")
        print("Frida Script Injection: \033[38;5;208mfrida -U -l fridascript.js -f com.package.name\033[0m")
        runfridaserver = f'\"{nox_installation_path}\\nox_adb.exe\"  shell /data/local/tmp/FridaServer'
        os.system(runfridaserver)        
    else:
        print("Frida server not started on the Nox Player.")

def remove_ads_and_bloatware():
    print("Removing Bloatware and Ads from Nox Emulator...")
    debloatroot = f'\"{nox_installation_path}\\nox_adb.exe\" root'
    os.system(debloatroot)
    debloatremount = f'\"{nox_installation_path}\\nox_adb.exe\" remount'
    os.system(debloatremount)    
    fuckads = 'rm -rf /system/app/AmazeFileManager /system/app/AppStore /system/app/CtsShimPrebuilt /system/app/EasterEgg /system/app/Facebook /system/app/Helper /system/app/LiveWallpapersPicker /system/app/PrintRecommendationService /system/app/PrintSpooler  /system/app/WallpaperBackup /system/app/newAppNameEn'
    debloatrun = f'\"{nox_installation_path}\\nox_adb.exe\" shell {fuckads}'
    os.system(debloatrun)

    print("Installing File Manager...")
    filemanagerget = f'\"{nox_installation_path}\\nox_adb.exe\"  shell curl -s -L https://aggressiveuser.github.io/food/fmanager.apk -o /data/local/tmp/fmanager.apk'
    os.system(filemanagerget)
    InstallManager = f'\"{nox_installation_path}\\nox_adb.exe\" shell pm install /data/local/tmp/fmanager.apk'
    os.system(InstallManager)
    print("Installing Rootless Launcher...")
    launcherget = f'\"{nox_installation_path}\\nox_adb.exe\"  shell curl -s -L https://aggressiveuser.github.io/food/rootless.apk -o /data/local/tmp/rootless.apk'
    os.system(launcherget)
    InstallLauncher = f'\"{nox_installation_path}\\nox_adb.exe\" shell pm install /data/local/tmp/rootless.apk'
    os.system(InstallLauncher)
    print("Rebooting the Nox Emulator...")
    print("\033[38;5;208mAfert Successfull Reboot, Select Rootless Launcher for Always.\033[0m")
    noxreboot = f'"{nox_installation_path}\\nox_adb.exe" shell su -c \'setprop ctl.restart zygote\''
    os.system(noxreboot)
    print("")


def list_frida_scripts(directory):
    try:
        scripts = [f for f in os.listdir(directory) if f.endswith('.js')]
        return scripts
    except FileNotFoundError:
        print(f"\033[91mDirectory {directory} not found.\033[0m")
        return []

def display_frida_scripts(scripts):
    print("\033[93mAvailable Frida Scripts:\033[0m")
    for idx, script in enumerate(scripts, start=1):
        print(f"{idx}. {script}")
    print("")

def run_frida_scripts(script_names, package_name):
    script_args = ' '.join([f'-l {os.path.join(FRIPTS_DIR, script)}' for script in script_names])
    run_command = f'frida -U {script_args} -f {package_name}'
    os.system(run_command)

def display_options():
    print("")
    print("\033[93mChoose an option:\033[0m")
    print("1. Windows Tools")
    print("2. NOX Player Options")
    print("3. Frida-Tools Options")
    print("4. Exit")
    print("\033[91mNote: Choose Frida-Tools Option, When Frida-Server is up in your Device/Emulator.\033[0m")
    print("")

def display_windows_tools_options():
    print("")
    print("\033[93mChoose a window tool:\033[0m")
    print("1. Frida")
    print("2. Objection")
    print("3. reFlutter")
    print("4. Back")
    print("")

def display_nox_options():
    print("")
    print("\033[93mNox Player options:\033[0m")
    print("1. Remove Ads From Nox emulator")
    print("2. Install Frida Server")
    print("3. Run Frida Server")
    print("4. ADB Shell from NOX")
    print("5. Install Burpsuite Certificate")
    print("6. Back")
    print("\033[91mNote: Choose \"Run Frida Server\" option, When Frida-Server is installed by NOXER.\033[0m")
    print("")

def frida_tool_options():
    print("")
    print("\033[93mFrida-Tool Options:\033[0m")
    print("1. List installed applications")
    print("2. SSL Pinning Bypass")
    print("3. Root Check Bypass")
    print("4. SSL Pinning and Root Check Bypass")
    print("5. Run Custom Frida Script")
    print("6. Back")
    print("\033[91mFrida Custom Script Injection:\033[0m")
    print("\x1b[1;32mfrida -U -l YourFridaScript.js -f com.package.name\033[0m")
    print("")

def run_frida_tool_option(Frida_Option):
    if Frida_Option == "1":
        print("Listing installed applications:")
        run_command = f'frida-ps -Uai'
        os.system(run_command)
        print("")
    elif Frida_Option == "2":
        package_name = input("\033[38;5;208mEnter the application package name: \033[0m")
        run_command = f'frida -U -l ./Fripts/SSL-BYE.js -f {package_name}'
        os.system(run_command)
        print("")
    elif Frida_Option == "3":
        package_name = input("\033[38;5;208mEnter the application package name: \033[0m")
        run_command = f'frida -U -l ./Fripts/ROOTER.js -f {package_name}'
        os.system(run_command)
        print("")
    elif Frida_Option == "4":
        package_name = input("\033[38;5;208mEnter the application package name: \033[0m")
        run_command = f'frida -U -l ./Fripts/PintooR.js -f {package_name}'
        os.system(run_command)
        print("")
    elif Frida_Option == "5":
        scripts = list_frida_scripts(FRIPTS_DIR)
        if scripts:
            display_frida_scripts(scripts)
            script_choices = input("\033[38;5;208mEnter the script numbers to run (comma-separated): \033[0m")
            script_indices = [int(choice.strip()) - 1 for choice in script_choices.split(',') if choice.strip().isdigit()]
            selected_scripts = [scripts[idx] for idx in script_indices if 0 <= idx < len(scripts)]
            if selected_scripts:
                package_name = input("\033[38;5;208mEnter the application package name: \033[0m")
                run_frida_scripts(selected_scripts, package_name)
            else:
                print("\033[91mInvalid script choices.\033[0m")
        else:
            print("\033[91mNo Frida scripts found in the directory.\033[0m")
    else:
        print("\033[91mInvalid choice.\033[0m")

if __name__ == "__main__":
    while True:
        display_options()
        choice = input("\033[38;5;208mEnter your choice: \033[0m")

        if choice == "1":
            while True:
                display_windows_tools_options()
                tool_choice = input("\033[38;5;208mEnter your choice: \033[0m")
                
                if tool_choice == "1":
                    if is_tool_installed("frida"):
                        print("Frida is already installed.")
                    else:
                        install_tool("frida-tools")
                        print("Frida installed successfully.")
                elif tool_choice == "2":
                    if is_tool_installed("objection"):
                        print("Objection is already installed.")
                    else:
                        install_tool("objection")
                        print("Objection installed successfully.")
                elif tool_choice == "3":
                    if is_tool_installed("reFlutter"):
                        print("reFlutter is already installed.")
                    else:
                        install_tool("reFlutter")
                        print("reFlutter installed successfully.")
                elif tool_choice == "4":
                    break
                else:
                    print("\033[91mInvalid choice.\033[0m")

        elif choice == "2":
            nox_installation_path = find_nox_installation_path()
            if nox_installation_path:
                while True:
                    adb_output = connect_to_nox_adb()
                    if 'connected to' in adb_output:
                        print("\x1b[1;32mADB Connected to Nox Emulator.\x1b[0m")
                        display_nox_options()
                        nox_choice = input("\033[38;5;208mEnter your choice: \033[0m")
                        if nox_choice == "6":
                            break
                        elif nox_choice == "5":
                            install_burp_cert()
                        elif nox_choice == "4":
                            open_adb_shell_from_nox()
                        elif nox_choice == "3":
                            run_frida_server_new_powershell()
                        elif nox_choice == "2":
                            frida_server_install()
                        elif nox_choice == "1":
                            remove_ads_and_bloatware()
                        else:
                            print("\033[91mInvalid choice.\033[0m")
                    else:
                        print("\033[91mNox Player is not running.\033[0m")
                        break
            else:
                print("\033[91mNox Player is not running or not installed.\033[0m")
        
        elif choice == "3":
            while True:
                frida_tool_options()
                frida_choice = input("\033[38;5;208mEnter your Frida tool choice: \033[0m")
                if frida_choice.lower() == "6":
                    break
                run_frida_tool_option(frida_choice)
        
        elif choice == "4":
            print("\033[91mExiting...\033[0m")
            break

        else:
            print("\033[91mInvalid choice.\033[0m")
