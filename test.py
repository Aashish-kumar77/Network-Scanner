# enable_usb_write_protection.py
# This script enables write protection for all USB drives on a Windows system.
# It modifies the Windows Registry and requires administrator privileges to run.

import winreg
import sys
import os

def enable_write_protection():
    """
    Enables write protection for removable storage devices by modifying the registry.
    """
    try:
        # Define the registry key path
        key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"

        # Open the registry key, creating it if it doesn't exist
        # winreg.KEY_SET_VALUE gives write access
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            # If the StorageDevicePolicies key doesn't exist, create it
            control_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control", 0, winreg.KEY_CREATE_SUB_KEY)
            key = winreg.CreateKey(control_key, "StorageDevicePolicies")
            winreg.CloseKey(control_key)

        # Set the WriteProtect DWORD value to 1 (Enabled)
        winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        print("USB write protection enabled successfully.")
        print("You will need to restart your computer for the changes to take full effect.")
        print("To disable, run 'disable_usb_write_protection.py' as administrator.")

    except PermissionError:
        print("Error: Permission denied. Please run this script as an administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if os.name == 'nt': # Check if the operating system is Windows
        # Check if running as administrator
        if sys.platform == "win32":
            try:
                # Attempt to open a key that requires admin rights
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
            except PermissionError:
                print("This script needs to be run with Administrator privileges.")
                input("Press Enter to exit.")
                sys.exit(1)
        enable_write_protection()
    else:
        print("This script is designed for Windows operating systems only.")


# disable_usb_write_protection.py
# This script disables write protection for all USB drives on a Windows system.
# It reverts the Windows Registry setting and requires administrator privileges to run.

import winreg
import sys
import os

def disable_write_protection():
    """
    Disables write protection for removable storage devices by modifying the registry.
    """
    try:
        # Define the registry key path
        key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"

        # Open the registry key
        # winreg.KEY_SET_VALUE gives write access
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            print("The 'StorageDevicePolicies' registry key does not exist or write protection is not enabled.")
            print("No action needed.")
            return

        # Set the WriteProtect DWORD value to 0 (Disabled)
        winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        print("USB write protection disabled successfully.")
        print("You will need to restart your computer for the changes to take full effect.")
        print("To enable, run 'enable_usb_write_protection.py' as administrator.")

    except PermissionError:
        print("Error: Permission denied. Please run this script as an administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if os.name == 'nt': # Check if the operating system is Windows
        # Check if running as administrator
        if sys.platform == "win32":
            try:
                # Attempt to open a key that requires admin rights
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
            except PermissionError:
                print("This script needs to be run with Administrator privileges.")
                input("Press Enter to exit.")
                sys.exit(1)
        disable_write_protection()
    else:
        print("This script is designed for Windows operating systems only.")