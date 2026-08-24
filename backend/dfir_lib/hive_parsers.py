import os
import codecs
import struct
from datetime import datetime, timezone
from Registry import Registry


# --- UTILITY: WINDOWS FILETIME CONVERTER ---
def filetime_to_utc(ft):
    """Converts 64-bit Windows FILETIME (100-ns intervals since 1601) to UTC string."""
    if not ft or ft == 0:
        return "1601-01-01 00:00:00+00:00"
    try:
        us = (ft - 116444736000000000) // 10
        dt = datetime.fromtimestamp(us / 1000000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S+00:00")
    except Exception:
        return "1601-01-01 00:00:00+00:00"


def safe_timestamp(key):
    """Safely extracts key timestamp formatted as UTC ISO string."""
    try:
        return key.timestamp().strftime("%Y-%m-%d %H:%M:%S+00:00")
    except Exception:
        return "1601-01-01 00:00:00+00:00"


# --- 1. NTUSER.DAT PARSER ---
def parse_ntuser(reg):
    """Parses NTUSER.DAT for UserAssist GUI execution history and User AutoRuns."""
    events = []

    # 1A. UserAssist (ROT13 Decoded Execution)
    ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try:
        ua_key = reg.open(ua_path)
        for guid_key in ua_key.subkeys():
            try:
                count_key = guid_key.subkey("Count")
                for val in count_key.values():
                    decoded_name = codecs.decode(val.name(), 'rot_13')
                    val_data = val.value()
                    
                    if isinstance(val_data, bytes) and len(val_data) >= 68:
                        run_count = struct.unpack_from("<I", val_data, 4)[0]
                        ft = struct.unpack_from("<Q", val_data, 60)[0]
                        timestamp = filetime_to_utc(ft)
                        
                        if run_count > 0:
                            events.append({
                                "timestamp": timestamp,
                                "event_id": 1,
                                "product": "windows",
                                "category": "process_creation",
                                "Image": decoded_name,
                                "CommandLine": f"Execution Count: {run_count}",
                                "ProcessId": "0",
                                "ParentProcessId": "0",
                                "User": "NTUSER_User",
                                "TargetObject": f"UserAssist\\{decoded_name}",
                                "Details": f"RunCount: {run_count}",
                                "sigma_alerts": []
                            })
            except Exception:
                continue
    except Exception:
        pass

    # 1B. User Persistence (Run / RunOnce)
    for path in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]:
        try:
            key = reg.open(path)
            last_write = safe_timestamp(key)
            for val in key.values():
                events.append({
                    "timestamp": last_write,
                    "event_id": 13,
                    "product": "windows",
                    "category": "registry_set",
                    "TargetObject": f"HKCU\\{path}\\{val.name()}",
                    "Details": str(val.value()),
                    "EventType": "SetValue",
                    "User": "NTUSER_User",
                    "sigma_alerts": []
                })
        except Exception:
            pass

    return events


# --- 2. SOFTWARE HIVE PARSER ---
def parse_software(reg):
    """Parses SOFTWARE hive for IFEO Debugger backdoors, AutoRuns, and Defender exclusions."""
    events = []

    # 2A. Image File Execution Options (IFEO) Debugger Hijacks
    ifeo_path = r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        key = reg.open(ifeo_path)
        for binary in key.subkeys():
            bin_name = binary.name()
            last_write = safe_timestamp(binary)
            for val in binary.values():
                if val.name().lower() == "debugger":
                    events.append({
                        "timestamp": last_write,
                        "event_id": 13,
                        "product": "windows",
                        "category": "registry_set",
                        "ParentImage": bin_name,
                        "TargetObject": f"HKLM\\SOFTWARE\\{ifeo_path}\\{bin_name}\\Debugger",
                        "Details": f"Debugger Attach -> {val.value()}",
                        "EventType": "SetValue",
                        "sigma_alerts": []
                    })
    except Exception:
        pass

    # 2B. Machine AutoRuns
    for path in [r"Microsoft\Windows\CurrentVersion\Run", r"Microsoft\Windows\CurrentVersion\RunOnce"]:
        try:
            key = reg.open(path)
            last_write = safe_timestamp(key)
            for val in key.values():
                events.append({
                    "timestamp": last_write,
                    "event_id": 13,
                    "product": "windows",
                    "category": "registry_set",
                    "TargetObject": f"HKLM\\SOFTWARE\\{path}\\{val.name()}",
                    "Details": str(val.value()),
                    "EventType": "SetValue",
                    "sigma_alerts": []
                })
        except Exception:
            pass

    # 2C. Windows Defender Exclusions
    for path in [r"Microsoft\Windows Defender\Exclusions\Paths", r"Microsoft\Windows Defender\Exclusions\Processes"]:
        try:
            key = reg.open(path)
            last_write = safe_timestamp(key)
            for val in key.values():
                events.append({
                    "timestamp": last_write,
                    "event_id": 13,
                    "product": "windows",
                    "category": "registry_set",
                    "TargetObject": f"HKLM\\SOFTWARE\\{path}\\{val.name()}",
                    "Details": "Defender Exclusion Enabled",
                    "EventType": "SetValue",
                    "sigma_alerts": []
                })
        except Exception:
            pass

    return events


# --- 3. SYSTEM HIVE PARSER ---
def parse_system(reg):
    """Parses SYSTEM hive for Services, Drivers, and BootExecute persistence."""
    events = []

    # 3A. Service & Driver Installations
    for control_set in ["ControlSet001", "CurrentControlSet"]:
        services_path = f"{control_set}\\Services"
        try:
            key = reg.open(services_path)
            for service in key.subkeys():
                svc_name = service.name()
                last_write = safe_timestamp(service)
                image_path = ""
                start_type = ""

                for val in service.values():
                    v_name = val.name().lower()
                    if v_name == "imagepath":
                        image_path = str(val.value())
                    elif v_name == "start":
                        start_type = str(val.value())

                if image_path:
                    events.append({
                        "timestamp": last_write,
                        "event_id": 7045,
                        "product": "windows",
                        "category": "service_creation",
                        "ServiceName": svc_name,
                        "ServiceFileName": image_path,
                        "TargetObject": f"HKLM\\SYSTEM\\{services_path}\\{svc_name}",
                        "Details": f"ImagePath: {image_path} | StartType: {start_type}",
                        "sigma_alerts": []
                    })
        except Exception:
            pass

    return events


# --- 4. SAM HIVE PARSER (ACCOUNT ENUMERATION & RID HIJACKING) ---
def parse_sam(reg):
    """Parses SAM hive for local accounts, account names, and RID Hijacking attacks."""
    events = []

    # Try root path variations depending on hive structure
    possible_paths = [
        r"Domains\Account\Users",
        r"SAM\Domains\Account\Users",
        r"Account\Users"
    ]

    users_key = None
    for path in possible_paths:
        try:
            users_key = reg.open(path)
            break
        except Exception:
            continue

    if not users_key:
        return events

    # 4A. Resolve Hex RIDs to Actual Usernames via 'Names' Subkey
    rid_to_name = {}
    try:
        names_key = users_key.subkey("Names")
        for name_subkey in names_key.subkeys():
            username = name_subkey.name()
            for val in name_subkey.values():
                if val.name() == "":
                    rid_to_name[val.value_type()] = username
    except Exception:
        pass

    # 4B. Enumerate User RID Subkeys & Check for RID Hijacking
    for user_key in users_key.subkeys():
        account_hex = user_key.name()
        if account_hex.lower() == "names":
            continue

        last_write = safe_timestamp(user_key)

        try:
            account_rid = int(account_hex, 16)
            username = rid_to_name.get(account_rid, f"Account_0x{account_hex}")
        except ValueError:
            continue

        try:
            # Extract binary 'F' value to inspect Effective RID
            f_val = user_key.value("F").value()
            effective_rid = account_rid
            if isinstance(f_val, bytes) and len(f_val) >= 52:
                effective_rid = struct.unpack_from("<I", f_val, 48)[0]

            # RID Hijack Detection: Non-Admin account (RID != 500) mapped to Admin (RID 500)
            if account_rid != 500 and effective_rid == 500:
                details_msg = f"CRITICAL: RID Hijacking Detected! Account '{username}' (RID {account_rid}) elevated to Administrator (RID 500)"
            else:
                details_msg = f"Account Name: {username} | Account RID: {account_rid} | Effective RID: {effective_rid}"

            events.append({
                "timestamp": last_write,
                "event_id": 4720,
                "product": "windows",
                "category": "user_account_management",
                "User": username,
                "TargetObject": f"HKLM\\SAM\\Domains\\Account\\Users\\{account_hex}",
                "Details": details_msg,
                "sigma_alerts": []
            })
        except Exception:
            continue

    return events


# --- 5. DEFAULT HIVE PARSER ---
def parse_default(reg):
    """Parses DEFAULT profile registry hive for root user persistence."""
    events = []
    for path in [r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]:
        try:
            key = reg.open(path)
            last_write = safe_timestamp(key)
            for val in key.values():
                events.append({
                    "timestamp": last_write,
                    "event_id": 13,
                    "product": "windows",
                    "category": "registry_set",
                    "TargetObject": f"HKU\\.DEFAULT\\{path}\\{val.name()}",
                    "Details": str(val.value()),
                    "EventType": "SetValue",
                    "User": "DEFAULT_PROFILE",
                    "sigma_alerts": []
                })
        except Exception:
            pass
    return events


# --- 6. AMCACHE.HVE PARSER ---
def parse_amcache(reg):
    """Parses AMCACHE.HVE for executable execution evidence and SHA1 hashes."""
    events = []
    app_path = r"Root\InventoryApplicationFile"
    try:
        key = reg.open(app_path)
        for app in key.subkeys():
            last_write = safe_timestamp(app)
            file_name, file_path, sha1 = "", "", ""

            for val in app.values():
                v_name = val.name().lower()
                if v_name == "name":
                    file_name = str(val.value())
                elif v_name == "lowerpath":
                    file_path = str(val.value())
                elif v_name == "fileid":
                    sha1 = str(val.value())

            if file_name or file_path:
                events.append({
                    "timestamp": last_write,
                    "event_id": 1,
                    "product": "windows",
                    "category": "process_creation",
                    "Image": file_path or file_name,
                    "Hashes": f"SHA1={sha1}",
                    "TargetObject": f"Amcache\\{app.name()}",
                    "Details": f"File: {file_name} | Path: {file_path} | SHA1: {sha1}",
                    "sigma_alerts": []
                })
    except Exception:
        pass
    return events


# --- DISPATCHER ENGINE ---
def parse_registry_hive(hive_path):
    """Auto-detects registry hive type and routes to the correct specialized parser."""
    if not os.path.exists(hive_path):
        return []

    try:
        reg = Registry.Registry(hive_path)
        hive_name = os.path.basename(hive_path).upper()
        hive_type = reg.hive_type().name.upper()
        
        print(f"[*] Parsing Hive: {os.path.basename(hive_path)} (Type: {hive_type})")

        if "NTUSER" in hive_name or "NTUSER" in hive_type:
            return parse_ntuser(reg)
        elif "SOFTWARE" in hive_name or "SOFTWARE" in hive_type:
            return parse_software(reg)
        elif "SYSTEM" in hive_name or "SYSTEM" in hive_type:
            return parse_system(reg)
        elif "SAM" in hive_name or "SAM" in hive_type:
            return parse_sam(reg)
        elif "DEFAULT" in hive_name or "DEFAULT" in hive_type:
            return parse_default(reg)
        elif "AMCACHE" in hive_name or "AMCACHE" in hive_type:
            return parse_amcache(reg)

    except Exception as e:
        print(f"[!] Registry parsing error on {hive_path}: {e}")

    return []
