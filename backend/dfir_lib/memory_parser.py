import os
import json
import subprocess


def run_vol3_plugin(mem_path, plugin_name):
    """Executes a Volatility 3 plugin and returns JSON output."""
    # Attempt execution via 'vol' binary or python module wrapper
    commands = [
        ["vol", "-f", mem_path, "-r", "json", plugin_name],
        ["python3", "-m", "volatility3.cli", "-f", mem_path, "-r", "json", plugin_name]
    ]

    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except Exception:
            continue

    print(f"[!] Volatility 3 failed to run plugin: {plugin_name}")
    return []


def parse_memory_dump(mem_path):
    """Extracts process execution, command lines, network sockets, and code injection artifacts."""
    if not os.path.exists(mem_path):
        return []

    print(f"[*] Processing Volatile Memory Dump: {os.path.basename(mem_path)}")
    events = []

    # 1. Map Process Command Lines (windows.cmdline.CmdLine)
    cmdline_data = run_vol3_plugin(mem_path, "windows.cmdline.CmdLine")
    cmd_map = {}
    for item in cmdline_data:
        pid = str(item.get("PID", "0"))
        cmd_map[pid] = item.get("Args", "")

   # 2. Extract Resident Process Tree (Try PsList -> Fallback to PsScan)
    pslist_data = run_vol3_plugin(mem_path, "windows.pslist.PsList")
    if not pslist_data:
        pslist_data = run_vol3_plugin(mem_path, "windows.psscan.PsScan")

    for proc in pslist_data:
        pid = str(proc.get("PID", "0"))
        ppid = str(proc.get("PPID", "0"))
        image = proc.get("ImageFileName", "Unknown")
        created_at = proc.get("CreateTime", "") or "1601-01-01 00:00:00+00:00"

        events.append({
            "timestamp": str(created_at),
            "event_id": 1,
            "product": "windows",
            "category": "process_creation",
            "Image": image,
            "CommandLine": cmd_map.get(pid, f"Memory Executable: {image}"),
            "ProcessId": pid,
            "ParentProcessId": ppid,
            "User": "MEM_RESIDENT",
            "TargetObject": f"RAM\\Process\\{pid}",
            "Details": f"Volatile Memory Process Resident (PID: {pid}, PPID: {ppid})",
            "sigma_alerts": []
        })

    # 3. Extract Volatile Network Connections (windows.netscan.NetScan)
    net_data = run_vol3_plugin(mem_path, "windows.netscan.NetScan")
    for net in net_data:
        pid = str(net.get("PID", "0"))
        foreign_ip = str(net.get("ForeignAddr", ""))
        foreign_port = str(net.get("ForeignPort", ""))
        local_ip = str(net.get("LocalAddr", ""))
        local_port = str(net.get("LocalPort", ""))
        state = str(net.get("State", ""))
        owner = str(net.get("Owner", "Unknown"))
        created_at = net.get("Created", "") or "1601-01-01 00:00:00+00:00"

        if foreign_ip and foreign_ip not in ["0.0.0.0", "::", "*", "-"]:
            events.append({
                "timestamp": str(created_at),
                "event_id": 3,
                "product": "windows",
                "category": "network_connection",
                "Image": owner,
                "ProcessId": pid,
                "DestinationIp": foreign_ip,
                "DestinationPort": foreign_port,
                "SourceIp": local_ip,
                "SourcePort": local_port,
                "Details": f"Active RAM Socket -> {foreign_ip}:{foreign_port} [{state}]",
                "sigma_alerts": []
            })

    # 4. Extract Memory Injection / Hollowed Binaries (windows.malfind.MalFind)
    malfind_data = run_vol3_plugin(mem_path, "windows.malfind.MalFind")
    for mal in malfind_data:
        pid = str(mal.get("PID", "0"))
        process_name = str(mal.get("Process", "Unknown"))
        start_vpn = str(mal.get("StartVpn", ""))
        protection = str(mal.get("Protection", ""))

        events.append({
            "timestamp": "1601-01-01 00:00:00+00:00",
            "event_id": 10,  # Process Tampering / Injected Memory
            "product": "windows",
            "category": "process_tampering",
            "Image": process_name,
            "ProcessId": pid,
            "TargetObject": f"RAM\\InjectedMemory\\{start_vpn}",
            "Details": f"CRITICAL: Unbacked Executable Memory (MalFind)! Protection: {protection} at {start_vpn}",
            "sigma_alerts": []
        })

    return events
