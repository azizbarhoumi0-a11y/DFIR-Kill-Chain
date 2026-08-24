import os
import sys
import glob
from openai import OpenAI
from sigma.rule import SigmaRule
from sigma_rule_matcher import RuleMatcher
import networkx as nx

from evtx_parser import parse_evtx_to_json
from hive_parsers import parse_registry_hive


# --- 1. FULL-CHAIN SIGMA EVALUATION ENGINE ---
def load_and_evaluate_sigma(events, rules_dir="sigma/rules/windows"):
    """Evaluates telemetry across all Windows Sigma rules (both EVTX and Registry events)."""
    rule_files = (
        glob.glob(f"{rules_dir}/**/*.yml", recursive=True) +
        glob.glob(f"{rules_dir}/**/*.yaml", recursive=True)
    )
    
    if not rule_files:
        print(f"[!] No Sigma rules found in ./{rules_dir}/ directory.")
        return events

    matchers = []
    for r_file in rule_files:
        try:
            with open(r_file, "r", encoding="utf-8") as f:
                yaml_str = f.read().replace("|windash", "")
                rule = SigmaRule.from_yaml(yaml_str)
                matcher = RuleMatcher(rule)
                matchers.append((rule, matcher, r_file))
        except Exception:
            continue

    print(f"[*] Loaded {len(matchers)} Sigma rules across full attack chain categories.")

    default_fields = {
        "Image": "", "CommandLine": "", "ParentImage": "", "ParentCommandLine": "",
        "User": "", "OriginalFileName": "", "Hashes": "", "TargetFilename": "", 
        "TargetObject": "", "Details": "", "DestinationIp": "", "DestinationHostname": "",
        "DestinationPort": "", "QueryName": "", "TargetImage": "", "GrantedAccess": ""
    }

    alert_count = 0
    for event in events:
        eval_event = {**default_fields, **event}

        # Standard pySigma evaluation
        for rule, matcher, r_file in matchers:
            try:
                if matcher.match(eval_event):
                    alert_info = {
                        "title": rule.title,
                        "level": getattr(rule, "level", "medium"),
                        "tags": getattr(rule, "tags", []),
                        "rule_path": os.path.abspath(r_file),
                    }
                    if alert_info not in event["sigma_alerts"]:
                        event["sigma_alerts"].append(alert_info)
                        alert_count += 1
            except Exception:
                continue

    print(f"[*] pySigma triggered {alert_count} alert matches across telemetry.")
    return events


# --- 2. KILL CHAIN ATTACK GRAPH & REGISTRY STATE BUILDER ---
def build_enriched_tree(events):
    """Builds a process execution tree and correlates offline registry state artifacts."""
    G = nx.DiGraph()
    offline_registry_events = []

    # Step A: Separate Process Creation vs Offline State Events
    for event in sorted(events, key=lambda x: x.get('timestamp', '')):
        eid = event.get('event_id')
        pid = str(event.get('ProcessId') or '0')

        if eid in [1, 4688] and pid != '0':
            node_id = f"{pid}_{event.get('Image', 'Unknown')}"
            if not G.has_node(node_id):
                G.add_node(
                    node_id,
                    pid=pid,
                    ppid=str(event.get('ParentProcessId') or '0'),
                    image=event.get('Image') or 'Unknown',
                    cmd=event.get('CommandLine') or '',
                    user=event.get('User') or '',
                    timestamp=event.get('timestamp') or '',
                    alerts=event.get('sigma_alerts', []),
                    network_events=[],
                    file_events=[],
                    registry_events=[],
                    cred_access_events=[],
                    service_events=[]
                )
        else:
            # Standalone / Offline Registry or Service events
            if event.get('TargetObject') or event.get('ServiceName'):
                offline_registry_events.append(event)

    # Step B: Link Parent -> Child Process Hierarchy
    nodes = list(G.nodes(data=True))
    for child_id, child_data in nodes:
        child_ppid = child_data['ppid']
        for parent_id, parent_data in nodes:
            if parent_data['pid'] == child_ppid and parent_data['pid'] != '0':
                G.add_edge(parent_id, child_id)
                break

    # Helper function for formatting Sigma alerts
    def format_alerts(alerts, indent="       "):
        out = ""
        for a in alerts:
            raw_tags = [str(t) for t in a.get('tags', [])]
            tags_str = ", ".join(raw_tags) if raw_tags else "None"
            lvl_obj = a.get('level', 'medium')
            lvl_str = lvl_obj.name if hasattr(lvl_obj, 'name') else str(lvl_obj)
            out += f"{indent}🚨 SIGMA DETECT: [{lvl_str.upper()}] {a['title']}\n"
            out += f"{indent}   └─ MITRE TAGS: {tags_str}\n"
        return out

    # Step C: Render Process Tree
    tree_text = "=== RECONSTRUCTED ATTACK GRAPH & FORENSIC STATE ===\n\n"
    root_nodes = [node for node, in_degree in G.in_degree() if in_degree == 0]

    def print_node_details(n_data, header_prefix="", line_prefix=""):
        text = f"{header_prefix}PROCESS: {n_data['image']} (PID: {n_data['pid']})\n"
        text += f"{line_prefix}├── Timestamp: {n_data['timestamp']}\n"
        text += f"{line_prefix}├── Command  : {n_data['cmd']}\n"
        text += f"{line_prefix}└── User     : {n_data['user']}\n"
        if n_data['alerts']:
            text += format_alerts(n_data['alerts'], indent=f"{line_prefix}    ")
        return text

    if root_nodes:
        tree_text += "--- LIVE PROCESS EXECUTION TREE ---\n"
        for root in root_nodes:
            r_data = G.nodes[root]
            tree_text += print_node_details(r_data, header_prefix="ROOT ", line_prefix="")
            for child in G.successors(root):
                c_data = G.nodes[child]
                tree_text += print_node_details(c_data, header_prefix="    └── CHILD ", line_prefix="        ")
        tree_text += "\n"

    # Step D: Render Offline Registry & System Persistence Section
    if offline_registry_events:
        tree_text += "--- OFFLINE REGISTRY & FORENSIC ARTIFACTS ---\n"
        for reg_evt in offline_registry_events:
            ts = reg_evt.get('timestamp', 'N/A')
            obj = reg_evt.get('TargetObject') or reg_evt.get('ServiceName') or 'Registry Value'
            details = reg_evt.get('Details', '')
            tree_text += f"🔑 REGISTRY/SYSTEM KEY [{ts}]: {obj}\n"
            tree_text += f"   └── Value Data: {details}\n"
            if reg_evt.get('sigma_alerts'):
                tree_text += format_alerts(reg_evt['sigma_alerts'], indent="       ")
        tree_text += "\n"

    return tree_text


# --- 3. FULL KILL-CHAIN SYNTHESIS PROMPT ---
def analyze_with_hybrid_ai(tree_text, model_name="qwen2.5:7b"):
    client = OpenAI(
        base_url="http://localhost:11434/v1",
        api_key="ollama"
    )

    system_prompt = (
        "CRITICAL INSTRUCTION: You MUST write your entire response strictly and exclusively in ENGLISH. "
        "Do NOT output any Chinese characters or non-English text under any circumstances.\n\n"
        "You are a Lead DFIR Threat Hunter analyzing combined process graph telemetry and offline registry hive artifacts.\n"
        "Your task is to synthesize the provided telemetry into an end-to-end Cyber Kill Chain Report.\n\n"
        "REQUIRED REPORT STRUCTURE:\n"
        "1. EXECUTIVE SUMMARY: High-level overview of the incident.\n"
        "2. FULL ATTACK CHAIN CHRONOLOGY: Group evidence explicitly into MITRE ATT&CK tactical phases:\n"
        "   - Initial Access / Execution (UserAssist, Amcache, Process Creation)\n"
        "   - Privilege Escalation / Defense Evasion (IFEO backdoors, SAM RID Hijacking, Defender Exclusions)\n"
        "   - Persistence / Services (Run keys, System Services 7045)\n"
        "   - Command and Control (C2) / Exfiltration (if observed)\n"
        "3. VERIFIED MITRE ATT&CK MATRIX: List technique IDs matching pySigma rule tags and observed behaviors.\n"
        "4. CONTAINMENT & REMEDIATION PLAN: Concrete host-based and registry cleanup steps.\n\n"
        "STRICT CONSTRAINTS:\n"
        "- Base analysis ONLY on observed telemetry nodes in the graph and offline registry entries.\n"
        "- Do NOT invent network C2 connections or persistence unless explicitly present in the text."
    )

    print(f"[*] Querying local model ({model_name})...")
    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": tree_text}
        ],
        temperature=0.1
    )

    return response.choices[0].message.content


# --- MAIN PIPELINE ENTRY POINT ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hybrid_pipeline.py <path_to_evtx_or_dat_file_or_directory>")
        sys.exit(1)

    target_path = sys.argv[1]
    all_events = []

    print("[1/4] Ingesting Forensic Telemetry (EVTX & Registry DAT Hives)...")
    if os.path.isfile(target_path):
        if target_path.lower().endswith(".evtx"):
            all_events.extend(parse_evtx_to_json(target_path))
        else:
            all_events.extend(parse_registry_hive(target_path))
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                full_path = os.path.join(root, file)
                if file.lower().endswith(".evtx"):
                    all_events.extend(parse_evtx_to_json(full_path))
                else:
                    # Attempt parsing DAT/Hive files (NTUSER.DAT, SYSTEM, SOFTWARE, SAM, etc.)
                    all_events.extend(parse_registry_hive(full_path))

    print(f"[*] Total ingested events: {len(all_events)}")

    print("[2/4] Running pySigma Engine across Full Telemetry Set...")
    all_events = load_and_evaluate_sigma(all_events, rules_dir="sigma/rules/windows")

    print("[3/4] Building Multi-Stage Attack & Registry State Graph...")
    tree_text = build_enriched_tree(all_events)
    print("\n" + tree_text)

    print("[4/4] Generating AI Kill Chain Synthesis...")
    report = analyze_with_hybrid_ai(tree_text, model_name="qwen2.5:7b")

    print("\n" + "="*25 + " HYBRID DFIR KILL CHAIN REPORT " + "="*25 + "\n")
    print(report)
