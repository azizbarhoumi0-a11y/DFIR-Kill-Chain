import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

def strip_namespace(tag):
    return tag.split('}')[-1] if '}' in tag else tag

def parse_evtx_to_json(evtx_file_path):
    parsed_events = []

    # Extended Event ID Mapping covering the complete Cyber Kill Chain
    EVENT_CATEGORY_MAP = {
        1: "process_creation",          # Execution / Defense Evasion
        4688: "process_creation",       # Windows Process Creation
        3: "network_connection",        # C2 / Lateral Movement
        7: "image_load",                # DLL Hijacking / Loading
        8: "create_remote_thread",      # Process Injection / Privilege Escalation
        10: "process_access",           # Credential Access (e.g., LSASS Dumping)
        11: "file_event",               # Payload Drop / Staging
        12: "registry_add",             # Persistence
        13: "registry_set",             # Persistence / Configuration
        14: "registry_rename",          # Persistence
        22: "dns_query",                # C2 / Exfiltration
        4104: "powershell_block",       # Scriptblock Execution
        7045: "service_creation",       # Persistence / Privilege Escalation
        4697: "service_creation"        # Persistence
    }

    with Evtx(evtx_file_path) as log:
        for record in log.records():
            try:
                xml_data = record.xml()
                root = ET.fromstring(xml_data)

                system_node = next((child for child in root if strip_namespace(child.tag) == 'System'), None)
                if system_node is None:
                    continue

                event_id = None
                time_created = None

                for elem in system_node:
                    tag = strip_namespace(elem.tag)
                    if tag == 'EventID':
                        event_id = int(elem.text) if elem.text else None
                    elif tag == 'TimeCreated':
                        time_created = elem.attrib.get('SystemTime')

                if event_id in EVENT_CATEGORY_MAP:
                    event_data_node = next((child for child in root if strip_namespace(child.tag) == 'EventData'), None)
                    event_data = {}
                    
                    if event_data_node is not None:
                        for data in event_data_node:
                            name = data.attrib.get('Name')
                            if name:
                                event_data[name] = data.text

                    normalized_event = {
                        "timestamp": time_created,
                        "event_id": event_id,
                        "product": "windows",
                        "category": EVENT_CATEGORY_MAP[event_id],
                        
                        # Process Attributes
                        "Image": event_data.get("Image") or event_data.get("NewProcessName") or "",
                        "CommandLine": event_data.get("CommandLine") or "",
                        "ParentImage": event_data.get("ParentImage") or event_data.get("ParentProcessName") or "",
                        "ProcessId": event_data.get("ProcessId") or event_data.get("NewProcessId") or event_data.get("SourceProcessId") or "",
                        "ParentProcessId": event_data.get("ParentProcessId") or "",
                        "User": event_data.get("User") or event_data.get("TargetUserName") or "",
                        
                        # Network & DNS Attributes (C2 / Exfiltration)
                        "DestinationIp": event_data.get("DestinationIp") or "",
                        "DestinationPort": event_data.get("DestinationPort") or "",
                        "DestinationHostname": event_data.get("DestinationHostname") or "",
                        "QueryName": event_data.get("QueryName") or "",
                        
                        # File & Registry Attributes (Persistence / Drops)
                        "TargetFilename": event_data.get("TargetFilename") or "",
                        "TargetObject": event_data.get("TargetObject") or "",
                        "Details": event_data.get("Details") or "",
                        "EventType": event_data.get("EventType") or "",
                        
                        # Credential Access & Injection Attributes
                        "TargetImage": event_data.get("TargetImage") or "",
                        "GrantedAccess": event_data.get("GrantedAccess") or "",
                        "ScriptBlockText": event_data.get("ScriptBlockText") or "",
                        "ServiceName": event_data.get("ServiceName") or "",
                        "ServiceFileName": event_data.get("ImagePath") or event_data.get("ServiceFileName") or "",
                        
                        "sigma_alerts": []
                    }
                    parsed_events.append(normalized_event)

            except Exception:
                continue

    return parsed_events
