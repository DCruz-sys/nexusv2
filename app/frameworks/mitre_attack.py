"""MITRE ATT&CK Enterprise Framework - tactics and techniques."""

ATTACK_TACTICS = [
    {
        "id": "TA0043",
        "name": "Reconnaissance",
        "description": "The adversary is trying to gather information they can use to plan future operations.",
        "kill_chain_phase": "reconnaissance",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "subtechniques": ["T1595.001 Scanning IP Blocks", "T1595.002 Vulnerability Scanning", "T1595.003 Wordlist Scanning"], "tools": ["nmap", "masscan", "nikto"]},
            {"id": "T1592", "name": "Gather Victim Host Information", "subtechniques": ["T1592.001 Hardware", "T1592.002 Software", "T1592.003 Firmware", "T1592.004 Client Configurations"], "tools": ["nmap", "whatweb"]},
            {"id": "T1589", "name": "Gather Victim Identity Information", "subtechniques": ["T1589.001 Credentials", "T1589.002 Email Addresses", "T1589.003 Employee Names"], "tools": ["theharvester", "dmitry"]},
            {"id": "T1590", "name": "Gather Victim Network Information", "subtechniques": ["T1590.001 Domain Properties", "T1590.002 DNS", "T1590.003 Network Trust Dependencies", "T1590.004 Network Topology", "T1590.005 IP Addresses", "T1590.006 Network Security Appliances"], "tools": ["dnsrecon", "amass", "dig", "fierce"]},
            {"id": "T1591", "name": "Gather Victim Org Information", "subtechniques": ["T1591.001 Determine Physical Locations", "T1591.002 Business Relationships", "T1591.003 Identify Business Tempo", "T1591.004 Identify Roles"], "tools": ["theharvester", "whois"]},
            {"id": "T1598", "name": "Phishing for Information", "subtechniques": ["T1598.001 Spearphishing Service", "T1598.002 Spearphishing Attachment", "T1598.003 Spearphishing Link"], "tools": []},
            {"id": "T1597", "name": "Search Closed Sources", "subtechniques": ["T1597.001 Threat Intel Vendors", "T1597.002 Purchase Technical Data"], "tools": ["searchsploit"]},
            {"id": "T1596", "name": "Search Open Technical Databases", "subtechniques": ["T1596.001 DNS/Passive DNS", "T1596.002 WHOIS", "T1596.003 Digital Certificates", "T1596.004 CDNs", "T1596.005 Scan Databases"], "tools": ["whois", "dig", "sslscan"]},
            {"id": "T1593", "name": "Search Open Websites/Domains", "subtechniques": ["T1593.001 Social Media", "T1593.002 Search Engines", "T1593.003 Code Repositories"], "tools": ["theharvester"]},
            {"id": "T1594", "name": "Search Victim-Owned Websites", "subtechniques": [], "tools": ["whatweb", "curl"]},
        ]
    },
    {
        "id": "TA0042",
        "name": "Resource Development",
        "description": "The adversary is trying to establish resources they can use to support operations.",
        "kill_chain_phase": "weaponization",
        "techniques": [
            {"id": "T1583", "name": "Acquire Infrastructure", "subtechniques": ["T1583.001 Domains", "T1583.002 DNS Server", "T1583.003 Virtual Private Server", "T1583.004 Server", "T1583.006 Web Services"], "tools": []},
            {"id": "T1586", "name": "Compromise Accounts", "subtechniques": ["T1586.001 Social Media Accounts", "T1586.002 Email Accounts", "T1586.003 Cloud Accounts"], "tools": []},
            {"id": "T1584", "name": "Compromise Infrastructure", "subtechniques": ["T1584.001 Domains", "T1584.002 DNS Server", "T1584.004 Server"], "tools": []},
            {"id": "T1587", "name": "Develop Capabilities", "subtechniques": ["T1587.001 Malware", "T1587.002 Code Signing Certificates", "T1587.003 Digital Certificates", "T1587.004 Exploits"], "tools": ["metasploit", "searchsploit"]},
            {"id": "T1585", "name": "Establish Accounts", "subtechniques": ["T1585.001 Social Media Accounts", "T1585.002 Email Accounts", "T1585.003 Cloud Accounts"], "tools": []},
            {"id": "T1588", "name": "Obtain Capabilities", "subtechniques": ["T1588.001 Malware", "T1588.002 Tool", "T1588.003 Code Signing Certificates", "T1588.005 Exploits", "T1588.006 Vulnerabilities"], "tools": ["searchsploit"]},
        ]
    },
    {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network.",
        "kill_chain_phase": "delivery",
        "techniques": [
            {"id": "T1189", "name": "Drive-by Compromise", "subtechniques": [], "tools": ["nikto", "wapiti"]},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "subtechniques": [], "tools": ["sqlmap", "nikto", "wapiti", "commix", "searchsploit"]},
            {"id": "T1133", "name": "External Remote Services", "subtechniques": [], "tools": ["nmap", "hydra"]},
            {"id": "T1200", "name": "Hardware Additions", "subtechniques": [], "tools": []},
            {"id": "T1566", "name": "Phishing", "subtechniques": ["T1566.001 Spearphishing Attachment", "T1566.002 Spearphishing Link", "T1566.003 Spearphishing via Service"], "tools": []},
            {"id": "T1091", "name": "Replication Through Removable Media", "subtechniques": [], "tools": []},
            {"id": "T1195", "name": "Supply Chain Compromise", "subtechniques": ["T1195.001 Compromise Software Dependencies", "T1195.002 Compromise Software Supply Chain"], "tools": []},
            {"id": "T1199", "name": "Trusted Relationship", "subtechniques": [], "tools": ["nmap"]},
            {"id": "T1078", "name": "Valid Accounts", "subtechniques": ["T1078.001 Default Accounts", "T1078.002 Domain Accounts", "T1078.003 Local Accounts", "T1078.004 Cloud Accounts"], "tools": ["hydra", "medusa"]},
        ]
    },
    {
        "id": "TA0002",
        "name": "Execution",
        "description": "The adversary is trying to run malicious code.",
        "kill_chain_phase": "exploitation",
        "techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "subtechniques": ["T1059.001 PowerShell", "T1059.002 AppleScript", "T1059.003 Windows Command Shell", "T1059.004 Unix Shell", "T1059.005 Visual Basic", "T1059.006 Python", "T1059.007 JavaScript"], "tools": ["metasploit", "commix"]},
            {"id": "T1203", "name": "Exploitation for Client Execution", "subtechniques": [], "tools": ["metasploit", "searchsploit"]},
            {"id": "T1047", "name": "Windows Management Instrumentation", "subtechniques": [], "tools": ["metasploit"]},
            {"id": "T1053", "name": "Scheduled Task/Job", "subtechniques": ["T1053.001 At", "T1053.002 Cron", "T1053.005 Scheduled Task"], "tools": ["metasploit"]},
            {"id": "T1204", "name": "User Execution", "subtechniques": ["T1204.001 Malicious Link", "T1204.002 Malicious File", "T1204.003 Malicious Image"], "tools": []},
        ]
    },
    {
        "id": "TA0003",
        "name": "Persistence",
        "description": "The adversary is trying to maintain their foothold.",
        "kill_chain_phase": "installation",
        "techniques": [
            {"id": "T1098", "name": "Account Manipulation", "subtechniques": ["T1098.001 Additional Cloud Credentials", "T1098.002 Additional Email Delegate Permissions", "T1098.003 Additional Cloud Roles"], "tools": ["metasploit"]},
            {"id": "T1136", "name": "Create Account", "subtechniques": ["T1136.001 Local Account", "T1136.002 Domain Account", "T1136.003 Cloud Account"], "tools": ["metasploit"]},
            {"id": "T1505", "name": "Server Software Component", "subtechniques": ["T1505.003 Web Shell"], "tools": ["nikto", "dirb"]},
            {"id": "T1078", "name": "Valid Accounts", "subtechniques": [], "tools": ["hydra"]},
        ]
    },
    {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "description": "The adversary is trying to gain higher-level permissions.",
        "kill_chain_phase": "exploitation",
        "techniques": [
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "subtechniques": ["T1548.001 Setuid and Setgid", "T1548.002 Bypass User Account Control", "T1548.003 Sudo and Sudo Caching"], "tools": ["metasploit"]},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "subtechniques": [], "tools": ["metasploit", "searchsploit"]},
            {"id": "T1078", "name": "Valid Accounts", "subtechniques": [], "tools": ["hydra"]},
        ]
    },
    {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "The adversary is trying to avoid being detected.",
        "kill_chain_phase": "exploitation",
        "techniques": [
            {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "subtechniques": [], "tools": ["binwalk"]},
            {"id": "T1070", "name": "Indicator Removal", "subtechniques": ["T1070.001 Clear Windows Event Logs", "T1070.002 Clear Linux or Mac System Logs", "T1070.003 Clear Command History", "T1070.004 File Deletion"], "tools": ["metasploit"]},
            {"id": "T1036", "name": "Masquerading", "subtechniques": ["T1036.001 Invalid Code Signature", "T1036.005 Match Legitimate Name or Location"], "tools": []},
            {"id": "T1027", "name": "Obfuscated Files or Information", "subtechniques": ["T1027.001 Binary Padding", "T1027.002 Software Packing"], "tools": ["binwalk"]},
        ]
    },
    {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "The adversary is trying to steal account names and passwords.",
        "kill_chain_phase": "exploitation",
        "techniques": [
            {"id": "T1110", "name": "Brute Force", "subtechniques": ["T1110.001 Password Guessing", "T1110.002 Password Cracking", "T1110.003 Password Spraying", "T1110.004 Credential Stuffing"], "tools": ["hydra", "medusa", "john", "hashcat"]},
            {"id": "T1555", "name": "Credentials from Password Stores", "subtechniques": ["T1555.001 Keychain", "T1555.003 Credentials from Web Browsers"], "tools": ["metasploit"]},
            {"id": "T1557", "name": "Adversary-in-the-Middle", "subtechniques": ["T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay"], "tools": ["responder", "bettercap"]},
            {"id": "T1040", "name": "Network Sniffing", "subtechniques": [], "tools": ["wireshark", "tcpdump"]},
            {"id": "T1003", "name": "OS Credential Dumping", "subtechniques": ["T1003.001 LSASS Memory", "T1003.002 Security Account Manager", "T1003.003 NTDS"], "tools": ["metasploit"]},
        ]
    },
    {
        "id": "TA0007",
        "name": "Discovery",
        "description": "The adversary is trying to figure out your environment.",
        "kill_chain_phase": "exploitation",
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "subtechniques": [], "tools": ["nmap", "masscan"]},
            {"id": "T1135", "name": "Network Share Discovery", "subtechniques": [], "tools": ["enum4linux", "nmap"]},
            {"id": "T1018", "name": "Remote System Discovery", "subtechniques": [], "tools": ["nmap", "masscan"]},
            {"id": "T1082", "name": "System Information Discovery", "subtechniques": [], "tools": ["nmap"]},
            {"id": "T1016", "name": "System Network Configuration Discovery", "subtechniques": ["T1016.001 Internet Connection Discovery"], "tools": ["nmap"]},
            {"id": "T1049", "name": "System Network Connections Discovery", "subtechniques": [], "tools": ["nmap", "netcat"]},
        ]
    },
    {
        "id": "TA0008",
        "name": "Lateral Movement",
        "description": "The adversary is trying to move through your environment.",
        "kill_chain_phase": "exploitation",
        "techniques": [
            {"id": "T1210", "name": "Exploitation of Remote Services", "subtechniques": [], "tools": ["metasploit", "searchsploit"]},
            {"id": "T1534", "name": "Internal Spearphishing", "subtechniques": [], "tools": []},
            {"id": "T1570", "name": "Lateral Tool Transfer", "subtechniques": [], "tools": ["metasploit"]},
            {"id": "T1021", "name": "Remote Services", "subtechniques": ["T1021.001 Remote Desktop Protocol", "T1021.002 SMB/Windows Admin Shares", "T1021.004 SSH"], "tools": ["hydra", "metasploit", "nmap"]},
        ]
    },
    {
        "id": "TA0009",
        "name": "Collection",
        "description": "The adversary is trying to gather data of interest to their goal.",
        "kill_chain_phase": "actions_on_objectives",
        "techniques": [
            {"id": "T1560", "name": "Archive Collected Data", "subtechniques": ["T1560.001 Archive via Utility"], "tools": []},
            {"id": "T1005", "name": "Data from Local System", "subtechniques": [], "tools": ["metasploit"]},
            {"id": "T1039", "name": "Data from Network Shared Drive", "subtechniques": [], "tools": ["enum4linux"]},
            {"id": "T1114", "name": "Email Collection", "subtechniques": ["T1114.001 Local Email Collection", "T1114.002 Remote Email Collection"], "tools": []},
            {"id": "T1185", "name": "Browser Session Hijacking", "subtechniques": [], "tools": ["bettercap"]},
        ]
    },
    {
        "id": "TA0011",
        "name": "Command and Control",
        "description": "The adversary is trying to communicate with compromised systems to control them.",
        "kill_chain_phase": "actions_on_objectives",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "subtechniques": ["T1071.001 Web Protocols", "T1071.002 File Transfer Protocols", "T1071.003 Mail Protocols", "T1071.004 DNS"], "tools": ["wireshark", "tcpdump"]},
            {"id": "T1573", "name": "Encrypted Channel", "subtechniques": ["T1573.001 Symmetric Cryptography", "T1573.002 Asymmetric Cryptography"], "tools": ["wireshark"]},
            {"id": "T1572", "name": "Protocol Tunneling", "subtechniques": [], "tools": ["nmap", "wireshark"]},
            {"id": "T1090", "name": "Proxy", "subtechniques": ["T1090.001 Internal Proxy", "T1090.002 External Proxy"], "tools": ["burpsuite"]},
        ]
    },
    {
        "id": "TA0010",
        "name": "Exfiltration",
        "description": "The adversary is trying to steal data.",
        "kill_chain_phase": "actions_on_objectives",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "subtechniques": [], "tools": ["wireshark"]},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "subtechniques": ["T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"], "tools": ["wireshark", "tcpdump"]},
            {"id": "T1567", "name": "Exfiltration Over Web Service", "subtechniques": ["T1567.001 Exfiltration to Code Repository", "T1567.002 Exfiltration to Cloud Storage"], "tools": []},
        ]
    },
    {
        "id": "TA0040",
        "name": "Impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "kill_chain_phase": "actions_on_objectives",
        "techniques": [
            {"id": "T1485", "name": "Data Destruction", "subtechniques": [], "tools": []},
            {"id": "T1486", "name": "Data Encrypted for Impact", "subtechniques": [], "tools": []},
            {"id": "T1489", "name": "Service Stop", "subtechniques": [], "tools": ["nmap"]},
            {"id": "T1498", "name": "Network Denial of Service", "subtechniques": ["T1498.001 Direct Network Flood", "T1498.002 Reflection Amplification"], "tools": []},
            {"id": "T1496", "name": "Resource Hijacking", "subtechniques": [], "tools": ["nmap"]},
            {"id": "T1491", "name": "Defacement", "subtechniques": ["T1491.001 Internal Defacement", "T1491.002 External Defacement"], "tools": []},
        ]
    },
]


def get_all_tactics():
    return [{"id": t["id"], "name": t["name"], "description": t["description"],
             "technique_count": len(t["techniques"])} for t in ATTACK_TACTICS]


def get_tactic(tactic_id: str):
    for t in ATTACK_TACTICS:
        if t["id"] == tactic_id:
            return t
    return None


def get_technique(technique_id: str):
    for tactic in ATTACK_TACTICS:
        for tech in tactic["techniques"]:
            if tech["id"] == technique_id:
                return {**tech, "tactic_id": tactic["id"], "tactic_name": tactic["name"]}
    return None


def get_techniques_by_tool(tool_name: str):
    results = []
    for tactic in ATTACK_TACTICS:
        for tech in tactic["techniques"]:
            if tool_name in tech.get("tools", []):
                results.append({**tech, "tactic_id": tactic["id"], "tactic_name": tactic["name"]})
    return results
