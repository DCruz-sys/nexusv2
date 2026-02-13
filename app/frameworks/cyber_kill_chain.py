"""Lockheed Martin Cyber Kill Chain framework."""

KILL_CHAIN_PHASES = [
    {
        "phase": 1,
        "name": "Reconnaissance",
        "description": "Research, identification, and selection of targets. Gathering information about the target through public sources, social engineering, or scanning.",
        "activities": [
            "Harvest email addresses and employee names",
            "Identify internet-facing systems and services",
            "DNS enumeration and subdomain discovery",
            "Technology stack fingerprinting",
            "Social media intelligence gathering",
            "WHOIS and domain registration lookups",
        ],
        "attack_tactics": ["TA0043"],
        "tools": ["nmap", "amass", "subfinder", "theharvester", "whatweb", "dig", "whois", "dnsrecon", "fierce", "dmitry"],
        "owasp_mapping": ["WSTG-INFO"],
        "countermeasures": [
            "Monitor for scanning activity",
            "Limit public information exposure",
            "Implement rate limiting on public services",
            "Use honeypots for early detection",
        ]
    },
    {
        "phase": 2,
        "name": "Weaponization",
        "description": "Creating or adapting malware payloads paired with exploits. Coupling exploit with backdoor into deliverable payload.",
        "activities": [
            "Create or acquire exploits for identified vulnerabilities",
            "Develop custom malware or modify existing tools",
            "Prepare command and control infrastructure",
            "Create phishing emails or malicious documents",
            "Set up staging servers and redirect infrastructure",
        ],
        "attack_tactics": ["TA0042"],
        "tools": ["metasploit", "searchsploit"],
        "owasp_mapping": [],
        "countermeasures": [
            "Threat intelligence gathering",
            "Malware analysis capabilities",
            "Patch management programs",
            "Vulnerability assessments",
        ]
    },
    {
        "phase": 3,
        "name": "Delivery",
        "description": "Transmission of the weaponized payload to the target environment through email, web, USB, or other vectors.",
        "activities": [
            "Send phishing emails with malicious attachments/links",
            "Exploit public-facing web applications",
            "Compromise trusted websites (watering hole)",
            "Physical delivery via USB or hardware implants",
            "Supply chain compromise",
        ],
        "attack_tactics": ["TA0001"],
        "tools": ["sqlmap", "nikto", "wapiti", "commix", "hydra"],
        "owasp_mapping": ["WSTG-ATHN", "WSTG-INPV"],
        "countermeasures": [
            "Email filtering and sandboxing",
            "Web application firewalls",
            "Network intrusion prevention",
            "User security awareness training",
        ]
    },
    {
        "phase": 4,
        "name": "Exploitation",
        "description": "Triggering the exploit to gain execution on the target system. Taking advantage of a vulnerability to execute code.",
        "activities": [
            "Exploit software vulnerabilities",
            "Execute malicious code via social engineering",
            "Leverage zero-day or known vulnerabilities",
            "Bypass security controls",
            "Escalate privileges",
        ],
        "attack_tactics": ["TA0002", "TA0004"],
        "tools": ["metasploit", "sqlmap", "commix", "searchsploit"],
        "owasp_mapping": ["WSTG-INPV", "WSTG-ATHZ"],
        "countermeasures": [
            "Endpoint detection and response",
            "Application whitelisting",
            "Exploit prevention technology",
            "Regular patching and updates",
        ]
    },
    {
        "phase": 5,
        "name": "Installation",
        "description": "Installing malware or backdoors on the target system to maintain persistent access.",
        "activities": [
            "Install web shells on web servers",
            "Create new user accounts for persistence",
            "Install remote access trojans",
            "Modify startup scripts or scheduled tasks",
            "Install rootkits for stealth",
        ],
        "attack_tactics": ["TA0003"],
        "tools": ["metasploit", "nikto"],
        "owasp_mapping": ["WSTG-CONF"],
        "countermeasures": [
            "File integrity monitoring",
            "Process monitoring",
            "Host-based intrusion detection",
            "Privilege access management",
        ]
    },
    {
        "phase": 6,
        "name": "Command & Control",
        "description": "Establishing a command channel with the compromised system for remote manipulation.",
        "activities": [
            "Establish encrypted C2 channels",
            "Use common protocols (HTTP/S, DNS) to blend in",
            "Implement fallback communication channels",
            "Set up proxy chains for anonymity",
            "Use domain fronting or CDN redirectors",
        ],
        "attack_tactics": ["TA0011"],
        "tools": ["metasploit", "wireshark", "tcpdump", "bettercap"],
        "owasp_mapping": [],
        "countermeasures": [
            "Network segmentation",
            "DNS monitoring and filtering",
            "SSL/TLS inspection",
            "Outbound traffic analysis",
        ]
    },
    {
        "phase": 7,
        "name": "Actions on Objectives",
        "description": "Executing the final goal of the intrusion - data exfiltration, destruction, or other malicious activities.",
        "activities": [
            "Collect and exfiltrate sensitive data",
            "Lateral movement to additional systems",
            "Privilege escalation to domain admin",
            "Data manipulation or destruction",
            "Deploy ransomware or wipers",
            "Maintain long-term persistent access",
        ],
        "attack_tactics": ["TA0009", "TA0010", "TA0040", "TA0008"],
        "tools": ["metasploit", "enum4linux", "wireshark"],
        "owasp_mapping": ["WSTG-ATHZ", "WSTG-BUSL"],
        "countermeasures": [
            "Data loss prevention",
            "Network monitoring and SIEM",
            "Incident response procedures",
            "Data backup and recovery",
        ]
    },
]


def get_all_phases():
    return [{"phase": p["phase"], "name": p["name"], "description": p["description"]}
            for p in KILL_CHAIN_PHASES]


def get_phase(phase_number: int):
    for p in KILL_CHAIN_PHASES:
        if p["phase"] == phase_number:
            return p
    return None


def get_phase_by_name(name: str):
    for p in KILL_CHAIN_PHASES:
        if p["name"].lower() == name.lower():
            return p
    return None
