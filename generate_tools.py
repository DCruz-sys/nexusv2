
import subprocess
import json
import re

CATEGORIES = {
    "kali-tools-information-gathering": "information_gathering",
    "kali-tools-vulnerability": "vulnerability_analysis",
    "kali-tools-web": "web_application",
    "kali-tools-database": "database_assessment",
    "kali-tools-passwords": "password_attacks",
    "kali-tools-wireless": "wireless_attacks",
    "kali-tools-reverse-engineering": "reverse_engineering",
    "kali-tools-exploitation": "exploitation_tools",
    "kali-tools-social-engineering": "social_engineering",
    "kali-tools-sniffing-spoofing": "sniffing_spoofing",
    "kali-tools-post-exploitation": "post_exploitation",
    "kali-tools-forensics": "forensics",
    "kali-tools-reporting": "reporting_tools",
}

def get_dependencies(package):
    try:
        cmd = ["apt-cache", "depends", package]
        result = subprocess.run(cmd, capture_output=True, text=True)
        lines = result.stdout.split('\n')
        deps = []
        for line in lines:
            line = line.strip()
            if line.startswith("Depends:"):
                dep = line.split(":", 1)[1].strip()
                # filter out libraries and common packages
                if not dep.startswith("lib") and not dep.startswith("python"):
                    deps.append(dep)
        return deps
    except Exception as e:
        print(f"Error getting deps for {package}: {e}")
        return []

def get_package_info(package_name):
    try:
        cmd = ["apt-cache", "show", package_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        description = "Security tool"
        section = "utils"
        
        for line in result.stdout.split('\n'):
            if line.startswith("Description-en:"):
                description = line.split(":", 1)[1].strip()
                break
            elif line.startswith("Description:"):
                 description = line.split(":", 1)[1].strip()
        
        return {
            "name": package_name,
            "description": description,
        }
    except Exception:
        return {"name": package_name, "description": "Security tool"}

def generate_tools_list():
    tools_list = []
    seen_tools = set()
    
    print("Generating tool list from Kali metapackages...")
    
    for meta_pkg, category in CATEGORIES.items():
        print(f"Processing {meta_pkg} -> {category}...")
        deps = get_dependencies(meta_pkg)
        
        for dep in deps:
            if dep in seen_tools:
                continue
            
            info = get_package_info(dep)
            
            # Determine risk level based on category
            risk = "medium"
            if category in ["exploitation_tools", "password_attacks", "sniffing_spoofing"]:
                risk = "high"
            elif category in ["information_gathering", "forensics", "reporting_tools"]:
                risk = "low"
                
            tool_entry = {
                "name": dep,
                "category": category,
                "description": info["description"][:100].replace('"', "'"),
                "command_template": f"{dep} {{args}} {{target}}",
                "default_args": "--help",
                "risk_level": risk,
                "tags": [category.replace("_", " "), "kali"]
            }
            
            tools_list.append(tool_entry)
            seen_tools.add(dep)
            
    return tools_list

if __name__ == "__main__":
    tools = generate_tools_list()
    
    # Save to json first to inspect
    with open("kali_tools_dump.json", "w") as f:
        json.dump(tools, f, indent=2)
        
    print(f"Generated {len(tools)} tools.")
    
    # Now generate the python file content
    py_content = '"""Kali Linux tool catalog with categorized security tools."""\n\n'
    py_content += 'TOOL_CATEGORIES = {\n'
    for meta, cat in CATEGORIES.items():
        py_content += f'    "{cat}": "{meta.replace("kali-tools-", "").replace("-", " ").title()}",\n'
    py_content += '}\n\n'
    
    py_content += 'KALI_TOOLS = [\n'
    for t in tools:
        py_content += f'    {json.dumps(t)},\n'
    py_content += ']\n\n'
    
    # helper functions
    py_content += """
def get_tools_by_category(category: str) -> list:
    return [t for t in KALI_TOOLS if t["category"] == category]


def get_tool(name: str) -> dict | None:
    for t in KALI_TOOLS:
        if t["name"] == name:
            return t
    return None


def search_tools(query: str) -> list:
    q = query.lower()
    results = []
    for t in KALI_TOOLS:
        if (q in t["name"].lower() or q in t["description"].lower()
                or any(q in tag for tag in t.get("tags", []))):
            results.append(t)
    return results


def get_all_categories() -> dict:
    return TOOL_CATEGORIES
"""

    with open("/home/kali/.gemini/antigravity/scratch/nexus-pentest/app/frameworks/kali_tools.py", "w") as f:
        f.write(py_content)
        
    print("Updated kali_tools.py successfully.")
