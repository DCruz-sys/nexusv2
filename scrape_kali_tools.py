
import requests
import re
import json
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import time

BASE_URL = "https://www.kali.org/tools/all-tools/"
TOOL_URL_PREFIX = "https://www.kali.org/tools/"

async def fetch(session, url):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

async def parse_tool_page(session, tool_name, url):
    html = await fetch(session, url)
    if not html:
        return None

    soup = BeautifulSoup(html, 'html.parser')
    
    # Get description
    # Usually in <div class="card-body"> or first <p> after title
    description = ""
    meta_desc = soup.find("meta", {"name": "description"})
    if meta_desc:
        description = meta_desc["content"]
    
    # Get category/tags if available
    # The structure varies, but we can look for specific sections
    
    # Construct tool entry
    return {
        "name": tool_name,
        "url": url,
        "description": description,
        "category": "unknown", # We might need to infer this or map it
        "command_template": f"{tool_name} {{args}} {{target}}",
        "default_args": "--help",
        "risk_level": "medium", 
        "tags": ["kali", "scraped"]
    }

async def main():
    print("Fetching tool list...")
    async with aiohttp.ClientSession() as session:
        main_page = await fetch(session, BASE_URL)
        if not main_page:
            print("Failed to fetch main page")
            return

        soup = BeautifulSoup(main_page, 'html.parser')
        tool_links = []
        
        # Find all tool links. Based on previous curl, they are in a list.
        # Structure: <li><a href="https://www.kali.org/tools/tool-name/">...</a></li>
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(TOOL_URL_PREFIX) and href != TOOL_URL_PREFIX and href != BASE_URL:
                tool_name = href.replace(TOOL_URL_PREFIX, "").strip("/")
                tool_links.append((tool_name, href))

        # Remove duplicates
        tool_links = list(set(tool_links))
        print(f"Found {len(tool_links)} tools.")

        # Limit for testing if needed, but user said ALL.
        # We will dispatch them in batches to not kill the server/our connection
        
        tools_data = []
        batch_size = 20
        for i in range(0, len(tool_links), batch_size):
            batch = tool_links[i:i+batch_size]
            print(f"Processing batch {i} to {i+len(batch)}...")
            tasks = [parse_tool_page(session, name, url) for name, url in batch]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    tools_data.append(res)
            # small delay
            await asyncio.sleep(0.5)

        print(f"Scraped {len(tools_data)} tools successfully.")
        
        with open("kali_tools_scraped.json", "w") as f:
            json.dump(tools_data, f, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
