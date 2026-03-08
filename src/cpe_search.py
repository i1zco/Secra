import nvdlib
from rich.progress import track
from rich.console import Console
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
from colorama import Fore, Style

async def search_cpe(search_query, max_results=100):
    print(f"{Fore.CYAN}[*] Searching for: {search_query}{Style.RESET_ALL}")
    query = search_query
    console = Console()
    with console.status("Fetching CPEs...") :
        loop = asyncio.get_event_loop()
        try:
            cpes = await loop.run_in_executor(
                 None,
                 lambda: nvdlib.searchCPE(
                 keywordSearch=query,
                 limit=max_results,
                 )
            )
        except Exception as e:
            return e
    print(f"{Fore.GREEN}[+] Found {len(cpes)} CPEs{Style.RESET_ALL}")
    return cpes
