import sys
import argparse
import asyncio
from pprint import pprint
from colorama import Fore, Style
from style.banner import display_banner
from module import CVE_Search
from src.Scanner import scan_cpe
from src.setup.enum import display_vulnerabilities
import aiofiles
import json

async def run_scan(target):
    display_banner()
    print(f"{Fore.GREEN}[+] Scanning Target:{Style.RESET_ALL} {target}")
    cpes = await scan_cpe(target)
    if not cpes:
        print(f"{Fore.RED}[-] No services detected.{Style.RESET_ALL}")
        return
    cpe_selected = await display_vulnerabilities(cpes)
    search = CVE_Search(cpes=cpe_selected)
    cves = await search.run_search()
    pprint(cves)
    user_in = input("\nDo You Want Save it in file? (y/n): ")
    if user_in == "y":
        filename = input("Enter File Name (e.g results.json): ")
        async with aiofiles.open(filename, "w", encoding="UTF-8") as f:
              await f.write(json.dumps(cves, indent=4))
              print(f"(+)Result saved to {filename}")
    else:
        print("{*}Result not saved")


async def run_search(vendor=None, product=None, version=None, **kwargs):
    display_banner()
    search = CVE_Search(vendor=vendor, product=product, version=version, **kwargs)
    cves = await search.run_search()
    pprint(cves)
    user_in = input("\nDo You Want Save it in file? (y/n): ")
    if user_in == "y":
        filename = input("Enter File Name (e.g results.json): ")
        async with aiofiles.open(filename, "w", encoding="UTF-8") as f:
              await f.write(json.dumps(cves, indent=4))
              print(f"(+)Result saved to {filename}")
    else:
        print("{*}Result not saved")


async def interactive():
    while True:
        display_banner()
        print(f"""{Fore.WHITE}{Style.DIM}
1. Search Vulnerabilities by OS
2. Scan Target IP
0. Exit
""")
        choice = input("Enter Choice: ").strip()
        if choice == "1":
            product = input("Enter Product: ").lower()
            vendor = input("Enter Vendor (optional): ").lower() or None
            version = input("Enter Version (optional): ").lower() or None
            await run_search(vendor, product, version)
        elif choice == "2":
            target = input("Enter Target IP: ").strip()
            await run_scan(target)
        elif choice == "0":
            print("Good Bye :)")
            sys.exit()
        else:
            print("Invalid option")


async def main():
    parser = argparse.ArgumentParser(prog="secra", description="Secra Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan target IP")
    scan_parser.add_argument("target", help="Target IP address")

    search_parser = subparsers.add_parser("search", help="Search vulnerabilities by OS")
    search_parser.add_argument("product")
    search_parser.add_argument("vendor", nargs="?")
    search_parser.add_argument("--version", required=False)

    args = parser.parse_args()

    if args.command == "scan":
        await run_scan(args.target)
    elif args.command == "search":
        await run_search(args.vendor, args.product, args.version)
    else:
        await interactive()


if __name__ == "__main__":
    asyncio.run(main())
