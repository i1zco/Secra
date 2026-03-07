import sys
from pprint import pprint
import argparse
import asyncio
from colorama import Fore, Style

from module import CVE_Search
from src.setup.enum import display_vulnerabilities
from style.banner import display_banner
from src.cpe_search import search_cpe
from src.Scanner import scan_cpe

# ==============================
# Scan Command
# ==============================
async def run_scan(target: None):

    if target is None:
        return

    display_banner()

    print("=" * 60)
    print(f"{Fore.GREEN}[+] Scanning Target:{Style.RESET_ALL} {target}")
    print("=" * 60)

    cpes = await scan_cpe(target)

    if not cpes:
        print(f"{Fore.RED}[-] No services detected.{Style.RESET_ALL}")
        return

    cpe = await display_vulnerabilities(cpes)
    new_cve = CVE_Search(cpes=cpe, cpe=True)
    cve = await new_cve.check_cpe()
    pprint(cve)

# ==============================
# Search Command
# ==============================
async def run_search(os_name, version=None):

    display_banner()

    if version is None:
       cpes = await search_cpe(os_name, version=None)
       cpe = await display_vulnerabilities(cpes)
       new_cve = CVE_Search(cpes=cpe, cpe=True)
       cve = await new_cve.check_cpe()
       return cve

    print("=" * 60)
    print("Searching CPE Database...")
    print("=" * 60)

    cpes = await search_cpe(os_name, version)
    if not cpes:
        print(f"{Fore.RED}[-] No CPE found.{Style.RESET_ALL}")
        return

    cpe = await display_vulnerabilities(cpes)
    new_cve = CVE_Search(cpes=cpe, cpe=True)
    cve = await new_cve.check_cpe()
    return cve


# ==============================
# Interactive Mode
# ==============================
async def interactive():

    while True:

        display_banner()

        print(f"""{Fore.WHITE}{Style.DIM}

1. Search Vulnerabilities by OS
2. Scan Target IP

""")

        choice = input("Enter Choice: ").strip()

        if choice == "1":

            os_name = input("Enter OS Name: ").lower()
            version = input("Enter Version: ").lower()

            cves = await run_search(os_name, version)
            pprint(cves)

        elif choice == "2":

            target = input("Enter Target IP: ").strip()

            await run_scan(target)

        elif choice == "0":

            print("Good Bye :)")
            sys.exit()

        else:

            print("Invalid option")


# ==============================
# CLI Arguments
# ==============================
async def main():

    parser = argparse.ArgumentParser(
        prog="secra",
        description="Secra Vulnerability Scanner"
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan target IP")
    scan_parser.add_argument("target", help="Target IP address")

    search_parser = subparsers.add_parser("search", help="Search vulnerabilities by OS")
    search_parser.add_argument("os")
    search_parser.add_argument("version", nargs="?")

    args = parser.parse_args()

    if args.command == "scan":
        await run_scan(args.target)

    elif args.command == "search":
        if args.version:
            app = await run_search(args.os, args.version)
            pprint(app)

        else:
            app = await run_search(args.os)
            pprint(app)

    else:
        await interactive()


# ==============================
# Start
# ==============================
if __name__ == "__main__":
     asyncio.run(main())
