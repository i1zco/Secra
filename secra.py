import sys
import argparse
from colorama import Fore, Style

from style.banner import display_banner
from src.cpe_search import search_cpe
from src.cve_search import search_cve
from src.Scanner import scan_cpe


# ==============================
# Display CPE List and Choose
# ==============================
def display_vulnerabilities(cpes):

    if not cpes:
        print(f"{Fore.RED}[-] No CPEs found.{Style.RESET_ALL}")
        return

    print("=" * 60)

    for idx, cpe in enumerate(cpes, start=1):
        try:
            print(f"{Fore.CYAN}{idx}.{Style.RESET_ALL} {cpe.cpeName}")
        except:
            print(f"{Fore.CYAN}{idx}.{Style.RESET_ALL} {cpe}")

    print("=" * 60)

    try:
        choice = int(input(f"{Fore.YELLOW}Select Number (0 Exit): {Style.RESET_ALL}"))

        if choice == 0:
            return

        if choice > len(cpes):
            print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")
            return

        selected = cpes[choice - 1]

        try:
            selected_cpe = selected.cpeName
        except:
            selected_cpe = selected

        print("=" * 60)
        print(f"{Fore.GREEN}Selected CPE:{Style.RESET_ALL} {selected_cpe}")
        print("=" * 60)

        cves = search_cve(selected_cpe)

        if not cves:
            print(f"{Fore.RED}[-] No vulnerabilities found.{Style.RESET_ALL}")

    except ValueError:
        print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")


# ==============================
# Scan Command
# ==============================
def run_scan(target: None) -> str:

    if target is None:
        return

    display_banner()

    print("=" * 60)
    print(f"{Fore.GREEN}[+] Scanning Target:{Style.RESET_ALL} {target}")
    print("=" * 60)

    cpes = scan_cpe(target)

    if not cpes:
        print(f"{Fore.RED}[-] No services detected.{Style.RESET_ALL}")
        return

    display_vulnerabilities(cpes)


# ==============================
# Search Command
# ==============================
def run_search(os_name, version=None):

    display_banner()

    if version is None:
       cpes = search_cpe(os_name, version=None)
       display_vulnerabilities(cpes)
       return True

    print("=" * 60)
    print("Searching CPE Database...")
    print("=" * 60)

    cpes = search_cpe(os_name, version)
    print(cpes)
    if not cpes:
        print(f"{Fore.RED}[-] No CPE found.{Style.RESET_ALL}")
        return

    display_vulnerabilities(cpes)
    return True


# ==============================
# Interactive Mode
# ==============================
def interactive():

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

            run_search(os_name, version)

        elif choice == "2":

            target = input("Enter Target IP: ").strip()

            run_scan(target)

        elif choice == "0":

            print("Good Bye :)")
            sys.exit()

        else:

            print("Invalid option")


# ==============================
# CLI Arguments
# ==============================
def main():

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
        run_scan(args.target)

    elif args.command == "search":
        if args.version:
            run_search(args.os, args.version)
        else:
            run_search(args.os)

    else:
        interactive()


# ==============================
# Start
# ==============================
if __name__ == "__main__":
     main()
