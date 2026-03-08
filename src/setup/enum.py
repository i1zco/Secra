from colorama import Fore, Style
import asyncio

async def display_vulnerabilities(cpes):
    if not cpes:
        print(f"{Fore.RED}[-] No CPEs found.{Style.RESET_ALL}")
        return None

    print("=" * 60)

    for idx, cpe in enumerate(cpes, start=1):
        name = getattr(cpe, "cpeName", cpe)
        print(f"{Fore.CYAN}{idx}.{Style.RESET_ALL} {name}")

    print("=" * 60)
    
    choice = await asyncio.to_thread(input, f"{Fore.YELLOW}Select Number (0 Exit): {Style.RESET_ALL}")

    if not choice.isdigit():
        print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
        return None

    choice = int(choice)

    if choice == 0:
        return None

    if choice > len(cpes) or choice < 1:
        print(f"{Fore.RED}Invalid choice.{Style.RESET_ALL}")
        return None

    selected = cpes[choice - 1]
    selected_cpe = getattr(selected, "cpeName", selected)

    return selected_cpe
