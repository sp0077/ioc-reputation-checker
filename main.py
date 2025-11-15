from modules.vt_checker import vt_check
from modules.otx_checker import otx_check
from modules.abuse_checker import abuse_check
from colorama import Fore, Style

def make_safe_for_file(s: str) -> str:
    # Defensive: ensure string can be written, but we prefer utf-8 file encoding below.
    # Replace any problematic control chars if needed.
    return s.replace("\r\n", "\n")

def main():
    print(Fore.CYAN + "=========== IOC REPUTATION CHECKER ===========" + Style.RESET_ALL)
    ioc = input("Enter IP / URL / Hash: ").strip()

    if not ioc:
        print(Fore.RED + "No IOC entered. Exiting." + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + "\nChecking reputation... Please wait...\n" + Style.RESET_ALL)

    vt_result = vt_check(ioc)
    otx_result = otx_check(ioc)
    abuse_result = abuse_check(ioc)

    print(Fore.YELLOW + vt_result + Style.RESET_ALL)
    print(Fore.YELLOW + otx_result + Style.RESET_ALL)
    print(Fore.YELLOW + abuse_result + Style.RESET_ALL)

    # Save to file using UTF-8 encoding to avoid UnicodeEncodeError on Windows
    try:
        with open("report/output.txt", "a", encoding="utf-8") as f:
            f.write("IOC Checked: " + ioc + "\n")
            f.write(make_safe_for_file(vt_result) + "\n")
            f.write(make_safe_for_file(otx_result) + "\n")
            f.write(make_safe_for_file(abuse_result) + "\n")
            f.write("-" * 50 + "\n")
        print(Fore.GREEN + "\nReport saved to report/output.txt" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Failed to write report: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
