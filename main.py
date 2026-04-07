from analyzer import analyze_password

def load_common_passwords(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

def main():
    common_passwords = load_common_passwords("common_passwords.txt")

    password = input("Enter a password to analyze: ").strip()
    result = analyze_password(password, common_passwords)

    print("\nResult")
    print("------")
    print(f"Strength: {result['strength']}")

    if result["issues"]:
        print("Issues:")
        for issue in result["issues"]:
            print(f"- {issue}")
    else:
        print("No issues found.")

if __name__ == "__main__":
    main()
