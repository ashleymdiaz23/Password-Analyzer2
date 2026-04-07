def analyze_password(password: str, common_passwords):
    issues = []

    if len(password) < 12:
        issues.append("Password is under 12 characters.")

    if not any(ch.islower() for ch in password):
        issues.append("Missing a lowercase letter.")

    if not any(ch.isupper() for ch in password):
        issues.append("Missing an uppercase letter.")

    if not any(ch.isdigit() for ch in password):
        issues.append("Missing a number.")

    if not any(not ch.isalnum() for ch in password):
        issues.append("Missing a special character.")

    if password.lower() in common_passwords:
        issues.append("This password is a common/banned password.")

    if len(issues) >= 3:
        strength = "Weak"
    elif len(issues) >= 1:
        strength = "Medium"
    else:
        strength = "Strong"

    return {
        "strength": strength,
        "issues": issues
    }
