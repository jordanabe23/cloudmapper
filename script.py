import subprocess
import requests
import json

PVWA_URL = "https://172.31.93.81"
USERNAME = "Jordan"
PASSWORD = "GPSUistheBest1"
SAFE_NAME = "AWSIAM"
GROUP_NAME = "LabDemo"

requests.packages.urllib3.disable_warnings()


def get_cyberark_token():
    url = f"{PVWA_URL}/PasswordVault/api/Auth/CyberArk/Logon"
    headers = {"Content-Type": "application/json"}
    data = {"username": USERNAME, "password": PASSWORD}
    response = requests.post(url, json=data, headers=headers, verify=False)
    return response.text.strip('"')


def get_aws_iam_usernames(group_name):
    result = subprocess.run(
        ["aws", "iam", "get-group", "--group-name", group_name,
         "--query", "Users[*].UserName", "--output", "text"],
        capture_output=True,
        text=True
    )
    return [user.strip() for user in result.stdout.strip().split()]


def get_cyberark_safe_usernames(token, safe_name):
    url = f"{PVWA_URL}/PasswordVault/api/Accounts"
    headers = {
        "Content-Type": "application/json",
        "Authorization": token
    }
    response = requests.get(url, headers=headers, verify=False)
    accounts = response.json().get("value", [])
    return [acct["userName"] for acct in accounts if acct["safeName"] == safe_name]


def get_iam_user_details(username):
    result = subprocess.run(
        ["aws", "iam", "get-user", "--user-name", username],
        capture_output=True,
        text=True
    )
    print(f"\nDEBUG: get-user result for {username}:\n{result.stdout}\n{result.stderr}")
    if result.returncode == 0:
        user = json.loads(result.stdout).get("User", {})
        # Fix bad ARN if needed - handle multiple patterns
        if "Arn" in user:
            original_arn = user["Arn"]
            print(f"DEBUG: Original ARN: {original_arn}")
            
            # Fix various malformed ARN patterns
            if "::aws:" in original_arn:
                # Pattern: arn:aws:iam::aws:user/username
                user["Arn"] = original_arn.replace("::aws:", ":448618645146:")
                print(f"DEBUG: Fixed ARN (::aws: pattern): {original_arn} -> {user['Arn']}")
            elif ":aws:user/" in original_arn and "448618645146" not in original_arn:
                # Pattern: arn:aws:iam:aws:user/username
                user["Arn"] = original_arn.replace(":aws:user/", ":448618645146:user/")
                print(f"DEBUG: Fixed ARN (:aws:user/ pattern): {original_arn} -> {user['Arn']}")
            elif not original_arn.startswith("arn:aws:iam::448618645146:"):
                # Generic fix for any ARN that doesn't have the right account ID
                import re
                # Replace any account ID or missing account with correct one
                fixed_arn = re.sub(r'arn:aws:iam::[^:]*:', 'arn:aws:iam::448618645146:', original_arn)
                if fixed_arn != original_arn:
                    user["Arn"] = fixed_arn
                    print(f"DEBUG: Fixed ARN (generic pattern): {original_arn} -> {user['Arn']}")
        return user
    else:
        return {"UserName": username, "Error": result.stderr.strip()}


# Main logic
token = get_cyberark_token()
aws_users = get_aws_iam_usernames(GROUP_NAME)
cyberark_users = get_cyberark_safe_usernames(token, SAFE_NAME)

missing_users = sorted(set(aws_users) - set(cyberark_users))

print("Users in AWS IAM but not in CyberArk Safe:\n")
for user in missing_users:
    details = get_iam_user_details(user)
    print(json.dumps(details, indent=2))

