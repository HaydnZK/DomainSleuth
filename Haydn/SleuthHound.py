import json
import os
import glob

# Folder paths
INPUT_FOLDER = "input"
OUTPUT_FOLDER = "output"

def load_json_by_type(file_type):
    pattern = os.path.join(INPUT_FOLDER, f"*_{file_type}.json")

    files = glob.glob(pattern)

    if not files:
        raise FileNotFoundError(f"No {file_type}.json file found.")

    latest_file = max(files, key=os.path.getctime)

    print(f"Loading {latest_file}")

    with open(latest_file, 'r') as f:
        data = json.load(f)

    # IMPORTANT: return only the actual objects
    return data.get("data", [])

def save_flags(flags, filename="flags.json"):
    path = os.path.join(OUTPUT_FOLDER, filename)
    with open(path, 'w') as f:
        json.dump(flags, f, indent=4)
    print(f"Flags saved to {path}")

# Vulnerability Number One: Excessive User Rights and Permissions
def check_excessive_permissions(users, flags):

    dangerous_rights = [
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "AllExtendedRights"
    ]

    for user in users:

        properties = user.get("Properties", {})
        username = properties.get("name", "UnknownUser")

        aces = user.get("Aces", [])

        # Use a SET to prevent duplicates
        found_rights = set()

        for ace in aces:

            right = ace.get("RightName")

            if right in dangerous_rights:
                found_rights.add(right)

        # Only add a flag if something dangerous was found
        if found_rights:

            flags.append({
                "user": username,
                "vulnerability": "Excessive Permissions",
                "permissions": list(found_rights),
                "description": f"{username} has dangerous rights: {', '.join(found_rights)}"
            })

# Vulnerability Number Two: Weak Password Policies (AS-REP Roasting)
def check_asrep_roasting(users, flags):

    for user in users:

        properties = user.get("Properties", {})

        username = properties.get("name", "UnknownUser")

        # Check AS-REP flag
        if properties.get("dontreqpreauth") == True:

            flags.append({
                "user": username,
                "vulnerability": "AS-REP Roasting",
                "description": f"{username} does not require Kerberos pre-authentication (AS-REP roastable)."
            })

# Vulnerability Number Three: Unconstrained Delegation
def check_unconstrained_delegation(users, flags):

    for user in users:

        properties = user.get("Properties", {})

        username = properties.get("name", "UnknownUser")

        if properties.get("unconstraineddelegation") == True:

            flags.append({
                "user": username,
                "vulnerability": "Unconstrained Delegation",
                "description": f"{username} has unconstrained delegation enabled (high risk)."
            })

# Vulnerability Number four: Machine Account Quota
def check_machine_account_quota(domains, flags):

    for domain in domains:

        properties = domain.get("Properties", {})

        domain_name = properties.get("name", "UnknownDomain")

        # Look for both naming formats
        quota = (
            properties.get("machineaccountquota")
            or properties.get("ms-DS-MachineAccountQuota")
            or properties.get("ms-ds-machineaccountquota")
            or 0
        )

        # Debug line (temporary)
        # print("DEBUG:", domain_name, quota)

        if quota > 0:

            flags.append({
                "domain": domain_name,
                "vulnerability": "Machine Account Quota",
                "quota": quota,
                "description": f"{domain_name} allows users to create {quota} machine accounts."
            })
# Vulnerability Number Five: Outdated OS
def check_outdated_os(computers, flags):

    outdated_versions = [
        # Vulnerable Systems
        "Windows XP",
        "Windows Vista",
        "Windows 7",
        "Windows 8",
        "Windows 8.1",

        # Vulnerable Servers
        "Windows Server 2003",
        "Windows Server 2008",
        "Windows Server 2008 R2",
        "Windows Server 2012",
        "Windows Server 2012 R2",
        "Windows Server 2016",

        # Vulnerable Non-Windows Systems
        "Ubuntu 14",
        "Ubuntu 16",
        "CentOS 6",
        "CentOS 7"
        ]

    for computer in computers:

        props = computer.get("Properties", {})

        computer_name = props.get("name", "Unknown")
        domain_name = props.get("domain", "UnknownDomain")

        os_name = props.get("operatingsystem")

        # Skip if OS is null
        if not os_name:
            continue

        # print(f"DEBUG: {computer_name} - {os_name}")

        # Check partial match
        for outdated in outdated_versions:

            if outdated in os_name:

                flags.append({
                    "computer": computer_name,
                    "domain": domain_name,
                    "vulnerability": "Outdated OS",
                    "operatingsystem": os_name,
                    "description": f"{computer_name} in {domain_name} is running an outdated OS: {os_name}"
                })

                break

def main():
    # Ensure output folder exists
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    # Load SharpHound data dynamically
    users = load_json_by_type("users")
    computers = load_json_by_type("computers")
    domains = load_json_by_type("domains")

    # print("DEBUG domains length:", len(domains))
    # print("DEBUG domains first item:", domains[0])

    print(f"Loaded {len(users)} users")
    print(f"Loaded {len(computers)} computers")
    print(f"Loaded {len(domains)} domains")

    # --- Separate flags for each vulnerability type ---
    excessive_flags = []
    asrep_flags = []
    delegation_flags = []
    machine_flags = []
    outdated_flags = []

    # --- Run misconfiguration checks ---
    check_excessive_permissions(users, excessive_flags)

    # --- Run AS-REP Check ---
    check_asrep_roasting(users, asrep_flags)

    # --- Run Unconstrained Delegation Check ---
    check_unconstrained_delegation(users, delegation_flags)

    # --- Run Machine Account Quota Check ---
    check_machine_account_quota(domains, machine_flags)

    # --- Run Outdated OS Check ---
    check_outdated_os(computers, outdated_flags)

    # --- Combined Flag  File ---
    all_flags = excessive_flags + asrep_flags + delegation_flags + machine_flags + outdated_flags

    # --- Save results to separate files ---
    save_flags(excessive_flags, "excessive_permissions.json")
    save_flags(asrep_flags, "asrep_roasting.json")
    save_flags(delegation_flags, "unconstrained_delegation.json")
    save_flags(machine_flags, "machine_account_quota.json")
    save_flags(outdated_flags, "outdated_os.json")

    # --- Save the master file ---
    save_flags(all_flags, "flags.json")
    
    print(f"Total vulnerabilities identified: {len(all_flags)}")

if __name__ == "__main__":
    main()
                      
