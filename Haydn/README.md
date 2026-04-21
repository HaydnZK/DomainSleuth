# DomainSleuth: SleuthHound
This component of DomainSleuth is the automated logic engine that parses through data for misconfigurations. SleuthHound is designed to ingest SharpHound JSON data and identify specific, high-impact AD misconfigurations that can lead to privilege escalation, or even domain compromise. 

## Features & Detections
The current version of the script identifies the following vulnerabilities:
- **AS-REP Roasting**: Users that have `dontreqpreauth` set to True.
- **Unconstrained Delegation**: Computer objects trusted to impersonate users across the network. 
- **ACE Abuse**: Identification of dangerous permissions, such as `GenericAll`, `WriteDacl`, and `WriteOwner`. 
- **Machine Account Quota**: Identification of non-zero quotas on the Domain object. 
- **Outdated Operating Systems**: Detection of legacy systems (such as 2008, 2012, and more) based on the OS version strings. 

## Requirements
- **SleuthHound Home**: Ensure SleuthHound.py is properly setup in the appropriate directory with and input and output folder. You can create the home for it with:
```bash
mkdir SleuthHound; cd SleuthHound; mkdir input; mkdir output
```
- **Python 3.x**: Ensure Python is installed and added to your PATH. If you don't have Python setup, you can do so with:
### Windows
1. **Download**: Get the latest installer from python.org
2. **Install**: Run the `.exe`. 
  - **IMPORTANT**: Ensure you check the box that says "Add Python to PATH" at the bottom of the first installer screen. 
2.1 **Manual PATH Check (if you missed the box)**:
  - Search for "Environmental Variable" in the Start menu.
  - Select "Edit the system environment variables."
  - Click Environment Variables > Path > Edit > New
  - Paste your Python installation path (such as `C:\Users\<name>\AppData\Local\Programs\Python\Python314\`). 
4. **Verify**: Open PowerShell and type:
```bash
python --version
```
### Linux (Ubuntu/Debian)
Python is typically pre-installed. To ensure you have the latest version and it's in your path:
1. **Install**: 
```bash
sudo apt update && sudo apt install python3 -y
```

2. **Verify PATH**: Most Linux distros add `/usr/bin/python3` to the PATH automatically. Check this with:
```bash
python3 --version
```

3. **Manual Export (if needed)**: Add this to your `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="$PATH:/usr/bin/python3"
```

- **SharpHound Data**: You must have the output JSON files. These must be extracted from the SharpHound zip and stored in the input directory. SleuthHound utilizes `users.json`, `computers.json`, and `domains.json` by default. 

## Setup and Usage
1. **Preparation**: Ensure your SharpHound JSON files are unzipped and located in the input directory. You can do so using with:
  - **Windows** (Replace `<sharphound_zip> with the appropriate file name. 
  ```bash
  Expand-Archive -Path ".\<sharphound_zip>.zip" -DestinationPath ".\input" -Force
  ```

  - **Linux (Terminal)**: If you don't have `unzip` installed, run `sudo apt install unzip` first. After, run:
  ```bash
  unzip <sharphound_zip>.zip -d ./input
  ```

2. **Run the Script**: In the SleuthHound directory, run the following command:
  - **Windows**:
  ```bash
  python SleuthHound.py
  ```

  - **Linux**:
  ```bash
  python3 SleuthHound.py
  ```


3. **Review Output**: SleuthHound will output a standardized list of vulnerabilities, including the type of risk, source of the risk, and the target object. Each of the five vulnerabilities are output into their own respective file as well as in a centralized `flags.txt` file. You can view these by using:
```bash
cd output && ls
```

## Source Code 
If you would prefer to create the file yourself, you can do so in two simple steps:
1. **Create the file**: In the SleuthHound directory, simply create the file with:
```bash
nano SleuthHound.py
```

2. **Populate the File**: Simply add the following script to your new file:
<details>
<summary>Click to expand SleuthHound.py Source Code</summary>
```python
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

    # --- Save results to separate files ---
    save_flags(excessive_flags, "excessive_permissions.json")
    save_flags(asrep_flags, "asrep_roasting.json")
    save_flags(delegation_flags, "unconstrained_delegation.json")
    save_flags(machine_flags, filename="machine_account_quota.json")
    save_flags(outdated_flags, "outdated_os.json")

if __name__ == "__main__":
    main()
                      
```

</details>

---

## Disclaimer
SleuthHound is intended for authorized security auditing, educational research, and lawful operations only. Unauthorized access to computer systems is illegal. The developers of this tool do not condone or encourage any unlawful use of this script and are not responsible for any misuse or damage caused by this tool. Use responsibly and only on systems you have explicit permission to audit.
