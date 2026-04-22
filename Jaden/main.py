import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import ListFlowable, ListItem

REQUIRED_KEYS = ["title", "description", "severity", "impact", "fixes"]


# Severity
SEVERITY_MAP = {
    "DCSync": "Critical",
    "AttackPath": "Critical",
    "GenericAll": "Critical",
    "Kerberoastable": "High",
    "ASREP": "High",
    "UnconstrainedDelegation": "High",
    "WeakPasswordPolicy": "Medium",
    "WeakGroup": "High",
    "InactivePrivilegedAccount": "Medium"
}

MITRE_MAP = {
    "Kerberoastable": "T1558.003",
    "ASREP": "T1558.004",
    "DCSync": "T1003.006",
    "GenericAll": "T1098",
    "UnconstrainedDelegation": "T1550",
    "WeakGroup": "TI069"
}

CONFIDENCE_MAP = {
    "DCSync": "High",
    "AttackPath": "High",
    "GenericAll": "High",
    "Kerberoastable": "Medium",
    "ASREP": "Medium",
    "UnconstrainedDelegation": "Medium",
    "WeakGroup": "Medium"
}


def get_severity(finding_type):
    return SEVERITY_MAP.get(finding_type, "Medium")

# Validate
def validate_result(r):
    if not isinstance(r, dict):
        return False

    for key in REQUIRED_KEYS:
        if key not in r or r[key] is None:
            return False

    if not isinstance(r["fixes"], list):
        return False

    return True


def deduplicate(results):
    seen = set()
    unique = []
    for r in results:
        key = (r["title"], r["description"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


#Summary
def build_summary(results, attack_paths):
    critical = sum(1 for r in results if r["severity"] == "Critical")
    high = sum(1 for r in results if r["severity"] == "High")

    return [
        f"Total Findings: {len(results)}",
        f"Critical: {critical}, High: {high}",
        f"Attack Paths Identified: {len(attack_paths)}"
    ]


def top_fixes(results):
    return [
        r["title"] for r in results if r["severity"] == "Critical"
    ][:3]


# Priority
def prioritize(results):
    order = {"Critical": 0, "High": 1, "Medium": 2}
    return sorted(results, key=lambda x: order[x["severity"]])


# Remediation
def get_remediation(finding):
    if finding["type"] == "GenericAll":
        return {
            "title": "Excessive Permissions (GenericAll)",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": f"{finding['source']} has full control over {finding['target']}.",
            "impact": f"Attacker could compromise {finding.get('source')} leading to lateral movement and potential domain escalation.",
            "fixes": [
                "Remove GenericAll permission from the source account.",
                "Restrict access using least privilege principles.",
                "Review and audit ACLs on the target object."
            ],
            "related_nodes": [finding.get("source"), finding.get("target")]
        }
    elif finding["type"] == "Kerberoastable":
        return {
            "title": "Kerberoastable Account",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": f"Service account {finding.get('account', 'unknown')} has an SPN set.",
            "impact": "Password can be cracked offline by attackers.",
            "fixes": [
                "Set a strong password (25+ characters) on the service account.",
                "Rotate the password regularly.",
                "Use Group Managed Service Accounts (gMSA) where possible."
            ],
            "related_nodes": [finding.get("account")]
        }
    elif finding["type"] == "ASREP":
        return {
            "title": "AS-REP Roastable User",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),    
            "exploitability": get_exploitability(finding["type"]),        
            "description": "Kerberos pre-authentication is disabled on this account.",
            "impact": "Allows offline password cracking and potential account compromise.",
            "fixes": [
                "Enable Kerberos pre-authentication for the account.",
                "Identify and review accounts with this setting enabled.",
                "Enforce strong password policies."
            ],
            "related_nodes": [finding.get("account")]
        }


    elif finding["type"] == "DCSync":
        return {
            "title": "DCSync Privileges Detected",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": "Account has replication privileges allowing password hash extraction.",
            "impact": "Leads to full domain compromise by dumping credentials.",
            "fixes": [
                "Remove 'Replicating Directory Changes' permissions from the account.",
                "Ensure only Domain Controllers have replication rights.",
                "Audit accounts with DCSync privileges using BloodHound or PowerView.",
                "Monitor for abnormal replication activity."
            ],
            "related_nodes": [finding.get("account")]
        }


    elif finding["type"] == "AttackPath":
        return {
            "title": "Privilege Escalation Path to Domain Admin",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": f"Attack path: {finding.get('path', 'unknown path')}.",
            "impact": "An attacker can escalate privileges and fully compromise the domain.",
            "fixes": [
                "Remove or restrict permissions along the attack path.",
                "Break privilege escalation chains by limiting access rights.",
                "Review group memberships and delegated permissions.",
                "Apply least privilege principles across all accounts."
            ],
            "related_nodes": [finding.get("path")]
        }
    
    elif finding["type"] == "UnconstrainedDelegation":
        return {
            "title": "Unconstrained Delegation Enabled",
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": f"Account {finding.get('account', 'unknown')} is configured with unconstrained delegation.",
            "impact": "Attackers who compromise this account can impersonate users and capture sensitive Kerberos tickets, potentially leading to privilege escalation.",
            "fixes": [
                "Disable unconstrained delegation on the account",
                "Migrate to constrained delegation where required",
                "Audit all accounts with delegation privileges enabled",
                "Monitor Kerberos ticket activity for anomalies"
            ],
            "related_nodes": [finding.get("host"), finding.get("account")]
        }
    
    elif finding["type"] == "WeakPasswordPolicy":
        return {
            "title": "Weak Password Policy Detected",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": "Domain password policy allows weak or easily guessable passwords.",
            "impact": "Increases risk of brute-force attacks and credential compromise across the domain.",
            "fixes": [
                "Enforce minimum password length of 14+ characters",
                "Require password complexity (uppercase, lowercase, numbers, symbols)",
                "Enable password history to prevent reuse",
                "Implement account lockout policies"
            ],
            "related_nodes": [finding.get("domain"), finding.get("issue")]
        }
    
    elif finding["type"] == "WeakGroup":
        return {
            "title": "Weak Group Configuration",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Medium"),
            "mitre": MITRE_MAP.get(finding["type"], "T1069"),  # Permission Groups Discovery
            "exploitability": get_exploitability(finding["type"]),
            "description": f"Group {finding.get('group')} contains excessive members: {finding.get('members')}",
            "impact": "Weak group configurations can be leveraged in attack paths to escalate privileges and gain unauthorized access.",
            "fixes": [
                "Review and remove unnecessary users from privileged groups",
                "Limit membership to only required accounts",
                "Implement role-based access control (RBAC)",
                "Regularly audit group memberships"
            ],
            "related_nodes": [finding.get("group")] + finding.get("members", [])
        }

    elif finding["type"] == "InactivePrivilegedAccount":
        return {
            "title": "Inactive Privileged Account Detected",
            "type": finding["type"],
            "severity": get_severity(finding["type"]),
            "confidence": CONFIDENCE_MAP.get(finding["type"], "Low"),
            "mitre": MITRE_MAP.get(finding["type"], "N/A"),
            "exploitability": get_exploitability(finding["type"]),
            "description": f"Privileged account {finding.get('account', 'unknown')} has been inactive but still has elevated permissions.",
            "impact": "Inactive accounts with privileges can be exploited without detection.",
            "fixes": [
                "Disable or remove inactive privileged accounts",
                "Conduct periodic account activity reviews",
                "Implement automated account lifecycle management",
                "Revoke unnecessary privileges immediately"
            ],
            "related_nodes": [finding.get("account"), finding.get("last_login")]
        }

    return None


# Helper
def get_exploitability(finding_type):
    easy = ["DCSync", "GenericAll", "AttackPath"]
    medium = ["Kerberoastable", "ASREP"]

    if finding_type in easy:
        return "Easy"
    elif finding_type in medium:
        return "Moderate"
    return "Hard"

# Process Findings
def process_findings(findings):
    results = []

    for f in findings:
        remediation = get_remediation(f)
        if remediation and validate_result(remediation):
            results.append(remediation)
        else:
            results.append({
                "title": f"Unknown Finding Type: {f.get('type')}",
                "type": f.get("type"),
                "severity": "Low",
                "confidence": "Low",
                "mitre": "N/A",
                "exploitability": get_exploitability(f.get("type")),
                "description": str(f),
                "impact": "Unknown impact",
                "fixes": ["Manually review this finding"],
                "related_nodes": []
            })
    
    results = deduplicate(results)
    results.sort(key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4))
    return results


# Attack Path Explanation
def explain_attack_path(path):
    if not isinstance(path, list):
        steps = [s.strip() for s in path.split("->")]
    else:
        steps = path

    explanation = []

    for i in range(len(steps) - 1):
        explanation.append(
            f"Step {i+1}: {steps[i]} has access to {steps[i+1]}"
        )

    explanation.append(f"Final Impact: {steps[-1]} access achieved")

    return "\n".join(explanation)


#Risk Score
def calculate_risk_score(results):
    severity_weight = {"Critical": 50, "High": 30, "Medium": 10}
    exploit_weight = {"Easy": 1.5, "Moderate": 1.2, "Hard": 1}

    score = 0
    counts = {"Critical": 0, "High": 0, "Medium": 0}

    for r in results:
        sev = r["severity"]
        exp = r.get("exploitability", "Hard")

        score += severity_weight.get(sev, 0) * exploit_weight.get(exp, 1)
        counts[sev] += 1

    score = min(int(score), 100)

    if counts["Critical"] > 0:
        level = "High"
    elif score >= 50:
        level = "Medium"
    else:
        level = "Low"

    return score, level, counts


def get_quick_wins(results):
    improvements = []

    for i, r in enumerate(results):
        new_score, _ = simulate_risk_without_finding(results, i)
        current_score, _, _ = calculate_risk_score(results)

        reduction = current_score - new_score

        improvements.append((reduction, r["title"]))

    improvements.sort(reverse=True)

    return improvements[:3]


def get_top_priority(results):
    priority_order = {"Critical": 0, "High": 1, "Medium": 2}
    sorted_results = sorted(results, key=lambda x: priority_order[x["severity"]])
    return sorted_results[0] if sorted_results else None


def get_first_step(path):
    if isinstance(path, list):
        return path[0], path[1]
    return None, None


def count_related_paths(finding, findings):
    if "related_nodes" not in finding:
        return 0

    count = 0

    for f in findings:
        if f["type"] == "AttackPath":
            path = f["path"]

            if not isinstance(path, list):
                path = [p.strip() for p in path.split("->")]

            for node in finding["related_nodes"]:
                if node in path:
                    count += 1
                    break

    return count


def simulate_risk_without_finding(results, remove_index):
    score = 0
    counts = {"Critical": 0, "High": 0, "Medium": 0}

    for i, r in enumerate(results):
        if i == remove_index:
            continue  # simulate removal

        severity = r["severity"]

        if severity == "Critical":
            score += 50
            counts["Critical"] += 1
        elif severity == "High":
            score += 30
            counts["High"] += 1
        elif severity == "Medium":
            score += 10
            counts["Medium"] += 1

    score = min(score, 100)

    if counts["Critical"] > 0:
        level = "Critical"
    elif counts["High"] > 0:
        level = "High"
    elif score >= 50:
        level = "Medium"
    else:
        level = "Low"

    return score, level


# PDF Report Generator
styles = getSampleStyleSheet()
def generate_pdf(results, attack_paths, findings):
    doc = SimpleDocTemplate("DomainSleuth_Report.pdf")
    elements = []

    # Title
    elements.append(Paragraph("<b>DomainSleuth Security Report</b>", styles["Title"]))
    elements.append(Spacer(1, 20))

    # Executive Summary
    elements.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))

    summary = f"{len(results)} findings detected. "
    if any(r["severity"] == "Critical" for r in results):
        summary += "Critical risks may lead to domain compromise."

    elements.append(Paragraph(summary, styles["BodyText"]))
    elements.append(Spacer(1, 20))


    # Risk Dashboard
    score, level, counts = calculate_risk_score(results)

    elements.append(Paragraph("<b>Risk Scoring Dashboard</b>", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(f"Total Findings: {len(results)}", styles["BodyText"]))
    elements.append(Paragraph(f"Critical: {counts['Critical']}", styles["BodyText"]))
    elements.append(Paragraph(f"High: {counts['High']}", styles["BodyText"]))
    elements.append(Paragraph(f"Medium: {counts['Medium']}", styles["BodyText"]))

    elements.append(Spacer(1, 10))
    color_map = {"High": "red", "Medium": "orange", "Low": "green"}
    elements.append(Paragraph(f"<b>Overall Risk Score:</b> <font color='{color_map[level]}'>{score} ({level} Risk)</font>", styles["BodyText"]))

    #Quuick Wins
    elements.append(Paragraph("<b>Quick Wins</b>", styles["Heading2"]))
    quick_wins = get_quick_wins(results)

    for reduction, title in quick_wins:
        elements.append(Paragraph(f"Fixing '{title}' reduces risk by {reduction} points", styles["BodyText"]))

    elements.append(Spacer(1, 20))

    # Top Priority Fix
    top = get_top_priority(results)

    if top:
        elements.append(Paragraph("<b>Top Priority Fix</b>", styles["Heading2"]))
        elements.append(Spacer(1, 10))

        elements.append(Paragraph(f"<b>Issue:</b> {top['title']}", styles["BodyText"]))
        elements.append(Paragraph(f"<b>Severity:</b> {top['severity']}", styles["BodyText"]))


        elements.append(Spacer(1, 5))
        elements.append(Paragraph("<b>Why This Matters:</b>", styles["BodyText"]))
        elements.append(Paragraph(top["impact"], styles["BodyText"]))

        elements.append(Spacer(1, 5))
        elements.append(Paragraph("<b>Recommended Action:</b>", styles["BodyText"]))

        # Show only top 2 fixes (cleaner)
        for fix in top["fixes"][:2]:
            elements.append(Paragraph(f"&bull; {fix}", styles["BodyText"]))

        elements.append(Spacer(1, 20))
    
    if top.get("type") == "AttackPath" and attack_paths:
        elements.append(Paragraph("<b>Associated Attack Path:</b>", styles["BodyText"]))
        elements.append(Paragraph(attack_paths[0], styles["BodyText"]))
    
    # Attack Paths Section
    if attack_paths:  # only show if list is NOT empty
        elements.append(Paragraph("<b>Attack Paths</b>", styles["Heading2"]))
        elements.append(Spacer(1, 10))

        for f in findings:
            if f["type"] == "AttackPath":
                src, dst = get_first_step(f["path"])
                
                if src and dst:
                    elements.append(Paragraph(f"<b>Remediation Insight:</b> Restrict access between {src} and {dst} to break this attack chain.", styles["BodyText"]))
            
    elements.append(Spacer(1, 10))



    # Findings Section
    elements.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for i, r in enumerate(results):
        elements.append(Paragraph(f"<b>{r['title']}</b>", styles["Heading3"]))
        elements.append(Spacer(1, 5))
        
        severity_color = {"Critical": "red", "High": "orange", "Medium": "black"}
        elements.append(Paragraph(f"<b>Severity:</b> <font color='{severity_color[r['severity']]}'>{r['severity']}</font>", styles["BodyText"]))

        elements.append(Paragraph(f"<b>MITRE Technique:</b> {r.get('mitre', 'N/A')}", styles["BodyText"]))
        elements.append(Paragraph(f"<b>Confidence:</b> {r.get('confidence', 'Low')}", styles["BodyText"]))
        elements.append(Paragraph(f"<b>Exploitability:</b> {r.get('exploitability', 'Unknown')}", styles["BodyText"]))

        elements.append(Paragraph(f"<b>Description:</b> {r['description']}", styles["BodyText"]))
        elements.append(Paragraph(f"<b>Impact:</b> {r['impact']}", styles["BodyText"]))

        elements.append(Spacer(1, 5))
        elements.append(Paragraph("<b>Remediation:</b>", styles["BodyText"]))

        related = count_related_paths(r, findings)

        if related > 0:
            elements.append(Paragraph(f"<b>Attack Path Impact:</b> Fixing this issue would break {related} attack path(s).", styles["BodyText"]))

        for fix in r["fixes"]:
            elements.append(Paragraph(f"&bull; {fix}", styles["BodyText"]))

        # Risk reduction simulation
        new_score, new_level = simulate_risk_without_finding(results, i)
        current_score, current_level, _ = calculate_risk_score(results)
        elements.append(Paragraph(f"<b>Fix Impact:</b> Fixing this reduces risk score from {current_score} ({current_level}) → {new_score} ({new_level})", styles["BodyText"]))

        elements.append(Spacer(1, 15))

    doc.build(elements)


# Input Methods
def manual_input():
    findings = []

    VALID_TYPES = ["GenericAll", "Kerberoastable", "ASREP", "DCSync", "AttackPath", "UnconstrainedDelegation", "WeakGroup", "WeakPasswordPolicy", "InactivePrivilegedAccount"]

    while True:
        print("\nEnter a new finding:")
        print("Valid types:", ", ".join(VALID_TYPES))

        f_type = input("Type: ")

        if f_type not in VALID_TYPES:
            print("Unknown type, skipping...")
            continue

        if f_type == "GenericAll":
            source = input("Source: ")
            target = input("Target: ")
            finding = {
                "type": f_type,
                "source": source,
                "target": target
            }

        elif f_type == "Kerberoastable":
            account = input("Account: ")
            finding = {
                "type": f_type,
                "account": account
            }

        elif f_type == "ASREP":
            account = input("Account: ")
            finding = {
                "type": f_type,
                "account": account
            }

        elif f_type == "DCSync":
            account = input("Account with replication rights: ")
            finding = {
                "type": f_type,
                "account": account
            }

        elif f_type == "AttackPath":
            print("Enter each step in order (type 'done' when finished)")
            steps = []

            while True:
                step = input("Step: ")
                if step.lower() == "done":
                    break
                steps.append(step)

            finding = {
                "type": f_type,
                "path": steps
            }

        elif f_type == "InactivePrivilegedAccount":
            account = input("Privileged account name: ")
            last_login = input("Last login (optional): ")

            finding = {
                "type": f_type,
                "account": account,
                "last_login": last_login
            }

        elif f_type == "WeakGroup":
            group = input("Group name: ")
            member_count = input("Number of members: ")

            finding = {
                "type": f_type,
                "group": group,
                "member_count": member_count
            }

        elif f_type == "WeakPasswordPolicy":
            domain = input("Domain name: ")
            issue = input("Describe weakness (e.g. short password length, no complexity): ")

            finding = {
                "type": f_type,
                "domain": domain,
                "issue": issue
            }

        elif f_type == "UnconstrainedDelegation":
            host = input("Host / Computer name: ")
            account = input("Affected account (optional): ")

            finding = {
                "type": f_type,
                "host": host,
                "account": account
            }

        findings.append(finding)

        cont = input("Add another? (y/n): ")
        if cont.lower() != "y":
            break

    return findings


#JSON
def load_from_json():
    while True:
        try:
            with open("findings.json", "r") as f:
                return json.load(f)

        except FileNotFoundError:
            print("\n[ERROR] findings.json not found.")
            choice = input("Try again? (y/n): ")

            if choice.lower() != "y":
                print("Switching to manual input...\n")
                return manual_input()



# MAIN PROGRAM
def main():
    print("=== DomainSleuth Remediation Engine ===")

    # Choose input method
    choice = input("Use JSON file? (y/n): ")

    if choice.lower() == "y":
        findings = load_from_json()
    else:
        findings = manual_input()

    # Process findings
    results = process_findings(findings)

    # Show results in terminal
    print("\n=== Processed Findings ===")
    for r in results:
        print("\n---")
        print("Title:", r["title"])
        print("Type:", r.get("type", "Unknown"))
        print("Severity:", r["severity"])
        print("Confidence:", r.get("confidence", "Low"))
        print("Exploitability:", r.get("exploitability", "Unknown"))
        print("MITRE:", r.get("mitre", "N/A"))
        print("Impact:", r["impact"])
        print("Fixes:")

        related = r.get("related_nodes", [])
        if related:
            print("Related Nodes:", ", ".join(related))
        else:
            print("Related Nodes: None")

        print("Fixes:")
        for fix in r["fixes"]:
            print("-", fix)

    # Attack path
    attack_paths = []
    for f in findings:
        if f["type"] == "AttackPath":
            explanation = explain_attack_path(f["path"])
            attack_paths.append(explanation)


            print("\n=== Attack Path ===")
            for ap in attack_paths:
                print(ap)




    # Generate PDF
    generate_pdf(results, attack_paths, findings)

    print("\n PDF report generated: DomainSleuth_Report.pdf")

    with open("report.json", "w") as f:
        json.dump(results, f, indent=2)


# Run program
if __name__ == "__main__":
    main()

