# DomainSleuth: Remediation & Reporting Engine #
**Introduction**  
        This function of the platform focuses on building a remediation and reporting engine that is able to transform security findings into actionable intelligence. The goal was to detect misconfigurations and vulnerabilities within an Active Directory environment, and contextualize them in terms of risk, exploitability, and impact. The final output is a structured PDF report that presents prioritized remediation guidance and highlights potential attack paths leading to domain compromise.  

**Research and Remediation Logic**  
The remediation logic was designed based on common Active Directory attack techniques and defensive best practices. Each finding type was mapped to:  
- A clear description of the issue  
- The potential impact if exploited  
- Actionable remediation steps  
- Severity, exploitability, and confidence levels  
- MITRE ATT&CK technique mappings (where applicable)  

**Key Finding Types and Research Basis**  
- DCSync (Critical) - Research shows that replication permissions can be abused to extract password hashes from domain controllers. This directly leads to full domain compromise. Remediation would be to restrict replication permissions and audit privileged accounts.  
- Kerberoastable Accounts (High) - Service accounts with Service Principal Names (SPNs) can be targeted for offline password cracking. Remediation is to enforce strong passwords, rotate credentials, and use managed service accounts.  
- AS-REP Roastable Users (High) - Accounts without Kerberos pre-authentication allow attackers to retrieve encrypted data for offline attacks. Remediation is to enable pre-authentication and enforce strong password policies.  
- GenericAll Permissions (Critical) - Full control over objects allows attackers to reset passwords or modify permissions, enabling lateral movement. Remediation would be to remove excessive permissions and enforce least privilege.  
- Weak Group Configuration (High) - Overly permissive group memberships increase the attack surface and enable privilege escalation. Remediation is an audit and restricted group membership using role-based access control.  
- Unconstrained Delegation (High) - Allows credential impersonation and Kerberos ticket abuse. Remediation is to replace with a constrained delegation and monitor ticket activity.  
- Inactive Privileged Accounts (Medium) - Dormant accounts with elevated privileges pose a hidden risk. Remediation is to disable or remove inactive accounts and implement lifecycle management.
- Attack Path to Domain Admin (Critical) - A sequence of misconfigurations or permissions allows an attacker to escalate privileges from a low-level account to Domain Admin. This represents a direct path to full domain compromise. Remediation is to identify and break the chain by removing unnecessary permissions, restricting access between nodes, and enforcing least privilege across the path.
- Weak Password Policy (Medium) - Domain password policies that allow short or simple passwords increase susceptibility to brute-force and credential-based attacks. Remediation is to enforce strong password requirements, enable complexity rules, implement password history, and configure account lockout policies.
  

**Attack Path Analysis**  
A key feature is its ability to interpret and explain attack paths. Attack paths are sequences of relationships that an attacker could exploit to escalate privileges.
The function:  
- Accepts user-defined paths (user, service account,  domain admin)  
- Converts them into step-by-step explanations  
- Identifies the weakest link in the chain  
- Provides remediation insights to break the path  
Additionally, findings are correlated with attack paths to determine how many escalation routes a single vulnerability supports. This enables prioritization based on real impact rather than isolated severity.  

**Risk Scoring Model**  
        The risk scoring component combines severity weights (Critical, High, Medium) and exploitability factors (Easy, Moderate, Hard). Each finding contributes to an overall score, capped at 100. The model also categorizes overall risk into critical, high, medium, and low.
Additional features include:  
- Quick Wins: Identifies fixes that reduce risk the most  
- Top Priority Fix: Highlights the most impactful issue  
- Risk Reduction Simulation: Shows how fixing a finding changes the overall score  
This ensures the report reflects both technical severity and practical risk reduction.  

**PDF Report Generation**  
The reporting component was implemented using Python’s ReportLab library. The PDF generator constructs a structured, readable report with multiple sections, the report structure is as follows:  
1. Executive Summary - Provides a high-level overview of findings and risk level.  
2. Risk Scoring Dashboard - Displays total findings, severity distribution, and overall risk score with color coding.  
3. Quick Wins - Highlights remediation actions that yield the greatest reduction in risk.  
4. Top Priority Fix - Identifies the most critical issue and provides focused remediation guidance.  
5. Attack Paths - Explains escalation chains and suggests how to break them.  
6. Detailed Findings - Each finding includes:
   - Severity (color-coded)  
   - MITRE technique mapping  
   - Confidence and exploitability  
   - Description and impact  
   - Remediation steps  
   - Attack path impact  
   - Simulated risk reduction  

**Design Highlights**  
- Modular Functions - Separate functions handle remediation logic, scoring, attack path analysis, and PDF generation.  
- Data Validation & Deduplication - Ensures consistent and clean report output.  
- Dynamic Content Generation - Sections such as attack paths and priority fixes only appear when relevant.  
- Styled Output - Uses headings, spacing, and bullet points to improve readability and professionalism.  

**Key Features**  
- Correlation between findings and attack paths  
- Risk-based prioritization rather than static severity  
- Simulated remediation impact on overall risk score  
- Integration of MITRE ATT&CK mappings  
- Dynamic and structured PDF reporting  
These features move the tool beyond simple vulnerability listing and toward actionable security analysis.

**Conclusion**  
        This project demonstrates how security findings can be transformed into meaningful, prioritized remediation guidance. By combining research-based remediation strategies, attack path analysis, and risk scoring, the tool provides a comprehensive view of an organization’s security posture. The final PDF report serves as both a technical and executive-level document, enabling stakeholders to understand risks and take targeted action to reduce them.

