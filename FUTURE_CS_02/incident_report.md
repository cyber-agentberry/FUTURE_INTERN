## 1. Introduction

As part of my cybersecurity internship, this task focused on simulating the real-world responsibilities of a Security Operations Center (SOC) analyst.  
The goal was to detect, analyze, and respond to simulated security incidents using a SIEM tool (Splunk) by ingesting logs, identifying malicious activity, and drafting an incident response report.

---

## 2. Purpose of the Task

- Monitor logs and network traffic for signs of suspicious or malicious activity.
- Use Splunk to identify and classify security alerts.
- Analyze malware-related activities such as failed logins, trojans, ransomware, spyware, worms, and rootkits.
- Take appropriate actions (e.g., escalate, isolate, notify) for each alert.
- Communicate findings clearly in a formal report.

---

## 3. Tools Used

| Tool        | Purpose                                     |
|-------------|---------------------------------------------|
| Splunk      | Log ingestion, searching, dashboards        |
| VirusTotal  | Threat intelligence and malware scanning    |
| Ubuntu      | Host environment for Splunk + tools         |


---

## 4. Methodology

1. Set up and configured **Splunk Free** on a Linux VM.
2. Ingested sample logs from multiple data sources.
3. Monitored and filtered alerts based on:
   - Malware detections (Trojan, Rootkit, Ransomware)
   - Suspicious login activity (e.g., brute force)
   - Anomalous outbound connections
4. Queried Splunk using SPL:
   ```spl
   index="threat_logs" | table _time, source_ip, user, action, threat | dedup source_ip, user, action

## 5. Splunk Dashboard & Threat Analysis

1. Dashboard Screenshot Placeholder
   [View Splunk Dashboard](https://github.com/cyber-agentberry/FUTURE_INTERN/blob/main/FUTURE_CS_02/Images/Dashboard_screenshot.png)

**The dashboard highlighted**:
- Repeated failed login attempts from specific IPs
- Detection of malware like ransomware and trojans
- High-frequency outbound traffic from internal systems

2. [View VirusTotal PDF report for IP 198.51.100.42](https://drive.google.com/file/d/1daV-bAX2dt03L4WjtzHqphHdQfCF4-0J/view?usp=share_link)
   [View VirusTotal PDF report for IP 203.0.113.77](https://drive.google.com/file/d/1NBdL31Hb0JC27xGmEXjZvxrBZfgSbFYG/view?usp=share_link)


  
## 6. Findings

| IP Address	| Threat Type| Action Taken	          |Status/Severity      |
|-------------|------------|------------------------|---------------------| 
| 192.168.1.3 |	Ransomware |Quarantined and Alerted	|  🚨 Critical        |
| 192.168.1.5 |	Worm	     |Logged, Under Monitoring|	 ⚠️ Medium          |      
| 192.168.1.7	| Trojan	   |Isolated + Notified     |	 🚨 High            |
| 192.168.1.9 | Rootkit    |	Escalated to IR Team	|  🚨 High            |
|192.168.1.11	| Spyware	   |Analyzed, Cleaned	      |  ⚠️ Low             |
|             |            |                        |                     |

## Conclusion
This task significantly enhanced my practical understanding of working within a Security Operations Center (SOC) environment. I gained hands-on experience with Splunk for real-time log analysis, identifying various malware threats, and validating indicators using tools like VirusTotal. Additionally, I developed key skills in alert prioritization, incident classification, and effective stakeholder communication. Overall, this exercise deepened my appreciation for the critical role of continuous monitoring and timely response in safeguarding organizational assets.

## Recommendations
- Automate alert classification in Splunk to reduce response time.
- Integrate VirusTotal API with Splunk for real-time threat validation.
- Improve firewall rules to block suspicious outbound traffic.
- Conduct user awareness training to avoid malware entry points.
