# Methodology

## 1. Environment Setup

The project was implemented in an isolated cybersecurity lab environment using Kali Linux, Debian 13, and Wazuh SIEM.

## 2. Reconnaissance

Network reconnaissance was performed from the Kali Linux attacker machine to identify exposed services on the Debian victim.

## 3. Attack Simulation

An SSH brute-force attack was simulated against a deliberately configured test account to generate authentication events.

## 4. Detection

Wazuh collected SSH authentication logs through the Wazuh agent and correlated events using detection rules.

## 5. Investigation

The generated alerts were investigated using source IP, target account, authentication pattern, timestamps, session behavior, and rule severity.

## 6. Automated Response

High-confidence confirmed-compromise events triggered an automated IP block and real-time email notification.

## 7. File Integrity Monitoring

File Integrity Monitoring was configured to detect unauthorized modifications associated with SSH persistence.

## 8. Validation

The detection system was tested using:
- Confirmed brute-force attack
- Legitimate password-typo scenario
- Failed-only brute-force attack
- Multi-stage intrusion scenario

## 9. Remediation

Security recommendations were documented based on the observed attack and detection results.
