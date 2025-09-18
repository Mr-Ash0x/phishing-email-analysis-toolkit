# 🛡️ Phishing Email Analysis Toolkit  

[![CI](https://github.com/YOUR-USERNAME/phishing-email-analysis-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/phishing-email-analysis-toolkit/actions/workflows/ci.yml)  
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)  

A Python-based toolkit to **analyze phishing emails** (`.eml` files), **extract Indicators of Compromise (IOCs)**, and perform automated checks against security intelligence services such as **VirusTotal**, **AbuseIPDB**, and **PhishTank**.  

This project is designed for **SOC Analysts, Incident Responders, and Security Enthusiasts** to quickly triage suspicious emails and generate structured reports.  

---

## 🚀 Features
- Parse `.eml` files and extract:
  - Email headers  
  - Sender information  
  - URLs and domains  
  - Attachments (hashes for reputation checks)  
- Integrates with external APIs:
  - [VirusTotal](https://www.virustotal.com/) — file & URL reputation  
  - [AbuseIPDB](https://www.abuseipdb.com/) — malicious IP checks  
  - [PhishTank](https://phishtank.org/) — phishing URL lookups  
- Generates structured **JSON reports** for SOC workflows  
- Includes **sample phishing email** for demo & testing  
- CI pipeline with **pytest** unit tests  

---



