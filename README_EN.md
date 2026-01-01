# WindowsVulMap

WindowsVulMap is a Windows vulnerability mapping and analysis tool based on the **Microsoft MSRC CVRF official API**. It enables precise vulnerability lookup, filtering, and risk evaluation by **specific Windows product versions**, with an optional capability to assist in determining whether **public PoCs / exploit code** exist.

This tool is designed for security research, offensive-defensive analysis, vulnerability management, and patch assessment scenarios, with emphasis on **data accuracy, controllability, and engineering extensibility**.

---

## ✨ Key Features

- ✅ Built on the **official Microsoft CVRF v2.0 API** (no web-scraping)
    
- ✅ Query security advisories by **year / month**
    
- ✅ Automatically match ProductID from **natural-language product strings** (e.g., `Windows 11 22H2`)
    
- ✅ Accurately filter vulnerabilities **officially declared as affected** (not inferred from title text)
    
- ✅ Supports filtering by vulnerability class:
    
    - Elevation of Privilege (EoP)
        
    - Remote Code Execution (RCE)
        
- ✅ Extracts and aggregates key information:
    
    - CVE ID
        
    - Vulnerability type
        
    - Highest CVSS base score
        
    - Official vulnerability title
        
    - Security update KB identifiers
        
- ✅ Color-highlighted terminal output with risk-based sorting
    
- ✅ **Optional** Google Custom Search preview to assess existence of public PoCs
    
- ✅ Google results are **only highlighted when the current CVE is explicitly matched**
    
- ✅ Supports local CVRF JSON caching to reduce API calls and improve performance
    

---

## 📦 Installation

`pip install requests colorama`

If you want to enable the Google search feature, you will also need:

- Google Custom Search API Key
    
- Custom Search Engine (CX)
    

---

## 🚀 Usage

### Basic query (Google search disabled)

```
python WindowsVulMap.py --query "Windows 11 22H2"
```

### Specify year and month

```
python WindowsVulMap.py \
--query "Windows 10 21H2" \
   --years 2023 \
   --months 1,2,3
```

### Show only Elevation of Privilege (EoP) vulnerabilities

```
python WindowsVulMap.py \
--query "Windows Server 2019" \
--only eop
```

### Enable Google PoC preview (optional)

```
python WindowsVulMap.py \
--query "Windows 11 22H2" \
--only eop \
--google
```

> ⚠️ The Google search feature is disabled by default and is only triggered when `--google` is explicitly specified.

---

## 🔍 Google PoC Highlight Logic

- A vulnerability is highlighted **only when the CVE ID explicitly appears** in the Google result title or snippet.
    
    - Matching CVE → highlight
        
    - Different CVE → do not highlight
        

Example:

```
[✔] Documentation and PoC for CVE-2023-21552 MSMQ Vulnerability   ← highlighted 
[ ] Documentation and PoC for CVE-2023-21533 MSMQ Vulnerability   ← not highlighted
```

This design reduces PoC misclassification risk and serves **only as a supplementary judgment reference**.

---

## 🗂️ Caching Mechanism

- Enable local cache using `--cache`
    
- CVRF data is stored under:
    

`cache/YYYY-MMM.json`

- Re-querying the same month will read from the local cache
    

`python WindowsVulMap.py --query "Windows 11" --cache`

---

## 📊 Output Description

Each vulnerability entry includes:

```
CVE-ID — Vulnerability Type — CVSS Score — Title — KB List     
        Google Preview (CVE occurrences highlighted in red)
```

- CVSS score is based on the highest BaseScore
    
- Vulnerabilities are sorted in descending risk order
    

---

## 🎯 Applicable Scenarios

- Windows platform vulnerability surface assessment
    
- Red team / Blue team vulnerability prioritization
    
- Patch coverage review and risk auditing
    
- Rapid judgment of potential public exploits
    

---

## ⚠️ Disclaimer

This tool is intended for security research and defensive purposes only. Google search results are provided as **supplementary reference information** and must not be treated as confirmed exploit verification. Users are responsible for risk evaluation and compliance with applicable laws and regulations.

---

## 📄 License

Copyright (C) 2025 wyx0r

This project is for learning and research use only.

---

If you would like, I can also:

- refine wording for open-source publication,
    
- produce a concise README version,
    
- or help adapt it for GitHub / PyPI style guidelines.
