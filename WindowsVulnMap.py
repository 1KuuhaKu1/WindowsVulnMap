# WindowsVulMap
# Copyright (C) 2025 wyx0r 

import argparse
import requests
import re
import json
from typing import List, Dict, Set

base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'

headers = {'Accept': 'application/json'}
GOOGLE_API_KEY = "" #Add your API key!!
GOOGLE_CX = "" #Add your CX!!


import os
from colorama import init, Fore, Style

init(autoreset=True)
COLOR_CVE = Fore.LIGHTYELLOW_EX
COLOR_TYPE = Fore.CYAN
COLOR_TITLE = Fore.CYAN
COLOR_SCORE_HIGH = Fore.RED
COLOR_SCORE_MED = Fore.YELLOW
COLOR_SCORE_LOW = Fore.GREEN
COLOR_KB = Fore.MAGENTA
COLOR_RESET = Style.RESET_ALL

def colorize_score(score):
    if score >= 9.0:
        return COLOR_SCORE_HIGH + str(score)
    elif score >= 7.0:
        return COLOR_SCORE_MED + str(score)
    else:
        return COLOR_SCORE_LOW + str(score)

def print_vuln(v):
    print(
        f"{COLOR_CVE}{v['CVE']}{COLOR_RESET} - "
        f"{COLOR_TYPE}{v['Type']}{COLOR_RESET} - "
        f"{colorize_score(v['Score'])}{COLOR_RESET} - "
        f"{COLOR_TITLE}{v['Title']}{COLOR_RESET} - "
        f"{COLOR_KB}{', '.join(v['PatchKBs'])}{COLOR_RESET}\n"
    )

#新增google预览功能，快速判断是否存在公开POC
def google_search_cve(
    cve_id,
    api_key,
    cx,
    max_results=10
):
    query = f"{cve_id} github poc exploit"
    url = "https://www.googleapis.com/customsearch/v1"

    params = {
        "key": api_key,
        "cx": cx,
        "q": query,
        "num": max_results
    }

    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()

    data = resp.json()
    results = []

    for item in data.get("items", []):
        results.append({
            "title": item.get("title"),
            "link": item.get("link"),
            "snippet": item.get("snippet")
        })

    return results

#googlesearch高亮
COLOR_CVE_HIGHLIGHT = Fore.LIGHTRED_EX + Style.BRIGHT
def highlight_cve(text: str, cve_id: str) -> str:
    """
    如果 text 中包含当前 CVE，则高亮该 CVE
    """
    if not text:
        return text

    pattern = re.escape(cve_id)
    return re.sub(
        pattern,
        f"{COLOR_CVE_HIGHLIGHT}{cve_id}{COLOR_RESET}",
        text,
        flags=re.IGNORECASE
    )

def result_contains_cve(result: dict, cve_id: str) -> bool:
    """
    判断 Google 搜索结果是否真正提及当前 CVE
    """
    haystack = " ".join([
        result.get("title", ""),
        result.get("snippet", "")
    ]).lower()

    return cve_id.lower() in haystack



#缓存读取函数
def load_cvrf(
    cvrf_id: str,
    base_url: str,
    headers: dict,
    cache_dir: str = "cache",
    use_cache: bool = True
):
    """
    获取 CVRF 数据：
    - use_cache=True  → 优先使用本地缓存
    - use_cache=False → 强制从服务器获取
    """
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{cvrf_id}.json")

    # 使用缓存
    if use_cache and os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)

    # 从服务器获取
    url = f"{base_url}cvrf/{cvrf_id}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()

    data = resp.json()

    # 写入缓存
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return data



#规范化函数
def normalize_name(name: str) -> str:
    name = name.lower()

    # 移除 edition / 噪声词
    noise_words = [
        "pro", "home", "enterprise", "education",
        "for", "based", "systems", "system",
        "edition", "editions"
    ]

    for w in noise_words:
        name = re.sub(rf"\b{w}\b", "", name)

    # 多空格归一
    name = re.sub(r"\s+", " ", name).strip()
    return name

def match_product_ids(system_name: str, product_map: dict):
    """
    输入系统版本字符串，返回匹配的 ProductID 列表
    """
    normalized_input = normalize_name(system_name)
    input_tokens = normalized_input.split()

    matches = []

    for pid, product_name in product_map.items():
        normalized_product = normalize_name(product_name)

        # 所有关键词都必须出现
        if all(token in normalized_product for token in input_tokens):
            matches.append({
                "ProductID": pid,
                "ProductName": product_name
            })

    return matches


def extract_products(node, product_map):
    """
    递归遍历 ProductTree，提取 ProductID -> 产品名称
    """
    if isinstance(node, dict):
        # 叶子节点
        if "ProductID" in node and "Value" in node:
            product_map[node["ProductID"]] = node["Value"]

        # 继续递归遍历所有字段
        for value in node.values():
            extract_products(value, product_map)

    elif isinstance(node, list):
        for item in node:
            extract_products(item, product_map)

def extract_all_product_ids(vuln: dict) -> set:
    """
    从 Vulnerability 中提取所有 ProductID
    """
    product_ids = set()

    for status in vuln.get("ProductStatuses", []):
        for pid in status.get("ProductID", []):
            product_ids.add(pid)

    return product_ids

#根据ID查询漏洞对象
def filter_vulnerabilities_by_product_ids(
    vulnerabilities: list,
    target_product_ids: set
) -> list:
    """
    仅做集合交集判断
    """
    matched = []

    for vuln in vulnerabilities:
        vuln_product_ids = extract_all_product_ids(vuln)

        if vuln_product_ids & set(target_product_ids):
            matched.append(vuln)

    return matched

#整理漏洞对象中的关键信息
'''
Root
└── Vulnerability[]                      # 漏洞数组（一个元素 = 一个 CVE）
    └── Vulnerability Object
        ├── CVE                          # CVE 编号（字符串）
        ├── Title
        │   └── Value                   # 漏洞标题
        ├── Notes[]                     # 说明性文本（描述 / FAQ / 厂商等）
        ├── CWE[]                       # CWE 分类
        ├── ProductStatuses[]           # 产品受影响状态（核心）
        │   └── ProductStatus
        │       ├── ProductID[]         # 受影响 ProductID 列表
        │       └── Type
        ├── Threats[]                   # 威胁与严重性（按 ProductID 细分）
        │   └── Threat
        │       ├── ProductID[]         # 单个或少量 ProductID
        │       └── Type / Description
        ├── CVSSScoreSets[]             # CVSS 分数（按 ProductID 绑定）
        │   └── CVSSScoreSet
        │       ├── ProductID[]         # 单 ProductID
        │       └── BaseScore / Vector
        ├── Remediations[]              # 修复信息（KB）
        │   └── Remediation
        │       ├── ProductID[]         # 该 KB 适用的 ProductID
        │       └── KB / URL / Build
        └── RevisionHistory[]           # 修订历史
'''
def extract_vuln_summary(vuln):
    # CVE
    cve = vuln.get("CVE", "N/A")

    # 漏洞名称
    title = vuln.get("Title", {}).get("Value", "N/A")

    # 漏洞类别（从 Threats 中找 Type=0）
    vuln_type = "Unknown"
    for t in vuln.get("Threats", []):
        if t.get("Type") == 0:
            vuln_type = t.get("Description", {}).get("Value", "Unknown")
            break

    # 漏洞分数（取最高 BaseScore）
    scores = [
        s.get("BaseScore", 0)
        for s in vuln.get("CVSSScoreSets", [])
    ]
    max_score = max(scores) if scores else 0

    # 补丁信息
    patch_urls = set()
    patch_kbs = set()

    for r in vuln.get("Remediations", []):
        if r.get("Type") == 2:  # Security Update
            url = r.get("URL")
            kb = r.get("Description", {}).get("Value")

            if url:
                patch_urls.add(url)
            if kb:
                patch_kbs.add(kb)

    return {
        "CVE": cve,
        "Type": vuln_type,
        "Score": max_score,
        "Title": title,
        "PatchURLs": list(patch_urls),
        "PatchKBs": list(patch_kbs)
    }

#表格打印
def build_vuln_table(vulnerabilities):
    table = []
    for v in vulnerabilities:
        row = extract_vuln_summary(v)
        table.append(row)
    return table

import argparse
from datetime import datetime
import calendar

def parse_months(months_arg):
    if months_arg is None:
        return list(range(1, 13))

    months = []
    for m in months_arg.split(","):
        m = int(m.strip())
        if m < 1 or m > 12:
            raise ValueError(f"Invalid month: {m}")
        months.append(m)

    return sorted(set(months))

def build_cvrf_ids(year, months):
    cvrf_ids = []
    for m in months:
        month_name = calendar.month_abbr[m]  # Jan, Feb, Mar...
        cvrf_ids.append(f"{year}-{month_name}")
    return cvrf_ids

#仅查看提权
def is_eop(vuln):
    title = vuln.get("Title", {}).get("Value", "")
    return "Elevation of Privilege" in title

#仅查看RCE
def is_rce(vuln):
    title = vuln.get("Title", {}).get("Value", "")
    return "Remote Code Execution" in title


def parse_args():
    parser = argparse.ArgumentParser(
        description="Microsoft CVRF Vulnerability Query Tool"
    )

    parser.add_argument(
        "--years",
        type=int,
        default=datetime.now().year,
        help="Year to query (default: current year)"
    )

    parser.add_argument(
        "--months",
        type=str,
        default=None,
        help="Months to query, e.g. 1 or 1,2,3. Default: whole year"
    )

    parser.add_argument(
        "--query",
        type=str,
        required=True,
        help="Product query string, e.g. 'Windows 11 22H2'"
    )

    parser.add_argument(
        "--cache",
        action="store_true",
        help="Use local cache instead of fetching from MSRC"
    )

    parser.add_argument(
    "--only",
    type=str,
    choices=["eop", "rce"],
    default=None,
    help="Only show specific vulnerability class: eop or rce"
    )

    parser.add_argument(
    "--google",
    action="store_true",
    help="Enable Google Custom Search preview for public PoC"
    )


    return parser.parse_args()




if __name__ == "__main__":
    #参数构造
    args = parse_args()

    #基本信息
    base_url = "https://api.msrc.microsoft.com/"
    headers = {
        "Accept": "application/json"
    }

    #缓存模式，会将内容下载下来，并优先使用下载好的库，减少服务端压力，默认不开启
    USE_CACHE = args.cache

    #确定需要哪些月份的
    months = parse_months(args.months)
    cvrf_ids = build_cvrf_ids(args.years, months)

    #开始主要工作
    all_matched_vulns = []

    for cvrf_id in cvrf_ids:
        print(f"[+] Loading CVRF {cvrf_id}")

        cvrf = load_cvrf(
            cvrf_id=cvrf_id,
            base_url=base_url,
            headers=headers,
            use_cache=USE_CACHE
        )

        #产品IDTree构造
        product_map = {}
        extract_products(cvrf.get("ProductTree", {}), product_map)

        #根据用户Query参数提供的搜索值，匹配出产品ID
        matched_products = match_product_ids(args.query, product_map)
        product_ids = [item["ProductID"] for item in matched_products]

        #筛选漏洞对象
        vulnerabilities = cvrf.get("Vulnerability", [])
        matched_vulns = filter_vulnerabilities_by_product_ids(
            vulnerabilities,
            product_ids
        )

        # 特种漏洞过滤（EoP / RCE）
        if args.only == "eop":
            matched_vulns = [v for v in matched_vulns if is_eop(v)]
        elif args.only == "rce":
            matched_vulns = [v for v in matched_vulns if is_rce(v)]


        all_matched_vulns.extend(matched_vulns)

    # 打印

    vuln_table = build_vuln_table(all_matched_vulns)
    vuln_table.sort(key=lambda x: x["Score"], reverse=True)

    for v in vuln_table:
        print_vuln(v)

        if not args.google:
            continue

        search_results = google_search_cve(
            v["CVE"],
            GOOGLE_API_KEY,
            GOOGLE_CX
        )

        for idx, r in enumerate(search_results, 1):
            title = r.get("title", "")
            snippet = r.get("snippet", "")

            if result_contains_cve(r, v["CVE"]):
                title = highlight_cve(title, v["CVE"])
                snippet = highlight_cve(snippet, v["CVE"])

            print(f"    [{idx}] {title}")
            if snippet:
                print(f"         {snippet}")
            print(f"         {r['link']}")


