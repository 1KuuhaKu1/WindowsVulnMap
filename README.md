# WindowsVulMap

  

WindowsVulMap 是一个基于 **Microsoft MSRC CVRF 官方接口** 的 Windows 漏洞映射与分析工具，用于按 **具体 Windows 产品版本** 精确查询、筛选和评估漏洞风险，并可选性地辅助判断是否存在 **公开 PoC / 利用代码**。

  

该工具面向安全研究、攻防分析、漏洞管理与补丁评估场景，强调 **数据准确性、可控性与工程可扩展性**。

  

---

  

## ✨ 核心特性

  

* ✅ 基于 **Microsoft 官方 CVRF v2.0 API**（非爬虫）

* ✅ 按 **年份 / 月份** 精确查询安全公告

* ✅ 按 **自然语言产品字符串**（如 `Windows 11 22H2`）自动匹配 ProductID

* ✅ 精确过滤“官方声明受影响”的漏洞（非标题猜测）

* ✅ 支持漏洞类别过滤：

  

  * Elevation of Privilege（EoP）

  * Remote Code Execution（RCE）

* ✅ 提取并汇总关键信息：

  

  * CVE 编号

  * 漏洞类型

  * 最高 CVSS BaseScore

  * 官方漏洞标题

  * 安全更新 KB 编号

* ✅ 终端彩色高亮输出，按风险等级排序

* ✅ **可选** Google Custom Search 预览，用于判断是否存在公开 PoC

* ✅ Google 搜索结果中 **仅当命中当前 CVE 才高亮**，避免误导

* ✅ 支持本地 CVRF JSON 缓存，减少 API 请求、提升性能

  

---

  

## 📦 安装依赖

  

```bash

pip install requests colorama

```

  

如需启用 Google 搜索功能，还需要：

  

* Google Custom Search API Key

* Custom Search Engine（CX）

  

---

  

## 🚀 使用方法

  

### 基础查询（不启用 Google 搜索）

  

```bash

python WindowsVulMap.py --query "Windows 11 22H2"

```

  

### 指定年份与月份

  

```bash

python WindowsVulMap.py \

  --query "Windows 10 21H2" \

  --years 2023 \

  --months 1,2,3

```

  

### 仅查看提权漏洞（EoP）

  

```bash

python WindowsVulMap.py \

  --query "Windows Server 2019" \

  --only eop

```

  

### 启用 Google PoC 预览（可选）

  

```bash

python WindowsVulMap.py \

  --query "Windows 11 22H2" \

  --only eop \

  --google

```

  

> ⚠️ Google 搜索功能默认关闭，只有显式指定 `--google` 才会触发 API 请求。

  

---

  

## 🔍 Google PoC 高亮逻辑说明

  

* 仅当 Google 搜索结果的 **标题或摘要中明确包含当前 CVE 编号** 时：

  

  * 对该 CVE 进行高亮显示

* 若搜索结果提及的是 **其他 CVE**（即使是同类漏洞）：

  

  * 不进行高亮

  

示例：

  

```text

[✔] Documentation and PoC for CVE-2023-21552 MSMQ Vulnerability   ← 高亮

[ ] Documentation and PoC for CVE-2023-21533 MSMQ Vulnerability   ← 不高亮

```

  

该设计用于降低 PoC 误判风险，仅作为**辅助研判依据**。

  

---

  

## 🗂️ 缓存机制

  

* 使用 `--cache` 参数启用本地缓存

* CVRF 数据将保存至：

  

```text

cache/YYYY-MMM.json

```

  

* 再次查询相同月份时将直接读取本地文件

  

```bash

python WindowsVulMap.py --query "Windows 11" --cache

```

  

---

  

## 📊 输出说明

  

每条漏洞输出包含：

  

```text

CVE-ID - 漏洞类型 - CVSS 分数 - 漏洞标题 - KB 列表

	google预览，并标红包含CVE字样内容

```

  ![[Pasted image 20251222190737.png]]

* CVSS 分数按最高 BaseScore 计算

* 所有漏洞按风险等级从高到低排序

  

---

  

## 🎯 适用场景

  

* Windows 系统漏洞面评估

* 红队 / 蓝队漏洞优先级排序

* 补丁覆盖与风险审计

* 已知漏洞是否存在公开利用的快速判断

  

---

  

## ⚠️ 免责声明

  

本工具仅用于安全研究与防御目的。Google 搜索结果仅作为辅助参考，**不能替代正式漏洞利用验证**。使用者需自行判断风险并遵守相关法律法规。

  

---

  

## 📄 License

  

Copyright (C) 2025 wyx0r

  

本项目仅供学习与研究使用。
