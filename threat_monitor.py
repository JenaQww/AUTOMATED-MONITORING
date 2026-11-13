#!/usr/bin/env python3
"""
Автоматизированный мониторинг и реагирование на угрозы информационной безопасности.

Инструмент выполняет:
1. Сбор данных из трех источников:
   - Журнал событий сетевой безопасности Suricata (формат EVE JSON);
   - Бюллетени уязвимостей через API Vulners (с автоматическим переключением
     на локальный кэш при отсутствии ключа или доступа к сети);
   - Репутационные данные IP-адресов через API VirusTotal v3 (с поддержкой
     локального дампа для автономной проверки).
2. Анализ данных с использованием библиотек pandas, json и requests:
   - Выявление подозрительных узлов по частоте DNS-запросов и сетевым алертам;
   - Фильтрация критических и высоких уязвимостей (CVSS >= 7.0);
   - Сопоставление подозрительных IP с вердиктами антивирусных движков VirusTotal.
3. Реагирование на выявленные угрозы:
   - Имитация блокировки вредоносных IP-адресов на межсетевом экране (правила iptables);
   - Имитация отправки оперативных оповещений в Telegram и по электронной почте.
4. Сохранение результатов и визуализация:
   - Экспорт сводного отчета в форматах JSON (threat_report.json) и CSV (threat_report.csv);
   - Построение и сохранение графиков анализа угроз в файл threat_analysis_chart.png.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import requests


# Пороговые значения для правил обнаружения
CVSS_CRITICAL_THRESHOLD = 7.0
DNS_QUERY_THRESHOLD = 15
VT_MALICIOUS_THRESHOLD = 3


def ensure_sample_data(data_dir: Path) -> Tuple[Path, Path, Path]:
    """
    Создает демонстрационные наборы данных (логи Suricata и кэши ответов API),
    если они еще не существуют в рабочей папке data/. Это гарантирует
    воспроизводимость проверки скрипта без обязательного ввода платных API-ключей.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    suricata_path = data_dir / "suricata_eve.json"
    vulners_cache_path = data_dir / "vulners_sample.json"
    vt_cache_path = data_dir / "virustotal_sample.json"

    if not suricata_path.exists():
        events: List[Dict[str, Any]] = []
        base_time = dt.datetime(2026, 11, 6, 14, 0, 0)

        # Профиль трафика по внешним и внутренним узлам:
        # (src_ip, dns_count, alert_count, signature, category, severity, dest_port)
        ip_profiles = [
            ("185.220.101.42", 64, 18, "ET TROJAN CobaltStrike Beacon DNS Tunneling", "Malware Command and Control Activity", 1, 53),
            ("45.155.205.233", 41, 14, "ET SCAN Nmap Scripting Engine SSH Brute-Force", "Attempted Information Leak", 1, 22),
            ("91.240.118.172", 29, 9, "ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)", "Attempted Administrator Privilege Gain", 1, 8080),
            ("194.26.29.114", 19, 6, "ET DNS High Volume Suspicious TXT Queries", "Potentially Bad Traffic", 2, 53),
            ("103.145.13.88", 16, 4, "ET WEB_SERVER SQL Injection Select Statement", "Web Application Attack", 2, 443),
            ("192.168.10.25", 7, 1, "SURICATA STREAM 3way handshake excessive retransmissions", "Generic Protocol Command Decode", 3, 443),
            ("10.0.5.14", 4, 0, "", "Normal Traffic", 3, 53),
        ]

        offset_sec = 0
        for src_ip, dns_cnt, alert_cnt, sig, cat, sev, dport in ip_profiles:
            for i in range(dns_cnt):
                offset_sec += 2
                ts = (base_time + dt.timedelta(seconds=offset_sec)).isoformat() + "Z"
                events.append({
                    "timestamp": ts,
                    "event_type": "dns",
                    "src_ip": src_ip,
                    "src_port": 51000 + (i % 500),
                    "dest_ip": "8.8.8.8",
                    "dest_port": 53,
                    "proto": "UDP",
                    "dns": {
                        "type": "query",
                        "id": 1000 + i,
                        "rrname": f"sub{i % 12}.c2-update-node.net" if dns_cnt >= DNS_QUERY_THRESHOLD else "api.internal.local",
                        "rrtype": "TXT" if dns_cnt >= DNS_QUERY_THRESHOLD else "A",
                    },
                })
            for j in range(alert_cnt):
                offset_sec += 3
                ts = (base_time + dt.timedelta(seconds=offset_sec)).isoformat() + "Z"
                events.append({
                    "timestamp": ts,
                    "event_type": "alert",
                    "src_ip": src_ip,
                    "src_port": 42000 + (j % 300),
                    "dest_ip": "192.168.10.10",
                    "dest_port": dport,
                    "proto": "TCP",
                    "alert": {
                        "action": "allowed",
                        "gid": 1,
                        "signature_id": 2024000 + j,
                        "rev": 2,
                        "signature": sig,
                        "category": cat,
                        "severity": sev,
                    },
                })

        with suricata_path.open("w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    if not vulners_cache_path.exists():
        vulners_sample = {
            "result": "OK",
            "data": {
                "search": [
                    {
                        "id": "CVE-2024-6387",
                        "title": "OpenSSH Server RegreSSHion Unauthenticated Remote Code Execution",
                        "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        "published": "2024-07-01",
                        "affected_software": "OpenSSH < 9.8p1",
                        "exploit_available": True,
                    },
                    {
                        "id": "CVE-2024-3400",
                        "title": "PAN-OS GlobalProtect Gateway Arbitrary File Creation and Command Injection",
                        "cvss": {"score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                        "published": "2024-04-12",
                        "affected_software": "Palo Alto PAN-OS 10.2 / 11.0",
                        "exploit_available": True,
                    },
                    {
                        "id": "CVE-2023-44487",
                        "title": "HTTP/2 Rapid Reset Attack Denial of Service Vulnerability",
                        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                        "published": "2023-10-10",
                        "affected_software": "nginx / Apache httpd / Envoy",
                        "exploit_available": True,
                    },
                    {
                        "id": "CVE-2021-44228",
                        "title": "Apache Log4j2 JNDI Lookup Remote Code Execution (Log4Shell)",
                        "cvss": {"score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                        "published": "2021-12-10",
                        "affected_software": "Apache Log4j 2.0-beta9 - 2.14.1",
                        "exploit_available": True,
                    },
                    {
                        "id": "CVE-2024-45337",
                        "title": "Go x/crypto/ssh ServerConfig PublicKeyCallback Authorization Bypass",
                        "cvss": {"score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
                        "published": "2024-12-11",
                        "affected_software": "golang.org/x/crypto < 0.31.0",
                        "exploit_available": False,
                    },
                    {
                        "id": "CVE-2024-27316",
                        "title": "Apache HTTP Server HTTP/2 CONTINUATION Frames Memory Exhaustion",
                        "cvss": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                        "published": "2024-04-03",
                        "affected_software": "Apache HTTP Server 2.4.17 - 2.4.58",
                        "exploit_available": False,
                    },
                    {
                        "id": "CVE-2023-50868",
                        "title": "DNSSEC KeyTrap Resource Exhaustion in Recursive Resolvers",
                        "cvss": {"score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"},
                        "published": "2024-02-13",
                        "affected_software": "BIND 9 / Unbound",
                        "exploit_available": False,
                    },
                ]
            },
        }
        with vulners_cache_path.open("w", encoding="utf-8") as f:
            json.dump(vulners_sample, f, ensure_ascii=False, indent=2)

    if not vt_cache_path.exists():
        vt_sample = {
            "185.220.101.42": {
                "country": "DE",
                "as_owner": "Tor Exit Node / Zwiebelfreunde e.V.",
                "last_analysis_stats": {"malicious": 19, "suspicious": 4, "harmless": 58, "undetected": 11},
                "reputation": -78,
            },
            "45.155.205.233": {
                "country": "RU",
                "as_owner": "Selectel Network Scanner Pool",
                "last_analysis_stats": {"malicious": 14, "suspicious": 3, "harmless": 61, "undetected": 14},
                "reputation": -54,
            },
            "91.240.118.172": {
                "country": "NL",
                "as_owner": "Serverius Holding B.V.",
                "last_analysis_stats": {"malicious": 11, "suspicious": 2, "harmless": 64, "undetected": 15},
                "reputation": -42,
            },
            "194.26.29.114": {
                "country": "SC",
                "as_owner": "CloudAssets Hosting Ltd",
                "last_analysis_stats": {"malicious": 7, "suspicious": 3, "harmless": 68, "undetected": 14},
                "reputation": -25,
            },
            "103.145.13.88": {
                "country": "VN",
                "as_owner": "Viettel IDC",
                "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 70, "undetected": 15},
                "reputation": -18,
            },
            "192.168.10.25": {
                "country": "LAN",
                "as_owner": "Internal Corporate Subnet",
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 7},
                "reputation": 0,
            },
            "10.0.5.14": {
                "country": "LAN",
                "as_owner": "Internal Corporate Subnet",
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 86, "undetected": 6},
                "reputation": 0,
            },
        }
        with vt_cache_path.open("w", encoding="utf-8") as f:
            json.dump(vt_sample, f, ensure_ascii=False, indent=2)

    return suricata_path, vulners_cache_path, vt_cache_path


def load_suricata_logs(log_path: Path) -> pd.DataFrame:
    """
    Этап 1 (Источник 1): Чтение файла логов Suricata в формате EVE JSON
    и преобразование событий в таблицу pandas DataFrame.
    """
    records: List[Dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            alert_obj = ev.get("alert", {})
            dns_obj = ev.get("dns", {})
            records.append({
                "timestamp": ev.get("timestamp"),
                "event_type": ev.get("event_type"),
                "src_ip": ev.get("src_ip"),
                "src_port": ev.get("src_port"),
                "dest_ip": ev.get("dest_ip"),
                "dest_port": ev.get("dest_port"),
                "proto": ev.get("proto"),
                "dns_rrname": dns_obj.get("rrname", ""),
                "dns_rrtype": dns_obj.get("rrtype", ""),
                "alert_signature": alert_obj.get("signature", ""),
                "alert_category": alert_obj.get("category", ""),
                "alert_severity": alert_obj.get("severity", None),
            })
    return pd.DataFrame(records)


def fetch_vulners_vulnerabilities(cache_path: Path, query: str = "OpenSSH OR Log4j OR HTTP/2") -> pd.DataFrame:
    """
    Этап 1 (Источник 2): Получение списка уязвимостей через API Vulners.
    При наличии переменной окружения VULNERS_API_KEY выполняет HTTP-запрос
    через библиотеку requests; при отсутствии ключа или сети использует
    подготовленный кэш ответа API.
    """
    api_key = os.getenv("VULNERS_API_KEY", "").strip()
    payload_data: Dict[str, Any] = {}

    if api_key:
        try:
            response = requests.post(
                "https://vulners.com/api/v3/search/lucene/",
                json={"query": query, "size": 10, "apiKey": api_key},
                timeout=8,
            )
            response.raise_for_status()
            payload_data = response.json()
            print("[INFO] Данные об уязвимостях успешно получены от онлайн API Vulners.")
        except requests.RequestException as exc:
            print(f"[WARN] Ошибка обращения к API Vulners ({exc}). Переключение на локальный кэш.")

    if not payload_data:
        with cache_path.open("r", encoding="utf-8") as f:
            payload_data = json.load(f)
        print(f"[INFO] Загружен набор данных уязвимостей Vulners из {cache_path.name}.")

    items = payload_data.get("data", {}).get("search", [])
    rows: List[Dict[str, Any]] = []
    for item in items:
        cvss_info = item.get("cvss", {})
        score = float(cvss_info.get("score", 0.0)) if isinstance(cvss_info, dict) else 0.0
        rows.append({
            "cve_id": item.get("id", "UNKNOWN"),
            "title": item.get("title", ""),
            "cvss_score": score,
            "cvss_vector": cvss_info.get("vector", "") if isinstance(cvss_info, dict) else "",
            "published": item.get("published", ""),
            "affected_software": item.get("affected_software", "N/A"),
            "exploit_available": bool(item.get("exploit_available", False)),
        })
    return pd.DataFrame(rows)


def check_ips_virustotal(ip_list: List[str], cache_path: Path) -> Dict[str, Dict[str, Any]]:
    """
    Этап 1 (Источник 3): Проверка репутации IP-адресов через API VirusTotal v3.
    Если задан ключ VT_API_KEY, выполняет запросы GET к VirusTotal API;
    иначе использует локальный дамп репутационных оценок.
    """
    api_key = os.getenv("VT_API_KEY", "").strip()
    with cache_path.open("r", encoding="utf-8") as f:
        cached_vt = json.load(f)

    results: Dict[str, Dict[str, Any]] = {}
    for ip in ip_list:
        if api_key and not ip.startswith(("192.168.", "10.")):
            try:
                headers = {"x-apikey": api_key}
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers=headers,
                    timeout=8,
                )
                resp.raise_for_status()
                attrs = resp.json().get("data", {}).get("attributes", {})
                results[ip] = {
                    "country": attrs.get("country", "UNKNOWN"),
                    "as_owner": attrs.get("as_owner", "UNKNOWN"),
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "reputation": attrs.get("reputation", 0),
                }
                continue
            except requests.RequestException:
                pass

        results[ip] = cached_vt.get(
            ip,
            {
                "country": "UNKNOWN",
                "as_owner": "Unverified Network",
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "reputation": 0,
            },
        )
    print(f"[INFO] Проверена репутация {len(results)} уникальных IP-адресов (источник: VirusTotal).")
    return results


def analyze_threats(
    suricata_df: pd.DataFrame,
    vulners_df: pd.DataFrame,
    vt_data: Dict[str, Dict[str, Any]],
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Этап 2: Аналитическая обработка собранных данных с помощью pandas.
    - Агрегирует сетевую активность по каждому IP-адресу из логов Suricata;
    - Обогащает таблицу метриками VirusTotal;
    - Выделяет подозрительные IP-адреса и критические уязвимости (CVSS >= 7.0);
    - Формирует единую таблицу обнаруженных угроз для отчета.
    """
    dns_counts = (
        suricata_df[suricata_df["event_type"] == "dns"]
        .groupby("src_ip")
        .size()
        .rename("dns_queries")
    )
    alert_df = suricata_df[suricata_df["event_type"] == "alert"]
    alert_counts = alert_df.groupby("src_ip").size().rename("suricata_alerts")
    top_signatures = (
        alert_df.groupby("src_ip")["alert_signature"]
        .agg(lambda s: s.mode().iloc[0] if not s.mode().empty else "Frequent DNS Queries")
        .rename("primary_signature")
    )

    all_ips = pd.Index(suricata_df["src_ip"].unique(), name="src_ip")
    ip_summary = pd.DataFrame(index=all_ips).join([dns_counts, alert_counts, top_signatures]).fillna(
        {"dns_queries": 0, "suricata_alerts": 0, "primary_signature": "Frequent DNS Activity"}
    )
    ip_summary["dns_queries"] = ip_summary["dns_queries"].astype(int)
    ip_summary["suricata_alerts"] = ip_summary["suricata_alerts"].astype(int)
    ip_summary = ip_summary.reset_index()

    # Обогащение данными VirusTotal
    ip_summary["vt_malicious"] = ip_summary["src_ip"].map(
        lambda ip: int(vt_data.get(ip, {}).get("last_analysis_stats", {}).get("malicious", 0))
    )
    ip_summary["vt_suspicious"] = ip_summary["src_ip"].map(
        lambda ip: int(vt_data.get(ip, {}).get("last_analysis_stats", {}).get("suspicious", 0))
    )
    ip_summary["country"] = ip_summary["src_ip"].map(lambda ip: vt_data.get(ip, {}).get("country", "N/A"))
    ip_summary["as_owner"] = ip_summary["src_ip"].map(lambda ip: vt_data.get(ip, {}).get("as_owner", "N/A"))

    # Интегральный индекс риска IP-адреса
    ip_summary["risk_score"] = (
        ip_summary["dns_queries"] * 0.6
        + ip_summary["suricata_alerts"] * 2.5
        + ip_summary["vt_malicious"] * 2.0
    ).round(1)

    ip_summary["is_threat"] = (
        (ip_summary["dns_queries"] >= DNS_QUERY_THRESHOLD)
        | (ip_summary["suricata_alerts"] >= 3)
        | (ip_summary["vt_malicious"] >= VT_MALICIOUS_THRESHOLD)
    )
    ip_summary = ip_summary.sort_values(by="risk_score", ascending=False).reset_index(drop=True)

    # Фильтрация опасных уязвимостей по порогу CVSS
    critical_vulns = vulners_df[vulners_df["cvss_score"] >= CVSS_CRITICAL_THRESHOLD].copy()
    critical_vulns = critical_vulns.sort_values(by="cvss_score", ascending=False).reset_index(drop=True)

    # Сводная таблица угроз для итогового отчета (.csv и .json)
    unified_rows: List[Dict[str, Any]] = []
    for _, row in ip_summary[ip_summary["is_threat"]].iterrows():
        severity_label = "CRITICAL" if row["vt_malicious"] >= 10 or row["dns_queries"] >= 40 else "HIGH"
        unified_rows.append({
            "threat_type": "Suspicious Network Node",
            "indicator": row["src_ip"],
            "source": "Suricata EVE + VirusTotal API",
            "severity": severity_label,
            "score_metric": float(row["risk_score"]),
            "details": (
                f"DNS queries: {row['dns_queries']}, Suricata alerts: {row['suricata_alerts']}, "
                f"VT malicious engines: {row['vt_malicious']} ({row['country']}, {row['as_owner']}). "
                f"Signature: {row['primary_signature']}"
            ),
            "recommended_action": f"Block IP via iptables & notify SOC",
        })

    for _, vrow in critical_vulns.iterrows():
        sev_label = "CRITICAL" if vrow["cvss_score"] >= 9.0 else "HIGH"
        unified_rows.append({
            "threat_type": "Software Vulnerability",
            "indicator": vrow["cve_id"],
            "source": "Vulners API",
            "severity": sev_label,
            "score_metric": float(vrow["cvss_score"]),
            "details": (
                f"{vrow['title']} | Affected: {vrow['affected_software']} | "
                f"CVSS: {vrow['cvss_score']} | Exploit public: {vrow['exploit_available']}"
            ),
            "recommended_action": "Apply security patch / restrict service access",
        })

    unified_df = pd.DataFrame(unified_rows)
    return ip_summary, critical_vulns, unified_df


def respond_to_threats(ip_summary: pd.DataFrame, critical_vulns: pd.DataFrame) -> List[Dict[str, str]]:
    """
    Этап 3: Реагирование на выявленные угрозы.
    Выводит предупреждения в консоль, имитирует блокировку вредоносных IP-адресов
    и отправку уведомлений в Telegram / по email.
    """
    actions_log: List[Dict[str, str]] = []
    now_str = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 78)
    print("ЭТАП 3. ОПЕРАТИВНОЕ РЕАГИРОВАНИЕ НА ОБНАРУЖЕННЫЕ УГРОЗЫ")
    print("=" * 78)

    suspicious_ips = ip_summary[ip_summary["is_threat"]]
    for _, row in suspicious_ips.iterrows():
        ip = row["src_ip"]
        fw_cmd = f"iptables -A INPUT -s {ip} -j DROP"
        msg = (
            f"[ALERT] Обнаружен вредоносный узел {ip} ({row['country']}, {row['as_owner']}): "
            f"DNS-запросов={row['dns_queries']}, алертов Suricata={row['suricata_alerts']}, "
            f"детектов VirusTotal={row['vt_malicious']}."
        )
        print(msg)
        print(f"  -> [FIREWALL SIM] Выполнена имитация блокировки IP: `{fw_cmd}`")
        print(f"  -> [NOTIFY SIM] Отправлено уведомление в Telegram-канал SOC и на soc-alerts@company.local")

        # Опциональная реальная отправка в Telegram при наличии токена
        tg_token = os.getenv("TG_BOT_TOKEN", "").strip()
        tg_chat = os.getenv("TG_CHAT_ID", "").strip()
        if tg_token and tg_chat:
            try:
                requests.post(
                    f"https://api.telegram.org/bot{tg_token}/sendMessage",
                    json={"chat_id": tg_chat, "text": f"{msg}\nКоманда: {fw_cmd}"},
                    timeout=5,
                )
            except requests.RequestException:
                pass

        actions_log.append({
            "timestamp": now_str,
            "target": ip,
            "action_type": "IP_BLOCK_AND_NOTIFY",
            "command": fw_cmd,
            "notification_channel": "Telegram & Email (Simulated)",
            "reason": row["primary_signature"],
        })

    print("-" * 78)
    for _, vrow in critical_vulns.iterrows():
        cve = vrow["cve_id"]
        cvss = vrow["cvss_score"]
        vuln_msg = (
            f"[VULN ALERT] Критическая уязвимость {cve} (CVSS {cvss}): "
            f"{vrow['title']} [{vrow['affected_software']}]"
        )
        print(vuln_msg)
        print(f"  -> [PATCH SIM] Создана заявка на экстренное обновление пакета ({vrow['affected_software']})")
        actions_log.append({
            "timestamp": now_str,
            "target": cve,
            "action_type": "PATCH_TICKET_AND_ALERT",
            "command": f"ansible-playbook patch_cve.yml -e cve_id={cve}",
            "notification_channel": "Email Security Team (Simulated)",
            "reason": f"High CVSS score ({cvss})",
        })

    print("=" * 78 + "\n")
    return actions_log


def save_reports_and_chart(
    ip_summary: pd.DataFrame,
    vulners_df: pd.DataFrame,
    critical_vulns: pd.DataFrame,
    unified_df: pd.DataFrame,
    actions_log: List[Dict[str, str]],
    output_dir: Path,
) -> Tuple[Path, Path, Path]:
    """
    Этап 4: Сохранение отчета в форматах CSV и JSON и построение итогового графика PNG.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "threat_report.csv"
    json_path = output_dir / "threat_report.json"
    chart_path = output_dir / "threat_analysis_chart.png"

    # 1. Сохранение CSV-отчета
    unified_df.to_csv(csv_path, index=False, encoding="utf-8")

    # 2. Сохранение структурированного JSON-отчета
    report_payload = {
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "total_ips_analyzed": int(len(ip_summary)),
            "malicious_ips_blocked": int(ip_summary["is_threat"].sum()),
            "total_vulnerabilities_checked": int(len(vulners_df)),
            "critical_vulnerabilities_found": int(len(critical_vulns)),
            "total_response_actions": len(actions_log),
        },
        "suspicious_ips": ip_summary[ip_summary["is_threat"]].to_dict(orient="records"),
        "critical_vulnerabilities": critical_vulns.to_dict(orient="records"),
        "response_actions_log": actions_log,
    }
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(report_payload, f, ensure_ascii=False, indent=2)

    # 3. Построение комбинированного аналитического графика (Топ-5 подозрительных IP + CVSS баллы)
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Calibri"]
    plt.rcParams["axes.unicode_minus"] = False

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.6), dpi=200)
    fig.patch.set_facecolor("#FFFFFF")

    # Левая панель: Топ-5 подозрительных IP по числу DNS-запросов и детектов VirusTotal
    top5_ips = ip_summary.head(5).iloc[::-1]
    y_pos = range(len(top5_ips))
    bars_dns = ax1.barh(
        [y - 0.18 for y in y_pos],
        top5_ips["dns_queries"],
        height=0.35,
        color="#1B365D",
        label="DNS-запросы (Suricata)",
    )
    bars_vt = ax1.barh(
        [y + 0.18 for y in y_pos],
        top5_ips["vt_malicious"],
        height=0.35,
        color="#D9534F",
        label="Детекты VirusTotal",
    )
    ax1.set_yticks(list(y_pos))
    ax1.set_yticklabels([f"{ip}\n({cnt})" for ip, cnt in zip(top5_ips["src_ip"], top5_ips["country"])], fontsize=9.5)
    ax1.set_xlabel("Количество событий / срабатываний", fontsize=10.5, fontweight="bold")
    ax1.set_title("Топ-5 подозрительных IP-адресов", fontsize=12, fontweight="bold", pad=12, color="#1B365D")
    ax1.axvline(DNS_QUERY_THRESHOLD, color="#E67E22", linestyle="--", linewidth=1.2, label=f"Порог DNS ({DNS_QUERY_THRESHOLD})")
    ax1.legend(loc="lower right", frameon=True, fontsize=8.8)
    ax1.grid(axis="x", linestyle=":", alpha=0.6)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.margins(x=0.16)

    for bar in bars_dns:
        w = bar.get_width()
        ax1.text(w + 0.8, bar.get_y() + bar.get_height() / 2, f"{int(w)}", va="center", fontsize=8.5, color="#1B365D", fontweight="bold")
    for bar in bars_vt:
        w = bar.get_width()
        ax1.text(w + 0.8, bar.get_y() + bar.get_height() / 2, f"{int(w)}", va="center", fontsize=8.5, color="#B52B27", fontweight="bold")

    # Правая панель: Распределение CVSS-баллов уязвимостей из Vulners API
    vulns_sorted = vulners_df.sort_values(by="cvss_score", ascending=True)
    colors_cvss = [
        "#C0392B" if s >= 9.0 else ("#E67E22" if s >= CVSS_CRITICAL_THRESHOLD else "#5DADE2")
        for s in vulns_sorted["cvss_score"]
    ]
    bars_cvss = ax2.barh(vulns_sorted["cve_id"], vulns_sorted["cvss_score"], color=colors_cvss, height=0.55)
    ax2.axvline(
        CVSS_CRITICAL_THRESHOLD,
        color="#C0392B",
        linestyle="--",
        linewidth=1.3,
        label=f"Порог высокого риска (CVSS >= {CVSS_CRITICAL_THRESHOLD})",
    )
    ax2.set_xlim(0, 11.2)
    ax2.set_xlabel("Оценка уязвимости CVSS v3.1", fontsize=10.5, fontweight="bold")
    ax2.set_title("Распределение баллов уязвимостей (Vulners API)", fontsize=12, fontweight="bold", pad=12, color="#1B365D")
    ax2.legend(loc="lower right", frameon=True, fontsize=8.8)
    ax2.grid(axis="x", linestyle=":", alpha=0.6)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    for bar in bars_cvss:
        w = bar.get_width()
        ax2.text(w + 0.18, bar.get_y() + bar.get_height() / 2, f"{w:.1f}", va="center", fontsize=9, fontweight="bold")

    plt.suptitle(
        "Результаты автоматизированного мониторинга угроз (Suricata + VirusTotal + Vulners)",
        fontsize=13.5,
        fontweight="bold",
        y=0.99,
        color="#112233",
    )
    plt.tight_layout(rect=[0, 0, 1, 0.94])
    plt.savefig(chart_path, dpi=200)
    plt.close(fig)

    print(f"[INFO] Отчет CSV сохранен:  {csv_path}")
    print(f"[INFO] Отчет JSON сохранен: {json_path}")
    print(f"[INFO] График PNG сохранен: {chart_path}")
    return csv_path, json_path, chart_path


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    output_dir = base_dir

    print("[START] Запуск системы автоматизированного мониторинга и реагирования на угрозы...")
    suricata_path, vulners_cache_path, vt_cache_path = ensure_sample_data(data_dir)

    # Этап 1. Сбор данных
    suricata_df = load_suricata_logs(suricata_path)
    print(f"[INFO] Загружено {len(suricata_df)} сетевых событий из журнала Suricata ({suricata_path.name}).")
    vulners_df = fetch_vulners_vulnerabilities(vulners_cache_path)
    unique_ips = suricata_df["src_ip"].dropna().unique().tolist()
    vt_data = check_ips_virustotal(unique_ips, vt_cache_path)

    # Этап 2. Анализ данных
    ip_summary, critical_vulns, unified_df = analyze_threats(suricata_df, vulners_df, vt_data)

    print("\n--- Сводка анализа сетевых узлов (Suricata + VirusTotal) ---")
    print(ip_summary[["src_ip", "country", "dns_queries", "suricata_alerts", "vt_malicious", "risk_score", "is_threat"]].to_string(index=False))

    print("\n--- Обнаруженные опасные уязвимости (CVSS >= 7.0, Vulners API) ---")
    print(critical_vulns[["cve_id", "cvss_score", "affected_software", "exploit_available", "title"]].to_string(index=False))

    # Этап 3. Реагирование на угрозы
    actions_log = respond_to_threats(ip_summary, critical_vulns)

    # Этап 4. Формирование отчета и визуализация
    save_reports_and_chart(ip_summary, vulners_df, critical_vulns, unified_df, actions_log, output_dir)
    print("[DONE] Мониторинг успешно завершен.")


if __name__ == "__main__":
    main()
