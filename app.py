import os
import uuid
import json
import hashlib
from datetime import date
from urllib.parse import urlparse

import requests

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def colorize(text: str, col: str) -> str:
    return f"{col}{text}{C.RESET}"


def ensure_dirs():
    base_dir = "configs"
    today_str = date.today().isoformat()
    day_dir = os.path.join(base_dir, today_str)
    os.makedirs(day_dir, exist_ok=True)
    return base_dir, today_str, day_dir


def safe_ext_from_url(url: str) -> str:
    path = urlparse(url).path
    ext = os.path.splitext(path)[1].lower()
    if not ext or len(ext) > 5:
        return ".txt"
    return ext


def stable_name_for_url(url: str) -> str:
    h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
    ext = safe_ext_from_url(url)
    return f"source_{h}{ext}"


def manifest_path(day_dir: str) -> str:
    return os.path.join(day_dir, "_manifest.json")


def load_manifest(day_dir: str) -> dict:
    p = manifest_path(day_dir)
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_manifest(day_dir: str, data: dict) -> None:
    p = manifest_path(day_dir)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def download_all_once_per_day(urls, day_dir, timeout=30, skip_if_downloaded_today=True):
    man = load_manifest(day_dir)
    results = []

    headers = {
        "User-Agent": "configs-fetcher/1.0",
        "Accept": "*/*",
    }

    for url in urls:
        out_path = os.path.join(day_dir, stable_name_for_url(url))

        if skip_if_downloaded_today:
            prev = man.get(url)
            if prev and os.path.isfile(prev):
                results.append(
                    {"url": url, "path": prev, "bytes": os.path.getsize(prev), "status": "skipped", "error": None}
                )
                continue

        try:
            r = requests.get(url, timeout=timeout, headers=headers)
            r.raise_for_status()

            # Write
            with open(out_path, "wb") as f:
                f.write(r.content)

            man[url] = out_path
            results.append(
                {"url": url, "path": out_path, "bytes": len(r.content), "status": "downloaded", "error": None}
            )

        except requests.RequestException as e:
            results.append({"url": url, "path": None, "bytes": 0, "status": "failed", "error": str(e)})

    save_manifest(day_dir, man)
    return results


def list_txt_files(day_dir: str):
    if not os.path.isdir(day_dir):
        return []
    files = []
    for name in sorted(os.listdir(day_dir)):
        p = os.path.join(day_dir, name)
        if os.path.isfile(p) and name.lower().endswith(".txt") and not name.startswith("_"):
            files.append(p)
    return files


def choose_file(files):
    if not files:
        return None

    print(colorize("\nChoose a file to scan:", C.CYAN))
    for i, f in enumerate(files, start=1):
        print(f"  {colorize(str(i), C.YELLOW)}) {f}")

    while True:
        s = input(colorize("Enter number (or blank to cancel): ", C.BLUE)).strip()
        if not s:
            return None
        if s.isdigit():
            i = int(s)
            if 1 <= i <= len(files):
                return files[i - 1]
        print(colorize("Invalid choice.", C.RED))


def print_results(results):
    ok = [r for r in results if r["status"] in ("downloaded", "skipped")]
    bad = [r for r in results if r["status"] == "failed"]

    print(colorize("\nResults:", C.BOLD))
    for r in results:
        status = r["status"]
        if status == "downloaded":
            s = colorize("DOWNLOADED", C.GREEN)
        elif status == "skipped":
            s = colorize("SKIPPED", C.GRAY)
        else:
            s = colorize("FAILED", C.RED)

        line = f"- {s} {colorize(r['url'], C.CYAN)}"
        print(line)
        if r["path"]:
            print(f"  {colorize('->', C.GRAY)} {r['path']} ({r['bytes']} bytes)")
        if r["error"]:
            print(f"  {colorize('!!', C.RED)} {r['error']}")

    print(colorize(f"\nSummary: {len(ok)} ok, {len(bad)} failed\n", C.BOLD))


def main():
    URLS = [
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    ]

    base_dir, today_str, day_dir = ensure_dirs()

    print(colorize(f"\nConfigs folder: {day_dir}\n", C.DIM))
    print(colorize("1) Fetch new configs", C.YELLOW))
    print(colorize("2) Scan existing file", C.YELLOW))

    choice = input(colorize("Choose (1/2): ", C.BLUE)).strip()

    if choice == "1":
        skip_if_downloaded_today = False

        results = download_all_once_per_day(
            URLS,
            day_dir,
            timeout=30,
            skip_if_downloaded_today=skip_if_downloaded_today,
        )
        print_results(results)
        return

    if choice == "2":
        files = list_txt_files(day_dir)
        picked = choose_file(files)
        if not picked:
            print(colorize("No file selected.", C.RED))
            return
        from utils.scanner import scan_file
        scan_file(picked, base_dir, today_str, day_dir)
        return

    print(colorize("Unknown option.", C.RED))


if __name__ == "__main__":
    main()
