import os
import uuid
from datetime import date, datetime
from urllib.parse import urlparse
import requests

def ensure_dirs():
    base_dir = "configs"
    today_str = date.today().isoformat()
    day_dir = os.path.join(base_dir, today_str)
    os.makedirs(day_dir, exist_ok=True)
    return base_dir, today_str, day_dir

def make_random_output_path(day_dir: str, url: str) -> str:
    path = urlparse(url).path
    ext = os.path.splitext(path)[1] or ".txt"
    return os.path.join(day_dir, f"{uuid.uuid4().hex}{ext}")

def download_first_working(urls, day_dir, timeout=30):
    last_error = None
    for u in urls:
        try:
            r = requests.get(u, timeout=timeout)
            r.raise_for_status()
            out_path = make_random_output_path(day_dir, u)
            with open(out_path, "wb") as f:
                f.write(r.content)
            return u, out_path, len(r.content)
        except requests.RequestException as e:
            last_error = e
            print(f"Failed: {u} -> {e}")
    raise RuntimeError(f"All URLs failed. Last error: {last_error}")

def list_txt_files(day_dir: str):
    if not os.path.isdir(day_dir):
        return []
    files = []
    for name in sorted(os.listdir(day_dir)):
        p = os.path.join(day_dir, name)
        if os.path.isfile(p) and name.lower().endswith(".txt"):
            files.append(p)
    return files

def choose_file(files):
    if not files:
        return None
    print("\nChoose a file to scan:")
    for i, f in enumerate(files, start=1):
        print(f"  {i}) {f}")
    while True:
        s = input("Enter number (or blank to cancel): ").strip()
        if not s:
            return None
        if s.isdigit():
            i = int(s)
            if 1 <= i <= len(files):
                return files[i - 1]
        print("Invalid choice.")

def main():
    URLS = [
        "https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",
    ]

    base_dir, today_str, day_dir = ensure_dirs()

    print("1) Fetch new configs")
    print("2) Scan existing file")
    choice = input("Choose (1/2): ").strip()

    if choice == "1":
        used_url, output_path, nbytes = download_first_working(URLS, day_dir, timeout=30)
        print(f"\nDownloaded from: {used_url}")
        print(f"Saved to: {output_path} ({nbytes} bytes)\n")
        from utils.scanner import scan_file
        scan_file(output_path, base_dir, today_str, day_dir)
        return

    if choice == "2":
        files = list_txt_files(day_dir)
        picked = choose_file(files)
        if not picked:
            print("No file selected.")
            return
        from utils.scanner import scan_file
        scan_file(picked, base_dir, today_str, day_dir)
        return

    print("Unknown option.")

if __name__ == "__main__":
    main()
