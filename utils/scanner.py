import os
import signal
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from .scanner_core import Endpoint, ScanResult, extract_endpoints, measure_tcp, measure_udp
from .singbox_tools import has_singbox, real_download_test


# ============================================================
# Configuration
# ============================================================
DEFAULT_WORKERS = 16
CHUNK_SIZE = 20

TCP_TRIES = 2
TCP_TIMEOUT = 3.0

ENABLE_UDP = False
UDP_TIMEOUT = 2.0

ENABLE_DOWNLOAD_TEST = True
DOWNLOAD_TEST_URL = "https://www.google.com/generate_204"
DOWNLOAD_TIMEOUT = 12.0
SINGBOX_BIN = "sing-box"

SCAN_ROOT = "scan_results"


# ============================================================
# Console
# ============================================================
console = Console()


# ============================================================
# Output Directories
# ============================================================
def ensure_scan_dirs() -> Tuple[str, str, str, str]:
    os.makedirs(SCAN_ROOT, exist_ok=True)

    results_dir = os.path.join(SCAN_ROOT, "results")
    whitelist_dir = os.path.join(SCAN_ROOT, "whitelist")
    failed_dir = os.path.join(SCAN_ROOT, "failed")

    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(whitelist_dir, exist_ok=True)
    os.makedirs(failed_dir, exist_ok=True)

    return SCAN_ROOT, results_dir, whitelist_dir, failed_dir


# ============================================================
# Pretty formatting (rich cells)
# ============================================================
def fmt_ms(v: Optional[float]) -> str:
    return f"{v:.0f} ms" if v is not None else "—"


def scheme_cell(ep: Endpoint) -> str:
    s = ep.scheme.upper()
    if ep.scheme == "vmess":
        return f"[cyan]{s}[/]"
    if ep.scheme == "vless":
        return f"[magenta]{s}[/]"
    if ep.scheme == "trojan":
        return f"[yellow]{s}[/]"
    if ep.scheme == "ss":
        return f"[blue]{s}[/]"
    return s


def status_cell(r: ScanResult) -> str:
    return "[bold green]ALIVE[/]" if r.alive else "[bold red]DEAD[/]"


def dl_cell(r: ScanResult) -> str:
    if not (ENABLE_DOWNLOAD_TEST and has_singbox(SINGBOX_BIN)):
        return "[dim]skipped[/]"
    if r.dl_ok:
        hs = f" ({r.http_status})" if r.http_status is not None else ""
        return f"[green]✓[/] {fmt_ms(r.dl_ms)}{hs}"
    return f"[red]✗[/] [dim]{r.dl_reason}[/]"


# ============================================================
# Save helpers (append each chunk into SAME files)
# ============================================================
def init_output_files(results_path: str, whitelist_path: str, failed_path: str) -> None:

    with open(results_path, "w", encoding="utf-8") as out:
        out.write("status\tscheme\tnetwork\thost\tport\ttcp_avg_ms\ttcp_fails\tudp\tudp_ms\tdl\tdl_ms\thttp\n")

    open(whitelist_path, "w", encoding="utf-8").close()
    open(failed_path, "w", encoding="utf-8").close()


def append_chunk_outputs(
    results_path: str,
    whitelist_path: str,
    failed_path: str,
    chunk_results: List[ScanResult],
) -> Tuple[int, int]:
    alive_lines: List[str] = []
    failed_lines: List[str] = []

    with open(results_path, "a", encoding="utf-8") as out:
        for r in chunk_results:
            out.write(
                f"{'ALIVE' if r.alive else 'DEAD'}\t{r.ep.scheme}\t{r.ep.network}\t{r.ep.host}\t{r.ep.port}\t"
                f"{r.tcp_avg_ms if r.tcp_avg_ms is not None else ''}\t{r.tcp_fails}\t"
                f"{r.udp_status}\t{r.udp_avg_ms if r.udp_avg_ms is not None else ''}\t"
                f"{r.dl_reason}\t{r.dl_ms if r.dl_ms is not None else ''}\t{r.http_status if r.http_status is not None else ''}\n"
            )

            if r.alive:
                alive_lines.append(r.ep.raw_line)
            else:
                failed_lines.append(r.ep.raw_line)

    if alive_lines:
        with open(whitelist_path, "a", encoding="utf-8") as wf:
            wf.write("\n".join(alive_lines) + "\n")

    if failed_lines:
        with open(failed_path, "a", encoding="utf-8") as ff:
            ff.write("\n".join(failed_lines) + "\n")

    return len(alive_lines), len(failed_lines)


# ============================================================
# Single scan
# ============================================================
def scan_one(idx: int, total: int, ep: Endpoint) -> ScanResult:
    tcp_avg, tcp_fails = measure_tcp(ep.host, ep.port, tries=TCP_TRIES, timeout=TCP_TIMEOUT)

    if ENABLE_UDP:
        udp_avg, udp_status = measure_udp(ep.host, ep.port, timeout=UDP_TIMEOUT)
    else:
        udp_avg, udp_status = None, "off"

    dl_ok, dl_reason, dl_ms, http_status = real_download_test(
        ep,
        enabled=ENABLE_DOWNLOAD_TEST,
        bin_name=SINGBOX_BIN,
        test_url=DOWNLOAD_TEST_URL,
        timeout=DOWNLOAD_TIMEOUT,
    )

    return ScanResult(
        idx=idx,
        total=total,
        ep=ep,
        tcp_avg_ms=tcp_avg,
        tcp_fails=tcp_fails,
        udp_avg_ms=udp_avg,
        udp_status=udp_status,
        dl_ok=dl_ok,
        dl_reason=dl_reason,
        dl_ms=dl_ms,
        http_status=http_status,
    )


# ============================================================
# Print chunk table
# ============================================================
def print_chunk(chunk_results: List[ScanResult], chunk_idx: int, chunk_total: int) -> None:
    c_alive = sum(1 for r in chunk_results if r.alive)
    c_dead = len(chunk_results) - c_alive

    console.print(
        Panel(
            f"[bold]Chunk {chunk_idx}/{chunk_total}[/]  "
            f"[bold green]ALIVE[/]: {c_alive}  [bold red]DEAD[/]: {c_dead}",
            expand=False,
        )
    )

    table = Table(title=f"Chunk {chunk_idx}/{chunk_total} Results")
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Status", width=8)
    table.add_column("Type", width=7)
    table.add_column("Host:Port", overflow="fold")
    table.add_column("Net", width=6)
    table.add_column("TCP", justify="right", width=12)
    table.add_column("Download", overflow="fold")

    chunk_sorted = sorted(chunk_results, key=lambda x: (not x.alive, x.idx))
    for r in chunk_sorted:
        tcp = fmt_ms(r.tcp_avg_ms)
        if r.tcp_fails:
            tcp += f" [yellow]({r.tcp_fails} fail)[/]"
        table.add_row(
            str(r.idx),
            status_cell(r),
            scheme_cell(r.ep),
            f"{r.ep.host}:{r.ep.port}",
            r.ep.network,
            tcp,
            dl_cell(r),
        )

    console.print(table)


# ============================================================
# Main Entry (used by app.py)
# ============================================================
def scan_file(
    input_txt: str,
    base_dir: str,
    today_str: str,
    day_dir: str,
    workers: int = DEFAULT_WORKERS,
    chunk_size: int = CHUNK_SIZE,
):
    scan_root, results_dir, whitelist_dir, failed_dir = ensure_scan_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    results_path = os.path.join(results_dir, f"results_{ts}.tsv")
    whitelist_path = os.path.join(whitelist_dir, f"whitelist_{ts}.txt")
    failed_path = os.path.join(failed_dir, f"failed_{ts}.txt")

    with open(input_txt, "r", encoding="utf-8", errors="replace") as f:
        endpoints = extract_endpoints(f.read().splitlines())

    total = len(endpoints)
    sb = has_singbox(SINGBOX_BIN)

    console.print(
        Panel(
            "\n".join(
                [
                    "[bold cyan]SCAN (chunked + incremental save)[/]",
                    f"[dim]File:[/] {input_txt}",
                    f"[dim]Configs:[/] {total}    [dim]Workers:[/] {workers}    [dim]Chunk:[/] {chunk_size}",
                    f"[dim]sing-box:[/] {'[green]YES[/]' if sb else '[red]NO[/]'}",
                    f"[dim]Output:[/] {scan_root}/ (results/ whitelist/ failed/)",
                ]
            ),
            expand=False,
        )
    )

    if total == 0:
        console.print(Panel("[yellow]No configs found in the file.[/]", expand=False))
        return

    init_output_files(results_path, whitelist_path, failed_path)

    stop_now = False

    def _handle_sigint(signum, frame):
        nonlocal stop_now
        stop_now = True

    old_handler = signal.signal(signal.SIGINT, _handle_sigint)

    alive_total = 0
    dead_total = 0
    done_total = 0

    try:
        chunks = [endpoints[i : i + chunk_size] for i in range(0, total, chunk_size)]
        chunk_total = len(chunks)

        for ci, chunk_eps in enumerate(chunks, start=1):
            if stop_now:
                break

            progress = Progress(
                SpinnerColumn(),
                TextColumn(f"[bold]Scanning chunk {ci}/{chunk_total}[/]"),
                BarColumn(),
                TextColumn("done {task.completed}/{task.total}"),
                TextColumn("[dim green]alive[/] {task.fields[alive]}"),
                TextColumn("[dim red]dead[/] {task.fields[dead]}"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
            )

            chunk_alive = 0
            chunk_dead = 0
            chunk_results: List[ScanResult] = []

            with progress:
                task = progress.add_task("scan", total=len(chunk_eps), alive=0, dead=0)

                with ThreadPoolExecutor(max_workers=workers) as ex:
                    futures = []
                    for offset, ep in enumerate(chunk_eps):
                        if stop_now:
                            break
                        global_idx = (ci - 1) * chunk_size + offset + 1  # 1-based index
                        futures.append(ex.submit(scan_one, global_idx, total, ep))

                    pending = set(futures)

                    while pending and not stop_now:
                        done_set, pending = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                        for fut in done_set:
                            try:
                                r = fut.result()
                            except Exception:
                                chunk_dead += 1
                                dead_total += 1
                                done_total += 1
                                progress.advance(task, 1)
                                progress.update(task, alive=chunk_alive, dead=chunk_dead)
                                continue

                            chunk_results.append(r)

                            done_total += 1
                            if r.alive:
                                chunk_alive += 1
                                alive_total += 1
                            else:
                                chunk_dead += 1
                                dead_total += 1

                            progress.advance(task, 1)
                            progress.update(task, alive=chunk_alive, dead=chunk_dead)

                    if stop_now:
                        console.print("[yellow]\nStopping... cancelling pending tasks.[/]")
                        for fut in pending:
                            fut.cancel()
                        ex.shutdown(wait=False, cancel_futures=True)

            if chunk_results:
                print_chunk(chunk_results, ci, chunk_total)

                saved_alive, saved_dead = append_chunk_outputs(
                    results_path, whitelist_path, failed_path, chunk_results
                )

                console.print(
                    Panel(
                        "\n".join(
                            [
                                f"[bold]Saved chunk {ci}/{chunk_total}[/]  "
                                f"[dim]({saved_alive} alive, {saved_dead} dead)[/]",
                                f"[dim]Results:[/]   {results_path}",
                                f"[dim]Whitelist:[/] {whitelist_path}",
                                f"[dim]Failed:[/]    {failed_path}",
                            ]
                        ),
                        expand=False,
                    )
                )

            console.print(
                Panel(
                    f"[bold]Total so far[/]  "
                    f"[bold green]ALIVE[/]: {alive_total}/{done_total}    "
                    f"[bold red]DEAD[/]: {dead_total}/{done_total}",
                    expand=False,
                )
            )

    finally:
        signal.signal(signal.SIGINT, old_handler)

    console.print(
        Panel(
            "\n".join(
                [
                    "[bold]DONE[/]" if not stop_now else "[bold yellow]STOPPED[/]",
                    f"[bold green]ALIVE[/]: {alive_total}/{done_total}    [bold red]DEAD[/]: {dead_total}/{done_total}",
                    "",
                    "[bold]FILES SAVED[/]",
                    f"[dim]Results:[/]   {results_path}",
                    f"[dim]Whitelist:[/] {whitelist_path}",
                    f"[dim]Failed:[/]    {failed_path}",
                ]
            ),
            expand=False,
        )
    )
