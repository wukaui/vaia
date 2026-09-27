from __future__ import annotations

import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aiav.agent import build_agent
from aiav.budget import budget_from_env
from aiav.capa_data import capa_ready_or_note
from aiav.disposition import QUARANTINE_RISKS, StateStore, default_store
from aiav.models import RiskLevel
from aiav.report import write_reports
from aiav.scanner import compute_sha256, iter_files, scan_file, scan_files_concurrent


def _configure_console_encoding() -> None:
    """Windows 控制台默认代码页是 cp936，rich 输出中文和边框符号会乱码或抛 UnicodeEncodeError。

    这里把标准输出/错误改成 UTF-8 + 容错，保证在 cmd / PowerShell 里（含双击 exe）都能正常打印。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001 - 输出被重定向到不支持 reconfigure 的对象时忽略
            pass


_configure_console_encoding()
# `load_dotenv()` 从**调用它的文件**往上找 .env：源码运行 = 仓库根 ✅，
# pip 装的包 = site-packages/aiav/ 往上走到 / 都没有，工作目录的 .env 永远看不到 ❌。
load_dotenv()
load_dotenv(Path.cwd() / ".env")
load_dotenv(Path.home() / ".config" / "aiav" / ".env")

app = typer.Typer(help="轻量级 AI 恶意文件扫描 Agent", no_args_is_help=True)
quarantine_app = typer.Typer(help="隔离区：查看 / 还原被隔离的文件", no_args_is_help=True)
whitelist_app = typer.Typer(help="白名单：同一文件（同 sha256）不再反复报", no_args_is_help=True)
app.add_typer(quarantine_app, name="quarantine")
app.add_typer(whitelist_app, name="whitelist")
console = Console()


def _store(state_dir: Path | None) -> StateStore:
    return StateStore(state_dir) if state_dir else default_store()


@app.callback()
def main() -> None:
    """轻量级 AI 恶意文件扫描 Agent。"""
    pass


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=True, readable=True,
                                help="要扫描的文件或目录"),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="报告输出目录"),
    no_ai: bool = typer.Option(False, "--no-ai", help="只用规则扫描，不调用 LLM"),
    max_size_mb: int = typer.Option(50, "--max-size-mb", help="跳过超过该大小的文件"),
    include_system: bool = typer.Option(False, "--include-system", help="不跳过 Windows/Program Files 等目录"),
    ai_threshold: int = typer.Option(
        300,
        "--ai-threshold",
        help="①层判据分数达到多少才把文件交给 AI（Assemblyline 刻度）。"
             "默认 300 = 上游 verdict.suspicious = 老口径的 12（两条弱信号才过线）。"
             "调到 0 会退回旧行为：每个文件都送审。",
    ),
    deep_evidence_threshold: int = typer.Option(
        0, "--deep-evidence-threshold",
        help="分流·取证层：预筛分数低于它的文件只采轻量证据（PE 头/导入表/明文字符串/签名），"
             "不跑 capa/floss。0=不分流（全部深挖）。单位是 Assemblyline 刻度，"
             "300 = 老口径的 12"),
    model: str | None = typer.Option(None, "--model", help="覆盖 AGENT_MODEL"),
    base_url: str | None = typer.Option(None, "--base-url", help="覆盖 AGENT_BASE_URL"),
    workers: int = typer.Option(4, "--workers", "-w", help="AI Agent 并发数"),
    quarantine: str = typer.Option(
        "off", "--quarantine", help="处置闭环：off / malicious / suspicious（要把哪些判定的文件移入隔离区）"),
    apply: bool = typer.Option(False, "--apply", help="真正执行隔离（默认只做 dry-run，不移动文件）"),
    state_dir: Path | None = typer.Option(None, "--state-dir", help="状态目录（默认 ~/ai-av-bench/ai-av-state）"),
    samples: int = typer.Option(0, "--samples", help="AI 多次采样取多数票（0=用 AI_AV_AGENT_SAMPLES，默认 1；建议 3）"),
    token_budget: int = typer.Option(0, "--token-budget", help="token 预算硬闸（0=用 AI_AV_TOKEN_BUDGET，默认不限）"),
    no_history: bool = typer.Option(False, "--no-history", help="不写扫描历史"),
    no_deterministic: bool = typer.Option(
        False, "--no-deterministic",
        help="消融/研究用：关掉全部确定性后处理（策略兜底 + 脱壳/压缩包抬升），结论只取模型原始输出"),
) -> None:
    """扫描一个文件或目录，输出 JSON + HTML 报告；可选地把命中项移入隔离区。"""

    agent = None
    if no_ai:
        console.print("[yellow]已禁用 AI Agent，仅使用规则预筛。[/yellow]")
    else:
        try:
            agent = build_agent(model_name=model, base_url=base_url)
            console.print(f"[green]AI Agent 已启用：{model or 'AGENT_MODEL'}[/green]")
        except Exception as exc:
            console.print(f"[yellow]AI Agent 未启用，降级为规则扫描：{exc}[/yellow]")

    # capa 缺失要在扫描开始就吼，别安静地少一个工具
    if agent is not None:
        capa_note = capa_ready_or_note()
        if capa_note:
            console.print(f"[yellow]{capa_note} 修复：`aiav capa-setup`[/yellow]")

    # 状态目录要在扫描前确定：白名单判定发生在 scan_file 内部，必须用同一个 store，
    # 否则 --state-dir 只影响处置、却让"加白名单免扫"仍然走默认目录（实测踩过）。
    store = _store(state_dir)

    # 跳过记账（外部审查 P4）：iter_files 会静默跳过 >max-size 的文件与点开头/系统目录，
    # 这里把"跳过了什么、各多少"接住，写进报告 —— 只加计数，不改过滤规则、不动判决。
    skip_stats: dict[str, int] = {}
    if path.is_file():
        files = [path]
    else:
        files = list(iter_files(path, max_size_mb=max_size_mb, include_system=include_system,
                                skip_stats=skip_stats))
    console.print(f"共发现 {len(files)} 个文件，开始扫描...")
    if skip_stats:
        skipped = sum(skip_stats.values())
        detail = "、".join(f"{k} {v}" for k, v in sorted(skip_stats.items()))
        console.print(f"[yellow]另有 {skipped} 项未进扫描（{detail}）；已记入报告的 scan_skips 字段[/yellow]")

    budget = budget_from_env() if token_budget <= 0 else None
    if token_budget > 0:
        from aiav.budget import TokenBudget

        budget = TokenBudget(limit=token_budget)
    if budget is not None and agent is not None:
        est = budget.estimate(len(files))
        if not est["unlimited"]:
            flag = "[red]超过预算！[/red]" if est["exceeds"] else "[green]在预算内[/green]"
            console.print(
                f"[cyan]Token 预算：上限 {est['limit']:,}，按 {est['est_per_file']:,}/文件估算 "
                f"本次约 {est['est_tokens']:,}（{flag}）；超出后自动降级为规则判定[/cyan]")

    reports = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("扫描中", total=max(len(files), 1))

        use_parallel = agent is not None and workers > 1 and len(files) > 1
        if use_parallel:
            agent_factory = lambda: build_agent(model_name=model, base_url=base_url)
            console.print(f"[cyan]使用 {workers} 个并发 Agent 扫描...[/cyan]")
            reports = scan_files_concurrent(
                files, agent_factory=agent_factory, ai_threshold=ai_threshold, workers=workers,
                agent_samples=samples or None, budget=budget, store=store,
                deterministic=not no_deterministic,
                deep_evidence_threshold=deep_evidence_threshold,
            )
            progress.advance(task, len(files))
            for file_path, report in zip(files, reports):
                if report.verdict.risk != RiskLevel.clean:
                    color = "red" if report.verdict.risk == RiskLevel.malicious else "yellow"
                    console.print(
                        f"[{color}]{report.verdict.risk.value.upper():<10}[/{color}] {file_path}"
                    )
        else:
            for file_path in files:
                report = scan_file(file_path, agent=agent, ai_threshold=ai_threshold,
                                   agent_samples=samples or None, budget=budget, store=store,
                                   deterministic=not no_deterministic,
                                   deep_evidence_threshold=deep_evidence_threshold)
                reports.append(report)
                progress.advance(task)

                if report.verdict.risk != RiskLevel.clean:
                    color = "red" if report.verdict.risk == RiskLevel.malicious else "yellow"
                    console.print(
                        f"[{color}]{report.verdict.risk.value.upper():<10}[/{color}] {file_path}"
                    )

    extra: dict = {}
    if budget is not None:
        extra["token_budget"] = budget.as_dict()
    if skip_stats:
        # 口径可查：报告里能看出"总数"之外还有多少东西被跳过了、为什么
        extra["scan_skips"] = {
            "total": sum(skip_stats.values()),
            "by_reason": dict(sorted(skip_stats.items())),
            "max_size_mb": max_size_mb,
            "include_system": include_system,
        }
    json_path, html_path, audit_path = write_reports(reports, output, extra=extra or None)

    # ---------------- 处置闭环 ----------------
    target_risk = quarantine.strip().lower()
    if target_risk not in ("off", "", *QUARANTINE_RISKS):
        console.print(f"[red]--quarantine 只支持 off / malicious / suspicious，收到: {target_risk}[/red]")
        raise typer.Exit(code=2)
    if target_risk not in ("off", ""):
        to_quarantine = [r for r in reports if r.verdict.risk.value == target_risk]
        if not to_quarantine:
            console.print(f"[green]没有 {target_risk} 级别的文件需要隔离。[/green]")
        else:
            mode = "执行隔离" if apply else "dry-run（不会移动文件，加 --apply 才真动）"
            console.print(f"[bold]处置：{len(to_quarantine)} 个 {target_risk} → 隔离区（{mode}）[/bold]")
            q_table = Table(title="处置动作")
            for col in ("文件", "动作", "结果", "隔离 ID"):
                q_table.add_column(col)
            for r in to_quarantine:
                plan = store.quarantine_file(
                    Path(r.path), r.sha256, scan_root=path,
                    risk=r.verdict.risk.value, category=r.verdict.category,
                    summary=r.verdict.summary,
                    basis=[str(e) for e in (r.verdict.evidence or [])[:4]],
                    report_path=str(json_path), apply=apply,
                )
                if plan.get("error"):
                    q_table.add_row(Path(r.path).name, "拒绝", plan["error"][:60], "-")
                elif plan.get("already_quarantined"):
                    q_table.add_row(Path(r.path).name, "skip", "此前已隔离", plan["already_quarantined"])
                elif plan.get("applied"):
                    r.disposition = {"status": "quarantined", "id": plan.get("id"),
                                     "quarantine_path": plan.get("quarantine_path"),
                                     "at": plan.get("quarantined_at")}
                    q_table.add_row(Path(r.path).name, "隔离", "已移入隔离区", str(plan.get("id")))
                else:
                    r.disposition = {"status": "quarantine_planned", "target": plan.get("planned_target")}
                    q_table.add_row(Path(r.path).name, "计划", "dry-run 未移动", "-")
            console.print(q_table)
            # 处置状态写回报告
            write_reports(reports, output, extra=extra)

    if not no_history:
        store.record_history({
            "scan_dir": str(path),
            "total": len(reports),
            "clean": sum(1 for r in reports if r.verdict.risk == RiskLevel.clean),
            "suspicious": sum(1 for r in reports if r.verdict.risk == RiskLevel.suspicious),
            "malicious": sum(1 for r in reports if r.verdict.risk == RiskLevel.malicious),
            "agent_used": sum(1 for r in reports if r.agent_used),
            "report_json": str(json_path),
            "quarantine_mode": target_risk or "off",
            "quarantine_applied": bool(apply and target_risk not in ("off", "")),
        })

    table = Table(title="扫描结果")
    table.add_column("指标", style="cyan")
    table.add_column("数量", justify="right")
    table.add_row("总数", str(len(reports)))
    table.add_row("安全", str(sum(1 for r in reports if r.verdict.risk == RiskLevel.clean)))
    table.add_row("可疑", str(sum(1 for r in reports if r.verdict.risk == RiskLevel.suspicious)))
    table.add_row("恶意", str(sum(1 for r in reports if r.verdict.risk == RiskLevel.malicious)))
    table.add_row("AI 研判", str(sum(1 for r in reports if r.agent_used)))
    if budget is not None and not budget.unlimited:
        table.add_row("Token 预算", f"{budget.used:,} / {budget.limit:,}"
                                    + (f"（预算耗尽，跳过 {budget.skipped_files} 个文件的 AI）"
                                       if budget.skipped_files else ""))
    multi = [r for r in reports if (r.sampling or {}).get("samples", 1) > 1]
    if multi:
        agree = sum((r.sampling or {}).get("agreement", 1.0) for r in multi) / len(multi)
        table.add_row(f"多次采样（{multi[0].sampling.get('samples')} 次）",
                      f"{len(multi)} 个，平均一致性 {agree*100:.0f}%")
    console.print(table)

    console.print(f"JSON 报告: [bold]{json_path}[/bold]")
    console.print(f"HTML 报告: [bold]{html_path}[/bold]")
    console.print(f"审计全文: [bold]{audit_path}[/bold] [dim]（工具调用链 + 证据原始片段）[/dim]")



# =========================
# 处置闭环子命令
# =========================
@quarantine_app.command("list")
def quarantine_list(
    state_dir: Path | None = typer.Option(None, "--state-dir"),
    all_records: bool = typer.Option(False, "--all", help="包含已还原的记录"),
) -> None:
    """列出隔离区内容。"""
    store = _store(state_dir)
    records = [r for r in store.records() if all_records or r.get("status") == "quarantined"]
    if not records:
        console.print(f"[green]隔离区是空的（{store.root}）[/green]")
        return
    table = Table(title=f"隔离区（{store.root}）")
    for col in ("ID", "风险", "状态", "文件", "SHA256", "隔离时间"):
        table.add_column(col)
    for r in records:
        table.add_row(r.get("id", "-"), r.get("risk", "-"), r.get("status", "-"),
                      Path(r.get("original_path", "")).name, str(r.get("sha256", ""))[:12],
                      r.get("quarantined_at", "-"))
    console.print(table)


@quarantine_app.command("show")
def quarantine_show(
    key: str = typer.Argument(..., help="隔离 ID（q-0001）或 sha256 前缀"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """查看某条隔离记录的完整元数据（含判定依据）。"""
    record = _store(state_dir).find(key)
    if not record:
        console.print(f"[red]找不到隔离记录: {key}[/red]")
        raise typer.Exit(code=1)
    console.print_json(data=record)


@quarantine_app.command("restore")
def quarantine_restore(
    key: str = typer.Argument(..., help="隔离 ID（q-0001）或 sha256 前缀"),
    apply: bool = typer.Option(False, "--apply", help="真正还原（默认只做 dry-run）"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """把隔离的文件还原回原路径（校验 sha256）。"""
    plan = _store(state_dir).restore(key, apply=apply)
    if plan.get("error"):
        console.print(f"[red]{plan['error']}[/red]")
        raise typer.Exit(code=1)
    if plan.get("applied"):
        console.print(f"[green]已还原 {plan['id']}: {plan['from']} → {plan['to']}[/green]")
    else:
        console.print(f"[yellow]dry-run：{plan['from']} → {plan['to']}（加 --apply 才真动）[/yellow]")


@whitelist_app.command("add")
def whitelist_add(
    target: str = typer.Argument(..., help="文件路径或完整 sha256"),
    reason: str = typer.Option("", "--reason", "-r", help="加白理由（会写进报告）"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """把文件加入白名单：之后同一 sha256 不再送 AI、不再报可疑。"""
    store = _store(state_dir)
    sha = target.lower()
    path_str = ""
    if len(sha) != 64:
        p = Path(target).expanduser()
        if not p.is_file():
            console.print(f"[red]既不是 sha256 也不是存在的文件: {target}[/red]")
            raise typer.Exit(code=1)
        sha = compute_sha256(p)
        path_str = str(p)
    entry = store.whitelist_add(sha, path=path_str, reason=reason)
    if entry.get("already"):
        console.print(f"[yellow]已在白名单: {sha[:16]}…[/yellow]")
    else:
        console.print(f"[green]已加入白名单: {sha[:16]}… ({reason or '无理由'})[/green]")


@whitelist_app.command("list")
def whitelist_list(state_dir: Path | None = typer.Option(None, "--state-dir")) -> None:
    """列出白名单。"""
    items = _store(state_dir).whitelist()
    if not items:
        console.print("[green]白名单是空的[/green]")
        return
    table = Table(title="白名单")
    for col in ("SHA256", "文件", "理由", "加入时间"):
        table.add_column(col)
    for i in items:
        table.add_row(str(i.get("sha256", ""))[:16], Path(i.get("path", "") or "-").name,
                      i.get("reason", "") or "-", i.get("added_at", "-"))
    console.print(table)


@whitelist_app.command("remove")
def whitelist_remove(
    sha256: str = typer.Argument(..., help="要移除的 sha256"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """从白名单移除。"""
    res = _store(state_dir).whitelist_remove(sha256)
    console.print(f"[green]移除 {res['removed']} 条[/green]" if res["removed"] else "[yellow]没找到该 sha256[/yellow]")


@app.command("history")
def history_cmd(
    limit: int = typer.Option(20, "--limit", "-n", help="显示最近多少条"),
    json_out: bool = typer.Option(False, "--json", help="输出原始 JSON"),
    state_dir: Path | None = typer.Option(None, "--state-dir"),
) -> None:
    """查看扫描历史（每次 scan 追加一条）。"""
    entries = _store(state_dir).history(limit=limit)
    if not entries:
        console.print("[green]还没有扫描历史[/green]")
        return
    if json_out:
        console.print_json(data=entries)
        return
    table = Table(title="扫描历史")
    for col in ("时间", "目录", "总数", "安全", "可疑", "恶意", "AI", "隔离模式"):
        table.add_column(col)
    for e in entries:
        table.add_row(e.get("recorded_at", "-"), str(e.get("scan_dir", "-"))[-40:],
                      str(e.get("total", "-")), str(e.get("clean", "-")),
                      str(e.get("suspicious", "-")), str(e.get("malicious", "-")),
                      str(e.get("agent_used", "-")),
                      f"{e.get('quarantine_mode', 'off')}{'(已执行)' if e.get('quarantine_applied') else ''}")
    console.print(table)


@app.command("tools")
def tools_cmd() -> None:
    """列出全部工具与检测项的本机状态 —— 哪些会交给 AI，哪些根本没跑。"""
    from aiav.capa_data import status as capa_status
    from aiav.tools import ALL_TOOLS, available_tools, unavailable_detections

    live = {t.__name__ for t in available_tools()}
    table = Table(title="工具表（按本机环境过滤后的真实状态）")
    table.add_column("工具")
    table.add_column("交给 AI")
    table.add_column("说明")
    for t in ALL_TOOLS:
        doc = (t.__doc__ or "").strip().splitlines()
        table.add_row(
            t.__name__,
            "[green]是[/green]" if t.__name__ in live else "[red]否[/red]",
            doc[0] if doc else "",
        )
    console.print(table)

    ok, line = capa_status()
    console.print(("[green]" if ok else "[red]") + line + "[/]")
    missing = unavailable_detections()
    if missing:
        console.print("[yellow]未执行的检测（不是「跑了没问题」，是「没跑」）：[/yellow]")
        for item in missing:
            console.print(f"  · {item}")


@app.command("capa-setup")
def capa_setup(
    version: str | None = typer.Option(None, "--version", help="capa 版本号，默认取本机 capa 二进制"),
    force: bool = typer.Option(False, "--force", help="已有的语料也重下"),
) -> None:
    """拉取 capa 的规则集与签名集（必装语料，pip 包不自带）。"""
    from aiav.capa_data import fetch

    ok, message = fetch(version=version, force=force)
    console.print(("[green]✓ " if ok else "[red]✗ ") + message + "[/]")
    if not ok:
        raise typer.Exit(code=1)


# 说明：`compute_sha256` 直接由上面 `from aiav.scanner import ...` 引入，与 `aiav.scanner` 里是
# **同一个函数对象**。旧写法是一个兼容 shim（`def _compute_sha256` 内部再 import 再赋值回来），
# 绕且没有额外语义。对外行为不变：`cli.compute_sha256` 仍然存在、可调用。


if __name__ == "__main__":
    app()
