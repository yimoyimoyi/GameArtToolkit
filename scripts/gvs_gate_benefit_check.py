# -*- coding: utf-8 -*-
"""
GameArt Toolkit - 两个候选实装项的**收益测量 / 回归判据**脚本 (只读)

用途: 在决定是否实装之前量化收益; 实装后同一脚本即成为回归判据。
本脚本不修改代码、不写配置、不发起任何网络请求 —— 只读模块常量、已落盘成绩单
与冻结的探测语料 (tests/data/gvs_probe_ip_corpus.json)。

两个被测候选:
  A. 闸门接线 (缺陷 L3): `gvs_health_hint(services)` 收了 services 参数却从不使用
     ⇒ 开关**任何**服务都弹 googlevideo 的告警。
  B. 投毒前缀表合并: `h3_upstream._DNS_POISON_PREFIX` 与
     `cdn_optimizer.POLLUTED_IP_PREFIXES` 是两份表, 存在不对称。

运行: python -X utf8 scripts/gvs_gate_benefit_check.py
退出码: 0 = 当前代码已满足全部判据; 1 = 存在未满足判据 (即"收益仍在")
"""

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "app"))
sys.path.insert(0, str(_ROOT))

_CORPUS_PATH = _ROOT / "tests" / "data" / "gvs_probe_ip_corpus.json"


# ===========================================================================
# 测量 A: 闸门接线
# ===========================================================================
def check_gate_wiring() -> list:
    """返回未满足的判据列表 (空 = 接线正确)"""
    import h3_upstream as H

    failures = []
    sb = H._NodeScoreboard()

    # 判据 A1: 为**非** googlevideo 的服务求解时, 必须返回空串。
    #   现状: 返回同一段 googlevideo 文案 ⇒ 任意服务开关都会弹该告警。
    for sid in ("gemini", "netflix", "pixiv"):
        hint = H.gvs_health_hint([sid], sb)
        if hint:
            failures.append(
                f"A1 传入 [{sid}] 仍返回 googlevideo 告警: {hint[:60]}...")

    # 判据 A2: **调用点**必须传启用清单。
    #   原始缺陷有两种形态, 必须分别盯住:
    #     · 启用边界 (on_service_toggled) 传了 [service_id] 但函数不读 ⇒ 已由 A1 覆盖;
    #     · 启动路径 (_start_h3_upstream) **不带参数** ⇒ "不带"按函数口径是"调用方未声明",
    #       保守提示 ⇒ googlevideo 没启用也会弹。故这里直接查调用点是否传了实参。
    try:
        src = (_ROOT / "app" / "pyside_app.py").read_text(encoding="utf-8")
    except Exception as e:                                   # pragma: no cover
        failures.append(f"A2 无法读取调用点源码: {type(e).__name__}: {e}")
        src = ""
    if src:
        import re
        # 只允许带实参的调用形态: gvs_health_hint(<非空>) —— 空括号即未声明启用清单
        for m in re.finditer(r"gvs_health_hint\(([^)]*)\)", src):
            arg = m.group(1).strip()
            if not arg:
                line = src[:m.start()].count("\n") + 1
                failures.append(
                    f"A2 pyside_app.py:{line} 调用 gvs_health_hint() 未传启用清单 "
                    f"⇒ googlevideo 未启用时也会弹告警")

    # 判据 A3: googlevideo 确实启用时, 不稳定的成绩单**仍须**给出告警。
    #   这是反向判据 —— 防"靠永远静音来通过 A1/A2"。
    hint_on = H.gvs_health_hint(["googlevideo"], sb)
    state = H.gvs_health(sb).get("state")
    if state in ("FLAKY", "UNSTABLE") and not hint_on:
        failures.append(
            f"A3 成绩单 state={state} 却未告警 —— 修 A1/A2 时不得把信号一起静音")
    return failures


# ===========================================================================
# 测量 B: 投毒前缀表
# ===========================================================================
# 实测投毒取值 (来源: docs/googlevideo-quic-channel.md 与
# docs/googlevideo-node-availability.md 记录的 DoH 原始应答) 及其被投毒的名字。
# ⚠ 只收**实测到的**取值, 与 `_DNS_POISON_PREFIX` 注释口径一致 —— 不凭记忆堆砌。
MEASURED_POISON = {
    "69.171.235.22":   "www.google.com (alidns)",
    "199.96.62.75":    "rr2---sn-i3b7kns1.googlevideo.com (漏过后补入)",
    "128.242.240.212": "rr2---sn-i3b7kns1.googlevideo.com (alidns)",
    "199.59.149.204":  "rr1---sn-i3b7kns6.googlevideo.com (alidns)",
    "2001::1":         "*.c.youtube.com / www.youtube.com / www.google.com (AAAA)",
    "185.45.5.35":     "*.c.youtube.com (doh.pub)",
    "174.132.167.252": "www.youtube.com (alidns)",
    "192.133.77.133":  "rr2---sn-i3b7kns1.googlevideo.com (doh.pub)",
}

# 真实 Google 公网网段取样 (防"合并时把 Google 一起拉黑")
_GOOGLE_SAMPLE = ["74.125.157.105", "172.217.152.161", "142.250.66.110",
                  "216.58.200.14", "2607:f8b0:4007:5::9", "2a00:1450:4001:3c::9",
                  "2001:4860:4860::8888"]


def check_poison_tables() -> list:
    """返回未满足的判据列表 (空 = 两表一致、无泄漏、无误拦)"""
    import cdn_optimizer as CO
    import h3_upstream as H

    failures = []

    # 判据 B1: 每个实测投毒取值都必须被**两个**表挡住。
    for ip, why in MEASURED_POISON.items():
        if not any(ip.startswith(p) for p in CO.POLLUTED_IP_PREFIXES):
            failures.append(f"B1 cdn_optimizer 漏过 {ip} ({why})")
        if not any(ip.startswith(p) for p in H._DNS_POISON_PREFIX):
            failures.append(f"B1 h3 腿漏过 {ip} ({why})")

    # 判据 B2: 漏过者若连第二道闸门也过 ⇒ 会真的进入候选池 (文档记载的"假 200"根因)。
    for ip in MEASURED_POISON:
        if not any(ip.startswith(p) for p in CO.POLLUTED_IP_PREFIXES) \
                and CO.is_valid_public_cdn_ip(ip):
            failures.append(
                f"B2 {ip} 两道闸门都放行 ⇒ 会真的进入候选池")

    # 判据 B3 (反向, 用**冻结的真实探测语料**): 合并后不得新拦下任何一个
    # "能被 is_valid_public_cdn_ip 接受"的地址 —— 那才是会真进候选池的地址,
    # 误拦它们等于把好 IP 挡在池外。
    #   语料 = ipv4_report.json / ipv6_report.json 的全部实测地址 (本机探测结果)。
    try:
        doc = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
        corpus = doc.get("corpus") or []
    except Exception as e:
        failures.append(f"B3 语料读取失败 ({_CORPUS_PATH.name}): {type(e).__name__}: {e}")
        corpus = []

    #   ⚠ 验收标准必须收三层, 不能只看 is_valid_public_cdn_ip —— 它只回答"是不是公网地址",
    #     而语料里的 `2a03:2880:...:face:b00c:...` 既是公网地址、又是**投毒值**
    #     (face:b00c 是 Facebook 自有 IPv6 空间, 见 h3_upstream.is_poisoned 的独立判据)。
    #     真正算"误拦"的只有: 公开 + **探测成功** + 未被投毒判据标记。
    #     探测失败的地址即便不是投毒也本就不可用, 拦下它不构成损失。
    old_c, new_c = set(CO.POLLUTED_IP_PREFIXES), set(H._DNS_POISON_PREFIX)
    merged = old_c | new_c
    newly_blocked, newly_blocked_acceptable = [], []
    for row in corpus:
        ip = row.get("ip") or ""
        if not ip or not any(ip.startswith(p) for p in merged):
            continue
        if any(ip.startswith(p) for p in old_c):
            continue                       # 合并前就拦 ⇒ 不是本次新增面
        newly_blocked.append(row)
        if not CO.is_valid_public_cdn_ip(ip):
            continue                       # 第二道闸门本就挡住
        if not row.get("ok"):
            continue                       # 探测失败 ⇒ 拦住无损失
        if H.is_poisoned(ip):
            continue                       # 投毒判据独立标记 (face:b00c 等)
        newly_blocked_acceptable.append(row)
    if newly_blocked_acceptable:
        for row in newly_blocked_acceptable:
            failures.append(
                f"B3 合并后误拦可用地址 {row['ip']} (服务 {row.get('service')}, "
                f"探测 ok={row.get('ok')})")
    # 语料自身的一致性快照: 生成时核验过"命中项全部是失败条目"
    snap = (doc or {}).get("merged_poison_hits") or {}
    if snap and not snap.get("all_are_failed_entries", True):
        failures.append("B3 语料快照记录: 合并表命中的条目里存在成功条目 ⇒ 需人工复核")

    # 判据 B4: 真实 Google 取样不得被任一张表拦下
    for ip in _GOOGLE_SAMPLE:
        if any(ip.startswith(p) for p in merged):
            failures.append(f"B4 真实 Google 地址被误拦: {ip}")
    return failures, {"corpus": len(corpus), "newly_blocked": len(newly_blocked),
                      "newly_blocked_acceptable": len(newly_blocked_acceptable)}


def main() -> int:
    all_failures = []

    print("=" * 74)
    print("候选 A: 闸门接线 (L3)")
    print("=" * 74)
    try:
        fa = check_gate_wiring()
    except Exception as e:                                   # pragma: no cover
        fa = [f"A 检查本身失败: {type(e).__name__}: {e}"]
    import h3_upstream as H
    print("当前成绩单:", H.gvs_health(H._NodeScoreboard()))
    for f in fa or ["✅ 判据全部满足"]:
        print("  " + f)
    all_failures += fa

    print()
    print("=" * 74)
    print("候选 B: 投毒前缀表合并")
    print("=" * 74)
    try:
        fb, stats = check_poison_tables()
    except Exception as e:                                   # pragma: no cover
        fb, stats = [f"B 检查本身失败: {type(e).__name__}: {e}"], {}
    if stats:
        print(f"B3 语料: {stats['corpus']} 条真实探测地址; "
              f"合并后新拦 {stats['newly_blocked']} 条, "
              f"其中可用地址 {stats['newly_blocked_acceptable']} 条 (须为 0)")
    for f in fb or ["✅ 判据全部满足"]:
        print("  " + f)
    all_failures += fb

    print()
    print("=" * 74)
    print(f"结论: {'收益仍在 —— 有未满足判据 ' + str(len(all_failures)) + ' 条' if all_failures else '✅ 无待修项'}")
    print("=" * 74)
    return 1 if all_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
