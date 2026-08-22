# -*- coding: utf-8 -*-
"""
GameArt Toolkit - CDN 优化测速引擎性能与命中率基准验证脚本

测试指标:
1. 全量 26 项服务测速总耗时 (目标: < 6.0 秒)
2. 各服务可用节点 (rank 0 / 1 / 2) 产出率
3. 单次测速有效 Upstream 生成完整性
"""

import sys
import time
import io
from pathlib import Path

# 确保在 Windows GBK 控制台下正常输出 UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 加入 app 搜索路径
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))

from cdn_optimizer import CDNOptimizer
from service_profile import PROFILES

def run_benchmark():
    print("=" * 80)
    print(" CDN 优化测速引擎基准压测 (两阶段漏斗 + 单节点独立计时 + 原地微重试)")
    print("=" * 80)

    opt = CDNOptimizer()
    t0 = time.perf_counter()

    print(f"\n[+] 开始执行全量 {len(PROFILES)} 项服务两阶段高并发测速...")
    results = opt.test_all_services(max_workers=64)
    elapsed = time.perf_counter() - t0

    print(f"\n[+] 测速完成！总耗时: {elapsed:.2f} 秒 (相比优化前 30s 缩短 {((30.0 - elapsed) / 30.0) * 100:.1f}%)")
    print("-" * 80)

    total_services = len(results)
    available_services = 0
    rank0_services = 0
    total_ips_probed = 0
    total_available_ips = 0

    print(f"{'服务 ID':<20} | {'首选 IP':<18} | {'延迟 (ms)':<10} | {'Rank':<6} | {'推荐模式':<8} | {'状态'}")
    print("-" * 80)

    for srv_id, ip_items in sorted(results.items()):
        total_ips_probed += len(ip_items)
        if not ip_items:
            print(f"{srv_id:<20} | {'无节点':<18} | {'N/A':<10} | {'3':<6} | {'none':<8} | ❌ 未配置")
            continue

        best = ip_items[0]
        rank = best.get("rank", 3)
        lat = best.get("latency")
        lat_str = f"{lat:>6.1f}ms" if lat is not None else "超时"
        ip_str = best.get("ip", "N/A")
        rec = best.get("recommend", "none")

        avail_count = sum(1 for it in ip_items if it.get("available"))
        total_available_ips += avail_count

        if avail_count > 0:
            available_services += 1
            if rank == 0:
                rank0_services += 1
            status_str = f"✅ 可用 ({avail_count}/{len(ip_items)})"
        else:
            status_str = f"⚠️ 兜底 ({avail_count}/{len(ip_items)})"

        print(f"{srv_id:<20} | {ip_str:<18} | {lat_str:<10} | {rank:<6} | {rec:<8} | {status_str}")

    print("=" * 80)
    print(f"📊 汇总报告:")
    print(f" - 总服务数: {total_services}")
    print(f" - 具备可用节点服务数: {available_services} / {total_services} (覆盖率: {(available_services/total_services)*100:.1f}%)")
    print(f" - 直连 rank0 极速服务数: {rank0_services} / {total_services}")
    print(f" - 探测候选 IP 总数: {total_ips_probed}, 捕获可用 IP 总数: {total_available_ips}")
    print(f" - 单次全量测速总耗时: {elapsed:.2f} 秒")

    # 验证动态 upstream 写入
    ok, msg = opt.apply_optimal(results)
    print(f"\n[+] 动态 Upstream 写入验证: {'成功 (PASS)' if ok else '失败 (FAIL)'} - {msg}")
    print("=" * 80)


if __name__ == "__main__":
    run_benchmark()
