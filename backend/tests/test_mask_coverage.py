"""测试：脱敏覆盖批次与质报汇总（脱敏核验 → 覆盖批次 → 补做回执 → 质报确认）。

验收场景：一批六行记录，五行有账号而只有两行成功遮盖，第六行缺账号但正常解析。
- 报告应显示字段覆盖率 2/5、解析成功率 6/6，漏遮盖与缺账号行可核对
- 出具当期报告前一条漏遮盖记录完成补做：旧批 2/5，允许纳入补做时当期 3/5
- 补做撤回后下一份质报恢复未保护计数，旧报告和旧回执仍能核对
- 重启恢复：回执已生成但批次未登记 → 核实真实保护结果后补登记，
  不把已遮盖值当原账号再处理，不凭报告仍有失败就重发补做
- 并发出具同一期报告只确认一次；报告可从选用的批次复算
- 任一种确认边界下，报告、回执、批次明细都不带账号原文
"""
from __future__ import annotations

import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.mask_coverage import (
    ITEM_FIELD_MISSING, ITEM_MISSED, ITEM_PROTECTED, ORIGIN_VERIFICATION,
    RECEIPT_WITHDRAWN, REDO_PROTECTED, REDO_REJECTED, MaskCoverageLedger,
    is_field_protected, make_coverage_ledger,
)
from app.core.mask_enrich import MaskEnrichPipeline
from app.core.models import (
    EventRecord, EventTypeDef, IngestJob, MaskMethod, MaskRule, ParseResultStatus,
    ParseRule,
)
from app.core.pipeline import PRESET_LOG_SOURCES, make_pipeline

# ---------- 验收数据：六行记录 ----------

ACCOUNT_PARSE_RULE = ParseRule(
    rule_id="PARS-ACCT",
    source_id=PRESET_LOG_SOURCES["app-backend"].source_id,
    regex_pattern=(
        r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+'
        r'(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+account=(\S*)\s+(.*)$'
    ),
    field_names=["timestamp", "thread", "level", "logger", "account", "detail"],
    state="生效中",
)

# 初验规则：只认手机账号；卡号账号遮盖不上 -> 漏遮盖
ACCOUNT_RULE_V1 = MaskRule(
    rule_id="MASK-ACCT", target_field="account",
    mask_method=MaskMethod.CUSTOM_REGEX, mask_pattern=r"1[0-9]{10}",
    rule_state="生效中",
)
# 补做规则：保护侧修正后同时认卡号账号
ACCOUNT_RULE_V2 = MaskRule(
    rule_id="MASK-ACCT", target_field="account",
    mask_method=MaskMethod.CUSTOM_REGEX, mask_pattern=r"1[0-9]{10}|[0-9]{16,19}",
    rule_state="生效中",
)

SIX_LINES = [
    '2026-11-24 10:15:01.001 [io-1] INFO  com.example.PayService - account=13800138000 amount=101',
    '2026-11-24 10:15:02.002 [io-2] INFO  com.example.PayService - account=13912345678 amount=102',
    '2026-11-24 10:15:03.003 [io-3] INFO  com.example.PayService - account=6222021234567890 amount=103',
    '2026-11-24 10:15:04.004 [io-4] INFO  com.example.PayService - account=6228480402564890 amount=104',
    '2026-11-24 10:15:05.005 [io-5] INFO  com.example.PayService - account=6225880212345678 amount=105',
    '2026-11-24 10:15:06.006 [io-6] INFO  com.example.PayService - account= amount=106',
]

ACCOUNT_VALUES = [
    "13800138000", "13912345678",
    "6222021234567890", "6228480402564890", "6225880212345678",
]


def run_real_verification(ledger: MaskCoverageLedger,
                          mask_rules: list[MaskRule] | None = None):
    """跑真实脱敏核验：原始行 → 解析 → 事件 → 脱敏 → 覆盖批次。

    返回 (records, parse_ok, parse_total, verify_dict, batch, mask_pipeline)。
    """
    ingest = make_pipeline()
    source = PRESET_LOG_SOURCES["app-backend"]
    entries = ingest.parse_raw_lines(source, SIX_LINES)
    parsed = ingest.apply_parse_rules(entries, ACCOUNT_PARSE_RULE)
    job = IngestJob(job_id="INGE-ACCT", source_id=source.source_id, batch_size=20)
    processed = ingest.run_ingest_job(parsed, job)
    parse_ok = sum(1 for e in processed if e.parse_status == ParseResultStatus.OK)
    records = ingest.classify_events(processed)

    mask_pipeline = MaskEnrichPipeline(
        mask_rules=mask_rules or [ACCOUNT_RULE_V1],
        enrich_rules=[],
        ledger=ledger,
    )
    mask_pipeline.process_records(records)
    verify = mask_pipeline.verify_mask_completeness(records)
    batch = ledger.get_batch(verify["batch_id"])
    return records, parse_ok, len(processed), verify, batch, mask_pipeline


def refs_of(refs: list[dict]) -> set[str]:
    return {ref["record_ref"] for ref in refs}


class TestCoverageBatchAcceptance:
    """六行记录验收：字段覆盖率 2/5、解析成功率 6/6。"""

    def test_six_rows_initial_report(self):
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, verify, batch, _ = run_real_verification(ledger)

        assert parse_ok == 6 and parse_total == 6
        assert len(records) == 6
        # 初验批次：2 行保护成功、3 行漏遮盖、1 行原字段缺失
        assert batch.protected_count() == 2
        assert batch.missed_count() == 3
        assert batch.field_missing_count() == 1
        assert batch.should_protect_count() == 5
        assert batch.coverage_rate() == round(2 / 5, 4)

        # 质报汇总：字段覆盖率 2/5、解析成功率 6/6
        report = ledger.issue_report("2026-11-24", parse_ok=parse_ok, parse_total=parse_total)
        assert report.protected == 2 and report.should_protect == 5
        assert report.field_coverage_rate == round(2 / 5, 4)
        assert report.parse_success_rate == 1.0

        # 漏遮盖是第 3、4、5 行，缺账号是第 6 行（匿名位置可核对）
        assert refs_of(report.missed_refs) == {"EVEN-000003", "EVEN-000004", "EVEN-000005"}
        assert refs_of(report.field_missing_refs) == {"EVEN-000006"}
        # 报告能从选用的批次复算
        assert ledger.recompute_report(report)["ok"]

    def test_multi_row_miss_never_negative(self):
        """同一账号字段在多行漏遮盖时，覆盖率不得为负。"""
        ledger = make_coverage_ledger()
        _, _, _, verify, batch, _ = run_real_verification(ledger)
        assert verify["missed"] == 3
        assert 0.0 <= verify["coverage_rate"] <= 1.0
        assert verify["coverage_rate"] == round(2 / 5, 4)
        # 核验入口计数与匿名位置一一对应
        assert len(verify["leaks_detail"]) == verify["leaks_found"] == 3
        assert refs_of(verify["leaks_detail"]) == {"EVEN-000003", "EVEN-000004", "EVEN-000005"}

    def test_verify_entry_denominator_is_should_protect(self):
        """分母是应保护项（记录×字段），不是规则条数。"""
        ledger = make_coverage_ledger()
        _, _, _, verify, _, _ = run_real_verification(ledger)
        assert verify["total_rules"] == 1
        assert verify["should_protect"] == 5
        assert verify["protected"] == 2
        assert verify["field_missing"] == 1


class TestRedoAndReportConflict:
    """补做与初验冲突：报告按实际发布批次取证，允许纳入补做时当期 3/5。"""

    def test_redo_then_current_period_report(self):
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, verify, batch, pipeline = run_real_verification(ledger)

        # 质检员领取这批结果：按匿名位置把漏遮盖行交给补做
        claim = ledger.claim_redo("EVEN-000003", "account")
        assert claim["ok"] and not claim["already_claimed"]

        # 出具当期报告前，保护侧修正规则并完成该行补做
        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        receipt = pipeline.redo_field("EVEN-000003", "account", records)
        assert receipt.result == REDO_PROTECTED
        assert is_field_protected("6222021234567890",
                                  records[2].masked_fields["account"])
        new_batch = ledger.register_receipt(receipt.receipt_id)
        assert new_batch is not None and new_batch.generation == 2

        # 两代完整核验结果冲突：旧批（初验）仍显示 2/5
        old_batch = ledger.latest_verification_batch()
        assert old_batch.batch_id == batch.batch_id
        assert old_batch.protected_count() == 2 and old_batch.should_protect_count() == 5

        # 允许纳入补做时，当期报告按实际发布批次取证 -> 3/5
        current = ledger.issue_report("2026-11-24", parse_ok=parse_ok,
                                      parse_total=parse_total, include_redo=True)
        assert current.protected == 3 and current.should_protect == 5
        assert current.field_coverage_rate == round(3 / 5, 4)
        assert current.batch_id == new_batch.batch_id
        assert ledger.recompute_report(current)["ok"]

        # 另一确认边界：不允许纳入补做时仍按初验批次 -> 2/5
        strict = ledger.issue_report("2026-11-24-strict", parse_ok=parse_ok,
                                     parse_total=parse_total, include_redo=False)
        assert strict.protected == 2 and strict.field_coverage_rate == round(2 / 5, 4)
        assert strict.batch_id == old_batch.batch_id

    def test_withdraw_restores_unprotected_count(self):
        """补做撤回后，下一份质报恢复未保护计数；旧报告和旧回执仍能核对。"""
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, _, _, pipeline = run_real_verification(ledger)

        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        ledger.claim_redo("EVEN-000003", "account")
        receipt = pipeline.redo_field("EVEN-000003", "account", records)
        gen2 = ledger.register_receipt(receipt.receipt_id)
        report_with_redo = ledger.issue_report("P1", parse_ok, parse_total)
        assert report_with_redo.protected == 3

        # 撤回补做 -> 下一份报告恢复未保护计数
        gen3 = ledger.withdraw_receipt(receipt.receipt_id)
        assert gen3 is not None and gen3.missed_count() == 3
        assert receipt.state == RECEIPT_WITHDRAWN
        report_after_withdraw = ledger.issue_report("P2", parse_ok, parse_total)
        assert report_after_withdraw.protected == 2
        assert report_after_withdraw.should_protect == 5
        assert report_after_withdraw.missed == 3

        # 旧报告仍是 3/5，且能从它选用的批次复算；旧回执仍可核对
        assert ledger.get_report("P1").protected == 3
        assert ledger.recompute_report(report_with_redo)["ok"]
        gen2_item = ledger.get_batch(gen2.batch_id).find_item("EVEN-000003", "account")
        assert gen2_item.receipt_id == receipt.receipt_id
        assert ledger.get_receipt(receipt.receipt_id) is not None


class TestRedoGuards:
    """补做约束：已保护字段不回填、缺账号行不假保护、重领不重发。"""

    def test_missing_account_cannot_fake_success(self):
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, _, batch, pipeline = run_real_verification(ledger)

        # 缺账号的行不能领取补做
        claim = ledger.claim_redo("EVEN-000006", "account")
        assert not claim["ok"]
        # 即使直接交给保护侧，也只能得到拒绝回执，不能生成假保护成功
        receipt = pipeline.redo_field("EVEN-000006", "account", records)
        assert receipt.result == REDO_REJECTED
        assert ledger.register_receipt(receipt.receipt_id) is None
        assert ledger.published_batch().batch_id == batch.batch_id
        assert ledger.published_batch().coverage_rate() == round(2 / 5, 4)

    def test_protected_field_not_refilled(self):
        ledger = make_coverage_ledger()
        records, _, _, _, _, pipeline = run_real_verification(ledger)

        before = records[0].masked_fields["account"]
        receipt = pipeline.redo_field("EVEN-000001", "account", records)
        # 已保护字段不重新从原值回填
        assert receipt.result == REDO_PROTECTED
        assert "未重新回填" in receipt.detail
        assert records[0].masked_fields["account"] == before
        # 登记也是幂等的：不产生新世代
        assert ledger.register_receipt(receipt.receipt_id).generation == 1

    def test_reclaim_is_idempotent(self):
        ledger = make_coverage_ledger()
        records, _, _, _, _, pipeline = run_real_verification(ledger)

        first = ledger.claim_redo("EVEN-000003", "account")
        assert first["ok"] and not first["already_claimed"]
        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        receipt = pipeline.redo_field("EVEN-000003", "account", records)
        # 重领同一失败项：返回既有回执，不重发补做
        second = ledger.claim_redo("EVEN-000003", "account")
        assert second["ok"] and second["already_claimed"]
        assert second["receipt"]["receipt_id"] == receipt.receipt_id
        again = pipeline.redo_field("EVEN-000003", "account", records)
        assert again.receipt_id == receipt.receipt_id
        assert len(ledger.receipts()) == 1


class TestRestartRecovery:
    """重启恢复：回执已生成但覆盖批次未登记这次成功。"""

    def test_recover_registers_verified_receipt(self):
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, _, _, pipeline = run_real_verification(ledger)

        # 保护侧完成某行账号补做并生成新回执，但覆盖批次还未登记就重启
        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        ledger.claim_redo("EVEN-000004", "account")
        receipt = pipeline.redo_field("EVEN-000004", "account", records)
        assert receipt.result == REDO_PROTECTED
        assert ledger.published_batch().generation == 1  # 未登记

        # 重启：从持久化状态恢复台账（回执在、批次登记丢失）
        restored = MaskCoverageLedger.restore_state(ledger.export_state())
        assert restored.published_batch().generation == 1

        # 质检员重领原失败项：返回既有回执，不凭报告仍有失败就重发补做
        reclaim = restored.claim_redo("EVEN-000004", "account")
        assert reclaim["already_claimed"]
        assert reclaim["receipt"]["receipt_id"] == receipt.receipt_id

        # 恢复核实原字段真正的保护结果后补登记；不把已遮盖值当原账号再处理
        masked_before = dict(records[3].masked_fields)
        records_by_ref = {r.record_id: r for r in records}
        recovered = restored.recover(records_by_ref)
        assert recovered == [receipt.receipt_id]
        assert records[3].masked_fields == masked_before  # 未二次脱敏
        assert len(restored.receipts()) == 1  # 未重发新补做

        # 恢复后发布批次为 3/5，当期报告按它取证
        assert restored.published_batch().protected_count() == 3
        report = restored.issue_report("2026-11-24", parse_ok, parse_total)
        assert report.field_coverage_rate == round(3 / 5, 4)
        assert restored.recompute_report(report)["ok"]

    def test_recover_rejects_unprotected_field(self):
        """回执声称成功但字段实际未保护时，恢复不得登记。"""
        ledger = make_coverage_ledger()
        records, _, _, _, _, pipeline = run_real_verification(ledger)

        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        ledger.claim_redo("EVEN-000004", "account")
        receipt = pipeline.redo_field("EVEN-000004", "account", records)
        # 模拟保护侧状态丢失：字段回退成未遮盖
        records[3].masked_fields["account"] = records[3].parsed_fields["account"]

        restored = MaskCoverageLedger.restore_state(ledger.export_state())
        recovered = restored.recover({r.record_id: r for r in records})
        assert recovered == []
        assert restored.published_batch().generation == 1
        assert restored.published_batch().coverage_rate() == round(2 / 5, 4)


class TestReportConfirmation:
    """质报确认边界：同期只确认一次、可复算、匿名位置齐全。"""

    def test_concurrent_issue_confirms_once(self):
        ledger = make_coverage_ledger()
        _, parse_ok, parse_total, _, _, _ = run_real_verification(ledger)

        barrier = threading.Barrier(8)
        results = []

        def issue():
            barrier.wait()
            results.append(ledger.issue_report("2026-11-24", parse_ok, parse_total))

        threads = [threading.Thread(target=issue) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len({r.report_id for r in results}) == 1
        assert len(ledger.reports()) == 1
        assert results[0].field_coverage_rate == round(2 / 5, 4)

    def test_report_recomputable_and_anonymous(self):
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, verify, _, pipeline = run_real_verification(ledger)

        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        ledger.claim_redo("EVEN-000003", "account")
        receipt = pipeline.redo_field("EVEN-000003", "account", records)
        ledger.register_receipt(receipt.receipt_id)

        report = ledger.issue_report("2026-11-24", parse_ok, parse_total)
        # 同份报告的保护结果和分母能从选用的批次复算
        check = ledger.recompute_report(report)
        assert check["ok"], check
        # 所有版本都保留匿名来源位置
        for batch in ledger.batches():
            for item in batch.items:
                assert item.record_ref.startswith("EVEN-")
        assert refs_of(report.missed_refs) == {"EVEN-000004", "EVEN-000005"}
        assert refs_of(report.field_missing_refs) == {"EVEN-000006"}

    def test_no_plaintext_under_any_confirmation_boundary(self):
        """任一种确认边界下，报告、回执、批次、核验结果都不带账号原文。"""
        ledger = make_coverage_ledger()
        records, parse_ok, parse_total, verify, _, pipeline = run_real_verification(ledger)

        pipeline.mask_rules = [ACCOUNT_RULE_V2]
        ledger.claim_redo("EVEN-000003", "account")
        receipt = pipeline.redo_field("EVEN-000003", "account", records)
        ledger.register_receipt(receipt.receipt_id)
        ledger.issue_report("boundary-initial", parse_ok, parse_total, include_redo=False)
        ledger.issue_report("boundary-with-redo", parse_ok, parse_total, include_redo=True)
        ledger.withdraw_receipt(receipt.receipt_id)
        ledger.issue_report("boundary-after-withdraw", parse_ok, parse_total)
        exported = ledger.export_state()

        payloads = [verify, exported]
        payloads += [r.to_dict() for r in ledger.reports()]
        payloads += [r.to_dict() for r in ledger.receipts()]
        payloads += [b.to_dict() for b in ledger.batches()]
        blob = json.dumps(payloads, ensure_ascii=False)
        for account in ACCOUNT_VALUES:
            assert account not in blob, f"账号原文泄露: {account}"


class TestQualityReportCallChain:
    """沿调用链修复分母：质报汇总直接采用脱敏覆盖批次。"""

    def test_generate_quality_report_uses_batch(self):
        ledger = make_coverage_ledger()
        _, parse_ok, parse_total, _, batch, _ = run_real_verification(ledger)

        ingest = make_pipeline()
        job = IngestJob(job_id="INGE-ACCT", source_id="LOG_-0002", batch_size=20)
        job.processed_lines, job.skipped_lines = 6, 0
        metric = ingest.compute_ingest_metrics(job, 1200.0, 6)
        report = ingest.generate_quality_report(
            metric, parse_ok=parse_ok, parse_total=parse_total,
            processed=6, skipped=0, coverage_batch=batch,
        )
        assert report.field_coverage_rate == round(2 / 5, 4)
        assert report.parse_success_rate == 1.0
        assert 0.0 <= report.field_coverage_rate <= 1.0


if __name__ == "__main__":
    import traceback

    tests = {
        "six_rows_initial_report": TestCoverageBatchAcceptance().test_six_rows_initial_report,
        "multi_row_miss_never_negative": TestCoverageBatchAcceptance().test_multi_row_miss_never_negative,
        "verify_entry_denominator": TestCoverageBatchAcceptance().test_verify_entry_denominator_is_should_protect,
        "redo_then_current_period_report": TestRedoAndReportConflict().test_redo_then_current_period_report,
        "withdraw_restores_unprotected": TestRedoAndReportConflict().test_withdraw_restores_unprotected_count,
        "missing_account_no_fake_success": TestRedoGuards().test_missing_account_cannot_fake_success,
        "protected_field_not_refilled": TestRedoGuards().test_protected_field_not_refilled,
        "reclaim_is_idempotent": TestRedoGuards().test_reclaim_is_idempotent,
        "recover_registers_verified_receipt": TestRestartRecovery().test_recover_registers_verified_receipt,
        "recover_rejects_unprotected": TestRestartRecovery().test_recover_rejects_unprotected_field,
        "concurrent_issue_once": TestReportConfirmation().test_concurrent_issue_confirms_once,
        "report_recomputable_anonymous": TestReportConfirmation().test_report_recomputable_and_anonymous,
        "no_plaintext_any_boundary": TestReportConfirmation().test_no_plaintext_under_any_confirmation_boundary,
        "call_chain_uses_batch": TestQualityReportCallChain().test_generate_quality_report_uses_batch,
    }

    passed = 0
    failed = 0
    for name, test_func in tests.items():
        try:
            test_func()
            passed += 1
            print(f"  PASS  test_mask_coverage: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  test_mask_coverage: {name}")
            traceback.print_exc()

    print(f"\ntest_mask_coverage: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
