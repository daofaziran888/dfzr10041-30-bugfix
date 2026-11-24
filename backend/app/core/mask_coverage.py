"""脱敏覆盖批次与质报汇总：脱敏核验 → 覆盖批次 → 补做回执 → 质量报告。

数据流：MaskEnrichPipeline.verify_mask_coverage → MaskCoverageBatch（脱敏覆盖批次）
       → MaskCoverageLedger（补做 / 撤回 / 重启恢复）→ 质报汇总（issue_report）
涉及模块：mask_rule, quality_report, event_store

约定：
- 覆盖批次、补做回执与质量报告只保留匿名来源位置（record_ref + field_name + rule_id），
  任何版本都不带账号原文。
- 批次按世代（generation）追加，旧世代不可变：同一份报告的保护结果和分母
  都能从它选用的批次复算，旧报告和旧回执始终可以核对。
- 字段覆盖率 = 保护成功项 / 应保护项；应保护项 = 保护成功 + 漏遮盖，
  原字段缺失不进分母，只单独统计。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.models import EventRecord, MaskRule

# ---------- 覆盖项状态 ----------
ITEM_PROTECTED = "protected"          # 保护成功
ITEM_MISSED = "missed"                # 漏遮盖
ITEM_FIELD_MISSING = "field_missing"  # 原字段缺失

# ---------- 批次来源 ----------
ORIGIN_VERIFICATION = "verification"  # 初验
ORIGIN_REDO = "redo"                  # 补做登记
ORIGIN_WITHDRAW = "withdraw"          # 补做撤回

# ---------- 回执状态 ----------
RECEIPT_CONFIRMED = "confirmed"
RECEIPT_WITHDRAWN = "withdrawn"

# 补做回执结果
REDO_PROTECTED = "protected"
REDO_REJECTED = "rejected"


def is_field_protected(original: str, masked: str) -> bool:
    """核实字段真正的保护结果：掩码值存在、不同于原值、且不含原值核心片段。"""
    if not original or not masked or masked == original:
        return False
    if len(original) > 3 and original[2:-2] in masked:
        return False
    return True


def _now() -> str:
    return datetime.now().isoformat()


@dataclass
class MaskCoverageItem:
    """逐字段覆盖项：一条记录的一个敏感字段在一次核验中的保护结果（匿名）。"""
    record_ref: str       # 匿名来源位置（记录编号）
    field_name: str
    rule_id: str
    status: str           # protected / missed / field_missing
    receipt_id: str = ""  # 补做回执编号（补做成功并登记后回填）

    def to_dict(self) -> dict[str, str]:
        return {
            "record_ref": self.record_ref,
            "field_name": self.field_name,
            "rule_id": self.rule_id,
            "status": self.status,
            "receipt_id": self.receipt_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "MaskCoverageItem":
        return cls(
            record_ref=data["record_ref"],
            field_name=data["field_name"],
            rule_id=data["rule_id"],
            status=data["status"],
            receipt_id=data.get("receipt_id", ""),
        )


@dataclass
class MaskCoverageBatch:
    """脱敏覆盖批次：一次完整核验（或补做登记/撤回）的逐字段结果集合。"""
    batch_id: str
    generation: int
    origin: str
    items: list[MaskCoverageItem]
    state: str = "已发布"
    created_at: str = field(default_factory=_now)

    # ----- 计数：保护成功项 / 应保护项 / 漏遮盖 / 原字段缺失 -----
    def protected_count(self) -> int:
        return sum(1 for item in self.items if item.status == ITEM_PROTECTED)

    def missed_count(self) -> int:
        return sum(1 for item in self.items if item.status == ITEM_MISSED)

    def field_missing_count(self) -> int:
        return sum(1 for item in self.items if item.status == ITEM_FIELD_MISSING)

    def should_protect_count(self) -> int:
        """应保护项（分母）= 保护成功 + 漏遮盖；原字段缺失不进分母。"""
        return self.protected_count() + self.missed_count()

    def coverage_rate(self) -> float:
        """字段覆盖率 = 保护成功项 / 应保护项；分母为 0 时视为全覆盖。"""
        should = self.should_protect_count()
        if should == 0:
            return 1.0
        return round(self.protected_count() / should, 4)

    # ----- 匿名位置清单 -----
    def missed_refs(self) -> list[dict[str, str]]:
        return [item.to_dict() for item in self.items if item.status == ITEM_MISSED]

    def field_missing_refs(self) -> list[dict[str, str]]:
        return [item.to_dict() for item in self.items if item.status == ITEM_FIELD_MISSING]

    def find_item(self, record_ref: str, field_name: str) -> MaskCoverageItem | None:
        for item in self.items:
            if item.record_ref == record_ref and item.field_name == field_name:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "generation": self.generation,
            "origin": self.origin,
            "state": self.state,
            "created_at": self.created_at,
            "protected": self.protected_count(),
            "should_protect": self.should_protect_count(),
            "missed": self.missed_count(),
            "field_missing": self.field_missing_count(),
            "coverage_rate": self.coverage_rate(),
            "items": [item.to_dict() for item in self.items],
        }


@dataclass
class MaskRedoReceipt:
    """补做回执：补做完成后按字段交回复核的凭证（只含匿名位置，不带账号原文）。"""
    receipt_id: str
    record_ref: str
    field_name: str
    rule_id: str
    result: str                # protected / rejected
    detail: str = ""
    state: str = RECEIPT_CONFIRMED   # confirmed / withdrawn
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, str]:
        return {
            "receipt_id": self.receipt_id,
            "record_ref": self.record_ref,
            "field_name": self.field_name,
            "rule_id": self.rule_id,
            "result": self.result,
            "detail": self.detail,
            "state": self.state,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "MaskRedoReceipt":
        return cls(
            receipt_id=data["receipt_id"],
            record_ref=data["record_ref"],
            field_name=data["field_name"],
            rule_id=data["rule_id"],
            result=data["result"],
            detail=data.get("detail", ""),
            state=data.get("state", RECEIPT_CONFIRMED),
            created_at=data.get("created_at", ""),
        )


@dataclass
class QualityReportSnapshot:
    """质报汇总产出：一期已确认的质量报告（匿名明细，可从选用的批次复算）。"""
    report_id: str
    period: str
    batch_id: str
    batch_generation: int
    protected: int
    should_protect: int
    missed: int
    field_missing: int
    parse_ok: int
    parse_total: int
    field_coverage_rate: float
    parse_success_rate: float
    missed_refs: list[dict[str, str]] = field(default_factory=list)
    field_missing_refs: list[dict[str, str]] = field(default_factory=list)
    state: str = "已确认"
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "period": self.period,
            "batch_id": self.batch_id,
            "batch_generation": self.batch_generation,
            "protected": self.protected,
            "should_protect": self.should_protect,
            "missed": self.missed,
            "field_missing": self.field_missing,
            "parse_ok": self.parse_ok,
            "parse_total": self.parse_total,
            "field_coverage_rate": self.field_coverage_rate,
            "parse_success_rate": self.parse_success_rate,
            "missed_refs": [dict(ref) for ref in self.missed_refs],
            "field_missing_refs": [dict(ref) for ref in self.field_missing_refs],
            "state": self.state,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QualityReportSnapshot":
        return cls(
            report_id=data["report_id"],
            period=data["period"],
            batch_id=data["batch_id"],
            batch_generation=int(data["batch_generation"]),
            protected=int(data["protected"]),
            should_protect=int(data["should_protect"]),
            missed=int(data["missed"]),
            field_missing=int(data["field_missing"]),
            parse_ok=int(data["parse_ok"]),
            parse_total=int(data["parse_total"]),
            field_coverage_rate=float(data["field_coverage_rate"]),
            parse_success_rate=float(data["parse_success_rate"]),
            missed_refs=[dict(ref) for ref in data.get("missed_refs", [])],
            field_missing_refs=[dict(ref) for ref in data.get("field_missing_refs", [])],
            state=data.get("state", "已确认"),
            created_at=data.get("created_at", ""),
        )


class MaskCoverageLedger:
    """脱敏覆盖批次台账。

    职责：
    - 登记脱敏核验入口产出的覆盖批次（按世代追加，旧世代不可变）；
    - 管理补做领取、逐字段回执、回执登记与撤回；
    - 重启恢复：核实已确认未登记回执对应字段的真实保护结果后补登记；
    - 质报汇总：同一期报告只确认一次，报告可从选用的批次复算。
    """

    def __init__(self) -> None:
        self._batches: list[MaskCoverageBatch] = []
        self._receipts: dict[str, MaskRedoReceipt] = {}
        self._claims: dict[tuple[str, str], dict[str, str]] = {}
        self._reports: dict[str, QualityReportSnapshot] = {}
        self._seq = 0
        self._lock = threading.RLock()

    # ---------- 内部工具 ----------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _registered_receipt_ids(self) -> set[str]:
        return {
            item.receipt_id
            for batch in self._batches
            for item in batch.items
            if item.receipt_id
        }

    def get_batch(self, batch_id: str) -> MaskCoverageBatch | None:
        for batch in self._batches:
            if batch.batch_id == batch_id:
                return batch
        return None

    def batches(self) -> list[MaskCoverageBatch]:
        return list(self._batches)

    def receipts(self) -> list[MaskRedoReceipt]:
        return list(self._receipts.values())

    def get_receipt(self, receipt_id: str) -> MaskRedoReceipt | None:
        return self._receipts.get(receipt_id)

    # ---------- 脱敏核验入口：登记覆盖批次 ----------

    def register_batch(self, items: list[MaskCoverageItem],
                       origin: str = ORIGIN_VERIFICATION) -> MaskCoverageBatch:
        """登记一代脱敏覆盖批次；新世代成为实际发布批次。"""
        with self._lock:
            seq = self._next_seq()
            batch = MaskCoverageBatch(
                batch_id=f"COVB-{seq:04d}",
                generation=len(self._batches) + 1,
                origin=origin,
                items=list(items),
            )
            self._batches.append(batch)
            return batch

    def published_batch(self) -> MaskCoverageBatch | None:
        """实际发布批次（最新世代）——补做与初验冲突时按它取证。"""
        with self._lock:
            return self._batches[-1] if self._batches else None

    def latest_verification_batch(self) -> MaskCoverageBatch | None:
        """最近一代初验批次（不含补做/撤回世代）。"""
        with self._lock:
            for batch in reversed(self._batches):
                if batch.origin == ORIGIN_VERIFICATION:
                    return batch
            return None

    # ---------- 补做：领取 → 重放 → 回执 → 登记 ----------

    def claim_redo(self, record_ref: str, field_name: str) -> dict[str, Any]:
        """质检员按匿名位置领取漏遮盖项交给补做。

        - 只能领取当前发布批次里的漏遮盖项；
        - 已领取或已有回执时返回既有结果（重领幂等，不因报告仍有失败就重发）。
        """
        with self._lock:
            key = (record_ref, field_name)
            existing = self._claims.get(key)
            if existing is not None:
                receipt = self._receipts.get(existing.get("receipt_id", ""))
                return {
                    "ok": True,
                    "already_claimed": True,
                    "claim": dict(existing),
                    "receipt": receipt.to_dict() if receipt else None,
                }
            batch = self.published_batch()
            item = batch.find_item(record_ref, field_name) if batch else None
            if item is None:
                return {"ok": False, "message": f"匿名位置 {record_ref}/{field_name} 不在覆盖批次中"}
            if item.status == ITEM_FIELD_MISSING:
                return {"ok": False, "message": "原字段缺失的行不能补做，不能生成假保护成功"}
            if item.status == ITEM_PROTECTED:
                return {"ok": False, "message": "该字段已保护成功，无需补做"}
            claim = {
                "record_ref": record_ref,
                "field_name": field_name,
                "rule_id": item.rule_id,
                "claimed_at": _now(),
                "receipt_id": "",
            }
            self._claims[key] = claim
            return {"ok": True, "already_claimed": False, "claim": dict(claim), "receipt": None}

    def complete_redo(self, record_ref: str, field_name: str,
                      record: EventRecord, rule: MaskRule) -> MaskRedoReceipt:
        """保护侧执行补做：只重放该字段对应的保护规则，产出逐字段回执。

        约束：
        - 缺账号（原字段缺失）的行不能生成假保护成功；
        - 原来已保护的字段不得重新从原值回填；
        - 只应用该字段这一条规则，不动其他字段。
        """
        with self._lock:
            key = (record_ref, field_name)
            claim = self._claims.get(key)
            if claim is None:
                claim = {
                    "record_ref": record_ref,
                    "field_name": field_name,
                    "rule_id": rule.rule_id,
                    "claimed_at": _now(),
                    "receipt_id": "",
                }
                self._claims[key] = claim
            if claim.get("receipt_id"):
                # 已有回执：重领/重放直接返回既有回执，不重复处理
                return self._receipts[claim["receipt_id"]]

            seq = self._next_seq()
            receipt = MaskRedoReceipt(
                receipt_id=f"REDO-{seq:04d}",
                record_ref=record_ref,
                field_name=field_name,
                rule_id=rule.rule_id,
                result=REDO_REJECTED,
            )
            if rule.target_field != field_name:
                receipt.detail = "保护规则与字段不对应，拒绝重放"
            else:
                original = record.parsed_fields.get(field_name, "")
                masked_now = record.masked_fields.get(field_name, "")
                if not original:
                    receipt.detail = "原字段缺失，不能生成假保护成功"
                elif is_field_protected(original, masked_now):
                    # 已保护的字段不得重新从原值回填
                    receipt.result = REDO_PROTECTED
                    receipt.detail = "字段已保护，未重新回填"
                else:
                    replayed = rule.apply(original)
                    if is_field_protected(original, replayed):
                        record.masked_fields[field_name] = replayed
                        receipt.result = REDO_PROTECTED
                        receipt.detail = "已重放该字段保护规则"
                    else:
                        receipt.detail = "保护规则重放后仍未遮盖"
            self._receipts[receipt.receipt_id] = receipt
            claim["receipt_id"] = receipt.receipt_id
            return receipt

    def register_receipt(self, receipt_id: str) -> MaskCoverageBatch | None:
        """把补做成功登记进覆盖批次：派生新世代并发布。

        只有 confirmed 且结果为 protected 的回执可以登记；重复登记幂等。
        """
        with self._lock:
            receipt = self._receipts.get(receipt_id)
            if receipt is None or receipt.result != REDO_PROTECTED:
                return None
            if receipt.state != RECEIPT_CONFIRMED:
                return None
            if receipt_id in self._registered_receipt_ids():
                return self.published_batch()
            base = self.published_batch()
            if base is None:
                return None
            item = base.find_item(receipt.record_ref, receipt.field_name)
            if item is None or item.status != ITEM_MISSED:
                # 只有漏遮盖项需要登记补做成功；已保护项不重复登记，
                # 缺账号项不能登记假保护成功
                return base
            items = [MaskCoverageItem(**prev.to_dict()) for prev in base.items]
            for item in items:
                if (item.record_ref == receipt.record_ref
                        and item.field_name == receipt.field_name):
                    item.status = ITEM_PROTECTED
                    item.receipt_id = receipt.receipt_id
            return self.register_batch(items, origin=ORIGIN_REDO)

    def withdraw_receipt(self, receipt_id: str) -> MaskCoverageBatch | None:
        """撤回一次补做：回执标记撤回，派生新世代恢复未保护计数。

        旧世代与旧报告保持不变，旧报告和旧回执仍能核对。
        """
        with self._lock:
            receipt = self._receipts.get(receipt_id)
            if receipt is None or receipt.state == RECEIPT_WITHDRAWN:
                return None
            receipt.state = RECEIPT_WITHDRAWN
            if receipt_id not in self._registered_receipt_ids():
                return None
            base = self.published_batch()
            items = [MaskCoverageItem(**prev.to_dict()) for prev in base.items]
            for item in items:
                if item.receipt_id == receipt_id:
                    item.status = ITEM_MISSED
                    item.receipt_id = ""
            return self.register_batch(items, origin=ORIGIN_WITHDRAW)

    # ---------- 重启恢复 ----------

    def recover(self, records_by_ref: dict[str, EventRecord]) -> list[str]:
        """重启恢复：核实已确认但未登记回执对应字段的真实保护结果。

        - 字段确实已保护（回执有效）→ 补登记进覆盖批次；
        - 不把已经遮盖过的值当原账号再处理（不改动任何 masked_fields）；
        - 不凭报告上仍有失败就重发补做（已有回执的领取保持幂等）。
        返回本次补登记回执编号列表。
        """
        recovered: list[str] = []
        with self._lock:
            pending = [
                receipt for receipt in self._receipts.values()
                if receipt.state == RECEIPT_CONFIRMED
                and receipt.result == REDO_PROTECTED
                and receipt.receipt_id not in self._registered_receipt_ids()
            ]
            for receipt in pending:
                record = records_by_ref.get(receipt.record_ref)
                if record is None:
                    continue
                original = record.parsed_fields.get(receipt.field_name, "")
                masked = record.masked_fields.get(receipt.field_name, "")
                # 核实原字段真正的保护结果，只读取不回填
                if is_field_protected(original, masked):
                    self.register_receipt(receipt.receipt_id)
                    recovered.append(receipt.receipt_id)
        return recovered

    # ---------- 质报汇总 ----------

    def issue_report(self, period: str, parse_ok: int, parse_total: int,
                     include_redo: bool = True) -> QualityReportSnapshot:
        """出具一期质量报告：同一期只确认一次，并发重入返回既有报告。

        取证优先级：允许纳入补做时按实际发布批次（含补做登记/撤回世代），
        否则按最近一代初验批次。
        """
        with self._lock:
            existing = self._reports.get(period)
            if existing is not None:
                return existing
            batch = (self.published_batch() if include_redo
                     else self.latest_verification_batch())
            if batch is None:
                raise ValueError("无可用脱敏覆盖批次，无法出具质量报告")
            seq = self._next_seq()
            parse_rate = round(parse_ok / parse_total, 4) if parse_total else 0.0
            report = QualityReportSnapshot(
                report_id=f"QUAL-{seq:04d}",
                period=period,
                batch_id=batch.batch_id,
                batch_generation=batch.generation,
                protected=batch.protected_count(),
                should_protect=batch.should_protect_count(),
                missed=batch.missed_count(),
                field_missing=batch.field_missing_count(),
                parse_ok=parse_ok,
                parse_total=parse_total,
                field_coverage_rate=batch.coverage_rate(),
                parse_success_rate=parse_rate,
                missed_refs=batch.missed_refs(),
                field_missing_refs=batch.field_missing_refs(),
            )
            self._reports[period] = report
            return report

    def get_report(self, period: str) -> QualityReportSnapshot | None:
        return self._reports.get(period)

    def reports(self) -> list[QualityReportSnapshot]:
        return list(self._reports.values())

    def recompute_report(self, report: QualityReportSnapshot) -> dict[str, Any]:
        """从报告选用的批次复算保护结果和分母，核对报告是否一致。"""
        batch = self.get_batch(report.batch_id)
        if batch is None:
            return {"ok": False, "message": f"批次 {report.batch_id} 不存在"}
        expected = {
            "protected": batch.protected_count(),
            "should_protect": batch.should_protect_count(),
            "missed": batch.missed_count(),
            "field_missing": batch.field_missing_count(),
            "field_coverage_rate": batch.coverage_rate(),
        }
        actual = {
            "protected": report.protected,
            "should_protect": report.should_protect,
            "missed": report.missed,
            "field_missing": report.field_missing,
            "field_coverage_rate": report.field_coverage_rate,
        }
        return {"ok": expected == actual, "expected": expected, "actual": actual}

    # ---------- 状态导出 / 恢复（模拟重启：回执已持久化、批次未登记） ----------

    def export_state(self) -> dict[str, Any]:
        """导出可持久化状态（全部匿名，不含账号原文）。"""
        with self._lock:
            return {
                "seq": self._seq,
                "batches": [
                    {
                        "batch_id": batch.batch_id,
                        "generation": batch.generation,
                        "origin": batch.origin,
                        "state": batch.state,
                        "created_at": batch.created_at,
                        "items": [item.to_dict() for item in batch.items],
                    }
                    for batch in self._batches
                ],
                "receipts": [receipt.to_dict() for receipt in self._receipts.values()],
                "claims": [
                    dict(claim) for claim in self._claims.values()
                ],
                "reports": [report.to_dict() for report in self._reports.values()],
            }

    @classmethod
    def restore_state(cls, state: dict[str, Any]) -> "MaskCoverageLedger":
        """从持久化状态恢复台账（重启后回执仍在、批次世代完整）。"""
        ledger = cls()
        ledger._seq = int(state.get("seq", 0))
        for raw in state.get("batches", []):
            ledger._batches.append(MaskCoverageBatch(
                batch_id=raw["batch_id"],
                generation=int(raw["generation"]),
                origin=raw["origin"],
                state=raw.get("state", "已发布"),
                created_at=raw.get("created_at", ""),
                items=[MaskCoverageItem.from_dict(item) for item in raw.get("items", [])],
            ))
        for raw in state.get("receipts", []):
            receipt = MaskRedoReceipt.from_dict(raw)
            ledger._receipts[receipt.receipt_id] = receipt
        for claim in state.get("claims", []):
            ledger._claims[(claim["record_ref"], claim["field_name"])] = dict(claim)
        for raw in state.get("reports", []):
            report = QualityReportSnapshot.from_dict(raw)
            ledger._reports[report.period] = report
        return ledger


def make_coverage_ledger() -> MaskCoverageLedger:
    """工厂函数：创建脱敏覆盖批次台账实例。"""
    return MaskCoverageLedger()
