"""拾音工坊脱敏与字段增强管道：event_store→mask_rule→field_enrich→event_type。

数据流：已存储的 EventRecord → 脱敏变换 (mask_rule) → 字段增强 (field_enrich) → 更新事件分类标记
涉及模块：event_store, mask_rule, field_enrich, event_type
"""
from __future__ import annotations

from typing import Any

from app.core.mask_coverage import (
    ITEM_FIELD_MISSING, ITEM_MISSED, ITEM_PROTECTED, MaskCoverageBatch,
    MaskCoverageLedger, MaskCoverageItem, MaskRedoReceipt, is_field_protected,
    make_coverage_ledger,
)
from app.core.models import (
    EventRecord, FieldEnrichRule, MaskMethod, MaskResult, MaskRule,
)

# ---------- 预置脱敏规则 ----------

PRESET_MASK_RULES: list[MaskRule] = [
    MaskRule(
        rule_id="MASK-0001",
        target_field="client_ip",
        mask_method=MaskMethod.IP,
        mask_pattern="",
        rule_state="生效中",
    ),
    MaskRule(
        rule_id="MASK-0002",
        target_field="user_agent",
        mask_method=MaskMethod.CUSTOM_REGEX,
        mask_pattern=r'[A-Za-z0-9+/]{40,}=*',
        rule_state="生效中",
    ),
    MaskRule(
        rule_id="MASK-0003",
        target_field="message",
        mask_method=MaskMethod.PHONE,
        mask_pattern="",
        rule_state="生效中",
    ),
]

# ---------- 预置字段增强规则 ----------

PRESET_ENRICH_RULES: list[FieldEnrichRule] = [
    FieldEnrichRule(
        rule_id="FIEL-0001",
        target_field="app_name",
        enrich_source="logger",
        mapping_dict={
            "com.example.IngestController": "ingest-service",
            "com.example.ParserEngine": "parser-engine",
            "com.example.CheckpointStore": "checkpoint-store",
            "com.example.MaskService": "mask-service",
        },
        default_value="unknown-service",
        priority=10,
    ),
    FieldEnrichRule(
        rule_id="FIEL-0002",
        target_field="severity_level",
        enrich_source="level",
        mapping_dict={
            "INFO": "LOW",
            "WARN": "MEDIUM",
            "ERROR": "HIGH",
            "DEBUG": "TRACE",
        },
        default_value="UNKNOWN",
        priority=10,
    ),
    FieldEnrichRule(
        rule_id="FIEL-0003",
        target_field="status_category",
        enrich_source="status",
        mapping_dict={
            "200": "SUCCESS",
            "201": "SUCCESS",
            "301": "REDIRECT",
            "302": "REDIRECT",
            "400": "CLIENT_ERROR",
            "401": "AUTH_ERROR",
            "403": "AUTH_ERROR",
            "404": "CLIENT_ERROR",
            "500": "SERVER_ERROR",
            "502": "SERVER_ERROR",
            "503": "SERVER_ERROR",
        },
        default_value="OTHER",
        priority=5,
    ),
]


class MaskEnrichPipeline:
    """脱敏与字段增强处理管道。

    接收 EventRecord 集合 → 依次应用 mask_rule → field_enrich → 更新 event_type 标记
    """

    def __init__(self, mask_rules: list[MaskRule] | None = None,
                 enrich_rules: list[FieldEnrichRule] | None = None,
                 ledger: MaskCoverageLedger | None = None):
        if mask_rules is None:
            mask_rules = PRESET_MASK_RULES
        if enrich_rules is None:
            enrich_rules = PRESET_ENRICH_RULES
        self.mask_rules = mask_rules
        self.enrich_rules = enrich_rules
        self._mask_results: list[MaskResult] = []
        # 脱敏覆盖批次台账：串联脱敏核验入口与质报汇总
        self.coverage_ledger = ledger if ledger is not None else make_coverage_ledger()

    # ---------- 数据流 3: event_store → mask_rule → field_enrich → event_type ----------

    def apply_all_masks(self, record: EventRecord) -> MaskResult:
        """对一条事件记录的所有敏感字段执行脱敏变换。

        每条脱敏规则按目标字段匹配 record.parsed_fields，
        执行对应脱敏方式（phone/id_card/email/ip/custom_regex）。
        脱敏后的值写入 record.masked_fields。
        """
        last_result: MaskResult | None = None
        for rule in self.mask_rules:
            target = rule.target_field
            value = record.parsed_fields.get(target, "")
            if not value:
                continue
            masked_value = rule.apply(value)
            record.masked_fields[target] = masked_value
            result = MaskResult(
                rule_id=rule.rule_id,
                field_name=target,
                original=value,
                masked=masked_value,
                method=rule.mask_method,
                is_masked=masked_value != value,
            )
            self._mask_results.append(result)
            last_result = result
        return last_result if last_result else MaskResult(
            rule_id="", field_name="", original="", masked="",
            method=MaskMethod.CUSTOM_REGEX, is_masked=False,
        )

    def apply_all_enrichments(self, record: EventRecord) -> dict[str, str]:
        """对一条事件记录执行所有字段增强。

        每条增强规则按 enrich_source 作为查询键查找 mapping_dict，
        将映射值写入 record.enriched_fields 的 target_field 下。
        未命中映射时使用 default_value。
        """
        enriched: dict[str, str] = {}
        for rule in sorted(self.enrich_rules, key=lambda r: r.priority):
            source_value = (
                record.parsed_fields.get(rule.enrich_source) or
                record.masked_fields.get(rule.enrich_source) or ""
            )
            mapped = rule.enrich(record.parsed_fields)
            record.enriched_fields[rule.target_field] = mapped
            enriched[rule.target_field] = mapped
        return enriched

    def process_records(self, records: list[EventRecord]) -> list[EventRecord]:
        """批量处理事件记录：依次执行脱敏和字段增强。

        这是 event_store → mask_rule → field_enrich → event_type 的完整实现。
        """
        for record in records:
            # 1. mask_rule: 脱敏变换
            self.apply_all_masks(record)
            # 2. field_enrich: 字段增强
            self.apply_all_enrichments(record)
            # 3. event_type: 增强后重新评估严重级别
            self._update_severity(record)
        return records

    def verify_mask_coverage(self, records: list[EventRecord]) -> MaskCoverageBatch:
        """脱敏核验入口：逐字段核验并登记一代脱敏覆盖批次。

        对每条记录 × 每条脱敏规则判定覆盖项状态：
        - 原字段缺失（无账号原值）→ field_missing，不进应保护分母；
        - 掩码值有效（不同于原值且不含原值核心）→ protected；
        - 其余（含未脱敏、掩码后仍泄露）→ missed。
        批次登记进台账，供质报汇总按实际发布批次取证。
        """
        items: list[MaskCoverageItem] = []
        for record in records:
            for rule in self.mask_rules:
                target = rule.target_field
                original = record.parsed_fields.get(target, "")
                if not original:
                    items.append(MaskCoverageItem(
                        record_ref=record.record_id, field_name=target,
                        rule_id=rule.rule_id, status=ITEM_FIELD_MISSING,
                    ))
                    continue
                masked = record.masked_fields.get(target, original)
                status = (ITEM_PROTECTED if is_field_protected(original, masked)
                          else ITEM_MISSED)
                items.append(MaskCoverageItem(
                    record_ref=record.record_id, field_name=target,
                    rule_id=rule.rule_id, status=status,
                ))
        return self.coverage_ledger.register_batch(items)

    def verify_mask_completeness(self, records: list[EventRecord]) -> dict[str, Any]:
        """验证脱敏完整性：检查是否有敏感值泄露（遗漏告警）。

        覆盖率按脱敏覆盖批次计算：保护成功项 / 应保护项，
        同一字段在多行漏遮盖时也不会出现负覆盖率。
        返回的遗漏清单只带匿名来源位置，不带账号原文。
        """
        batch = self.verify_mask_coverage(records)
        return {
            "total_rules": len(self.mask_rules),
            "leaks_found": batch.missed_count(),
            "leaks_detail": batch.missed_refs(),
            "coverage_rate": batch.coverage_rate(),
            "batch_id": batch.batch_id,
            "generation": batch.generation,
            "protected": batch.protected_count(),
            "should_protect": batch.should_protect_count(),
            "missed": batch.missed_count(),
            "field_missing": batch.field_missing_count(),
            "field_missing_refs": batch.field_missing_refs(),
        }

    def redo_field(self, record_ref: str, field_name: str,
                   records: list[EventRecord]) -> MaskRedoReceipt:
        """保护侧补做入口：按匿名位置找到原行，只重放该字段对应的保护规则。

        原来已保护的字段不会重新从原值回填；缺账号的行不能生成假保护成功。
        回执需经 ledger.register_receipt 登记后才进入覆盖批次。
        """
        record = next((r for r in records if r.record_id == record_ref), None)
        if record is None:
            raise ValueError(f"匿名位置 {record_ref} 对应的记录不存在")
        rule = next((r for r in self.mask_rules if r.target_field == field_name), None)
        if rule is None:
            raise ValueError(f"字段 {field_name} 没有对应的保护规则")
        return self.coverage_ledger.complete_redo(record_ref, field_name, record, rule)

    def verify_enrich_mapping(self, expected_enrich_count: int) -> dict[str, Any]:
        """验证字段增强：检查是否有映射缺失。

        统计 enrichment 实际生效的规则数量和映射质量。
        """
        return {
            "expected_rules": expected_enrich_count,
            "actual_rules": len(self.enrich_rules),
            "rules_active": [r.rule_id for r in self.enrich_rules],
            "mapping_missing": any(
                r.default_value != "unknown" for r in self.enrich_rules
            ),
        }

    def get_mask_results(self) -> list[MaskResult]:
        return list(self._mask_results)

    def _update_severity(self, record: EventRecord):
        """根据增强后的字段更新事件记录的严重级别。"""
        enhanced_severity = record.enriched_fields.get("severity_level", "")
        if enhanced_severity == "HIGH":
            record.event_type.severity = "HIGH"
        elif enhanced_severity == "MEDIUM":
            record.event_type.severity = "MEDIUM"
        elif enhanced_severity == "TRACE":
            record.event_type.severity = "DEBUG"


def make_mask_enrich_pipeline() -> MaskEnrichPipeline:
    """工厂函数：创建预配置的脱敏/增强管道实例。"""
    return MaskEnrichPipeline()