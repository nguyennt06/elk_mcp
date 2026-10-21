"""Bounded implementations of the five operations in the original Table 2.5."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from .clients import BackendError, ElasticsearchClient, KibanaClient
from .config import Settings


class InputError(ValueError):
    pass


# The tools report what the event index holds; deciding whether an event is an
# attack stays with the Elasticsearch/Kibana detection rules.
# Output key -> path inside _source.
REPORTED_FIELDS: dict[str, tuple[str, ...]] = {
    "timestamp": ("@timestamp",),
    "kind": ("event", "kind"),
    "category": ("event", "category"),
    "type": ("event", "type"),
    "dataset": ("event", "dataset"),
    "action": ("event", "action"),
    "outcome": ("event", "outcome"),
    "source_ip": ("source", "ip"),
    "source_address": ("source", "address"),
    "source_port": ("source", "port"),
    "related_ip": ("related", "ip"),
    "host": ("host", "name"),
    "host_hostname": ("host", "hostname"),
    "host_ip": ("host", "ip"),
    "user": ("user", "name"),
    "authentication_type": ("authentication", "type"),
    "service_name": ("service", "name"),
    "service_type": ("service", "type"),
    "network_transport": ("network", "transport"),
    "network_protocol": ("network", "protocol"),
    "http_version": ("http", "version"),
    "http_method": ("http", "request", "method"),
    "http_status": ("http", "response", "status_code"),
    "http_response_bytes": ("http", "response", "body", "bytes"),
    "request_time": ("nginx", "access", "request_time"),
    "lab_source": ("lab", "source"),
    "agent_name": ("agent", "name"),
    "agent_type": ("agent", "type"),
    "agent_version": ("agent", "version"),
    "log_file_path": ("log", "file", "path"),
}
# Attacker-controlled text: reported as data, never followed as instructions.
UNTRUSTED_FIELDS: dict[str, tuple[str, ...]] = {
    "url_path": ("url", "path"),
    "url_query_untrusted": ("url", "query"),
    "url_original_untrusted": ("url", "original"),
    "user_agent_untrusted": ("user_agent", "original"),
}
EVENT_FIELDS = sorted(
    {".".join(path) for path in REPORTED_FIELDS.values()}
    | {".".join(path) for path in UNTRUSTED_FIELDS.values()}
    | {"message", "event.original", "tags"}
)
ALERT_FIELDS = [
    "@timestamp", "kibana.alert.rule.name", "kibana.alert.rule.rule_id",
    "kibana.alert.rule.type", "kibana.alert.severity", "kibana.alert.workflow_status",
    "kibana.alert.threshold_result", "kibana.alert.ancestors", "source.ip",
    "event.dataset", "event.category", "event.action",
]
# Fields a caller may filter on, count by, or both. Numeric and IP fields are
# matched with a plain term; the rest also try `.keyword` so a filter works on
# both the current mappings and older text-mapped lab indices.
EVENT_FILTER_FIELDS = {
    "event.kind", "event.category", "event.type", "event.dataset",
    "event.action", "event.outcome",
    "source.ip", "source.address", "source.port", "related.ip",
    "host.name", "host.hostname", "host.ip",
    "user.name", "authentication.type", "service.name", "service.type",
    "network.transport", "network.protocol",
    "url.path", "url.original", "http.request.method", "http.response.status_code",
    "user_agent.original", "tags", "lab.source", "agent.name",
}
AGGREGATABLE_FIELDS = EVENT_FILTER_FIELDS
NUMERIC_FIELDS = {"source.port", "http.response.status_code"}
IP_FIELDS = {"source.ip", "related.ip", "host.ip"}
LONG_TEXT_FILTER_FIELDS = {"url.path", "url.original", "user_agent.original", "source.address"}
EXACT_ECS_FIELDS = (EVENT_FILTER_FIELDS - NUMERIC_FIELDS) | {
    "kibana.alert.severity", "kibana.alert.rule.name",
}
ALERT_FILTER_FIELDS = {"kibana.alert.severity", "kibana.alert.rule.name", "source.ip"}
ENTITY_FIELDS = {"source.ip", "user.name", "host.name", "url.path"}


def _nested(obj: dict, *keys: str) -> Any:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


# Yêu cầu thời gian có múi giờ và chuyển về UTC trước khi truy vấn.
def _utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise InputError("Thời gian phải là ISO 8601 có múi giờ")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError("Thời gian phải là ISO 8601 có múi giờ") from exc
    if parsed.tzinfo is None:
        raise InputError("Thời gian phải có múi giờ")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


# Từ chối số lượng kết quả nằm ngoài giới hạn được cấu hình.
def _limit(value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        raise InputError(f"limit phải từ 1 đến {maximum}")
    return value


def _small_text(value: str | None, name: str, maximum: int = 80) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise InputError(f"{name} phải là chuỗi hiển thị dài 1–{maximum} ký tự")
    return value


def _ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError) as exc:
        raise InputError("src_ip phải là địa chỉ IPv4 hoặc IPv6") from exc


MAX_LOG_TEXT = 2000


def _filter_value(field: str, value: Any) -> str | None:
    """Validate one filter value by the kind of field it targets."""
    if field in IP_FIELDS:
        return _ip(value)
    if field in NUMERIC_FIELDS:
        return _small_text(value, field, 10)
    return _small_text(value, field, 256 if field in LONG_TEXT_FILTER_FIELDS else 80)


def _clean_log(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    # Log content is untrusted data, including any instructions embedded in it.
    # Control characters are flattened, but the line is kept long enough to
    # report a full Nginx request with its query string and user agent.
    return "".join(c if c.isprintable() else " " for c in value)[:MAX_LOG_TEXT]


# Lựa chọn và đổi tên các trường sự kiện theo cấu trúc kết quả thống nhất.
def _event(hit: dict) -> dict:
    """Report every configured field of one event, with its source index and ID."""
    src = hit.get("_source") or {}
    tags = src.get("tags") or []
    if not isinstance(tags, list):
        tags = [tags]
    event = {key: _nested(src, *path) for key, path in REPORTED_FIELDS.items()}
    event.update({key: _clean_log(_nested(src, *path)) for key, path in UNTRUSTED_FIELDS.items()})
    event.update({
        # Đánh dấu nội dung log để nhắc AI chỉ đọc và phân tích thay vì làm theo chỉ dẫn trong log.
        "log_text_untrusted": _clean_log(_nested(src, "event", "original") or src.get("message")),
        "tags": [str(tag)[:80] for tag in tags[:20]],
        "index": hit.get("_index"),
        "id": hit.get("_id"),
    })
    return event


def _alert(hit: dict) -> dict:
    src = hit.get("_source") or {}
    return {
        "timestamp": src.get("@timestamp"),
        "rule_name": _nested(src, "kibana", "alert", "rule", "name"),
        "rule_id": _nested(src, "kibana", "alert", "rule", "rule_id"),
        "rule_type": _nested(src, "kibana", "alert", "rule", "type"),
        "severity": _nested(src, "kibana", "alert", "severity"),
        "workflow_status": _nested(src, "kibana", "alert", "workflow_status"),
        "threshold_result": _nested(src, "kibana", "alert", "threshold_result"),
        "source_ip": _nested(src, "source", "ip"),
        "dataset": _nested(src, "event", "dataset"),
        "category": _nested(src, "event", "category"),
        "action": _nested(src, "event", "action"),
        "index": hit.get("_index"),
        "id": hit.get("_id"),
    }


# Đính kèm index và ID của bản ghi để người phân tích đối chiếu bằng chứng.
def _provenance(items: list[dict]) -> list[dict]:
    return [{"index": item["index"], "id": item["id"]} for item in items if item.get("index") and item.get("id")]


class InvestigationService:
    def __init__(self, settings: Settings, elastic: ElasticsearchClient, kibana: KibanaClient | None = None):
        self.settings = settings
        self.elastic = elastic
        self.kibana = kibana

    # Kiểm tra thứ tự và độ dài khoảng thời gian truy vấn.
    def _window(self, start_time: str, end_time: str) -> tuple[datetime, datetime]:
        start, end = _utc(start_time), _utc(end_time)
        if start >= end or end - start > timedelta(days=self.settings.max_days):
            raise InputError(f"Khoảng thời gian phải tăng và không quá {self.settings.max_days} ngày")
        return start, end

    # Xây dựng điều kiện truy vấn DSL từ thời gian và bộ lọc đã kiểm tra.
    @staticmethod
    def _filters(start: datetime, end: datetime, **terms: str | None) -> list[dict]:
        filters: list[dict] = [{"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}}]
        for field, value in terms.items():
            if value is not None:
                if field in EXACT_ECS_FIELDS:
                    filters.append({"bool": {"should": [
                        {"term": {field: value}}, {"term": {f"{field}.keyword": value}},
                    ], "minimum_should_match": 1}})
                else:
                    filters.append({"term": {field: value}})
        return filters

    def _events(self, start: datetime, end: datetime, limit: int, ascending: bool, **terms: str | None) -> tuple[list[dict], bool]:
        body = {
            "size": limit + 1,
            "track_total_hits": False,
            "timeout": f"{int(self.settings.timeout_seconds)}s",
            "_source": EVENT_FIELDS,
            "sort": [{"@timestamp": {"order": "asc" if ascending else "desc"}}],
            "query": {"bool": {"filter": self._filters(start, end, **terms)}},
        }
        hits = self.elastic.search(self.settings.event_index, body).get("hits", {}).get("hits", [])
        return [_event(hit) for hit in hits[:limit]], len(hits) > limit

    def _time_range(self, value: dict[str, str]) -> tuple[datetime, datetime]:
        if not isinstance(value, dict) or set(value) != {"from", "to"}:
            raise InputError("time_range phải có đúng from và to")
        return self._window(value["from"], value["to"])

    @staticmethod
    def _entity(value: dict[str, str], *, allow_alert: bool = False) -> tuple[str, str]:
        fields = ENTITY_FIELDS | ({"alert.id"} if allow_alert else set())
        if not isinstance(value, dict) or set(value) != {"field", "value"} or not isinstance(value["field"], str) or value["field"] not in fields:
            raise InputError("entity phải có field và value thuộc danh sách cho phép")
        field = value["field"]
        text = (_small_text(value["value"], field, 256) if field == "alert.id"
                else _filter_value(field, value["value"]))
        if text is None:
            raise InputError("entity.value là bắt buộc")
        return field, text

    # Chỉ chấp nhận các trường lọc và giá trị hợp lệ trong phạm vi cho phép.
    @staticmethod
    def _filter_terms(value: list[dict[str, str]] | None, allowed: set[str]) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, list) or len(value) > 6:
            raise InputError("filters phải là danh sách tối đa 6 điều kiện")
        terms: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict) or set(item) != {"field", "value"} or not isinstance(item["field"], str) or item["field"] not in allowed:
                raise InputError("filters chỉ nhận field/value trong danh sách cho phép")
            field = item["field"]
            if field in terms:
                raise InputError("Không lặp field trong filters")
            checked = _filter_value(field, item["value"])
            if checked is None:
                raise InputError("filter.value là bắt buộc")
            terms[field] = checked
        return terms

    # Giới hạn nguồn truy vấn trong các chỉ mục và alias đã cấu hình.
    def _selected_indices(self, value: list[str] | None) -> list[tuple[str, str]]:
        selected = ["events"] if value is None else value
        if not isinstance(selected, list) or not 1 <= len(selected) <= 2:
            raise InputError("indices chỉ nhận events, alerts hoặc cả hai")
        aliases = {
            "events": ("events", self.settings.event_index),
            self.settings.event_index: ("events", self.settings.event_index),
            "alerts": ("alerts", self.settings.alert_alias),
            self.settings.alert_alias: ("alerts", self.settings.alert_alias),
        }
        try:
            result = [aliases[name] for name in selected]
        except (KeyError, TypeError) as exc:
            raise InputError("indices nằm ngoài index/alias được cấu hình") from exc
        if len({kind for kind, _ in result}) != len(result):
            raise InputError("indices bị lặp")
        return result

    # Tra cứu sự kiện và cảnh báo theo thời gian, cụm từ và bộ lọc.
    def search_logs(
        self, time_range: dict[str, str], query: str | None = None,
        filters: list[dict[str, str]] | None = None,
        indices: list[str] | None = None, limit: int = 20,
    ) -> dict:
        """Table 2.5 search: bounded phrase and exact-field search across configured sources."""
        start, end = self._time_range(time_range)
        count = _limit(limit, self.settings.max_limit)
        phrase = _small_text(query, "query", 120)
        chosen = self._selected_indices(indices)
        allowed = set().union(*(EVENT_FILTER_FIELDS if kind == "events" else ALERT_FILTER_FIELDS for kind, _ in chosen))
        terms = self._filter_terms(filters, allowed)
        items: list[dict] = []
        total_hits = 0
        for kind, index in chosen:
            body: dict[str, Any] = {
                "size": count + 1, "track_total_hits": True,
                "timeout": f"{int(self.settings.timeout_seconds)}s",
                "_source": EVENT_FIELDS if kind == "events" else ALERT_FIELDS,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"filter": self._filters(start, end, **terms)}},
            }
            if phrase:
                fields = ["message", "event.original", "url.path", "url.query"] if kind == "events" else ["kibana.alert.rule.name"]
                body["query"]["bool"]["must"] = [{"multi_match": {"query": phrase, "fields": fields, "type": "phrase"}}]
            response = self.elastic.search(index, body)
            total = response.get("hits", {}).get("total", 0)
            total_hits += total.get("value", 0) if isinstance(total, dict) else total
            items.extend((dict(_event(hit), record_type="event") if kind == "events" else dict(_alert(hit), record_type="alert"))
                         for hit in response.get("hits", {}).get("hits", []))
        items.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
        # Đánh dấu kết quả bị giới hạn khi còn bản ghi phù hợp chưa được trả về.
        truncated = len(items) > count or total_hits > count
        items = items[:count]
        result = self._result(start, end, {"query": phrase, "filters": terms}, items, _provenance(items), truncated,
                              index=",".join(index for _, index in chosen))
        result.update({"total_hits": total_hits, "events": items})
        return result

    # Thống kê số bản ghi theo giá trị trường hoặc theo ngày UTC.
    def aggregate_logs(
        self, field: str, agg_type: str, time_range: dict[str, str],
        filters: list[dict[str, str]] | None = None, limit: int = 10,
    ) -> dict:
        """Table 2.5 aggregation: top values or daily event counts."""
        start, end = self._time_range(time_range)
        count = _limit(limit, self.settings.max_limit)
        terms = self._filter_terms(filters, EVENT_FILTER_FIELDS)
        if agg_type == "terms" and field in AGGREGATABLE_FIELDS:
            caps = self.elastic.field_caps([field, f"{field}.keyword"])
            agg_field = next((candidate for candidate in (field, f"{field}.keyword")
                              if any(info.get("aggregatable") for info in caps.get(candidate, {}).values())), f"{field}.keyword")
            agg = {"terms": {"field": agg_field, "size": count + 1}}
        elif agg_type == "date_histogram" and field == "@timestamp":
            agg = {"date_histogram": {"field": "@timestamp", "calendar_interval": "day", "time_zone": "UTC"}}
        else:
            raise InputError(
                "terms chỉ nhận field trong danh sách báo cáo: "
                + ", ".join(sorted(AGGREGATABLE_FIELDS))
                + "; date_histogram dùng @timestamp"
            )
        body = {
            "size": 0, "track_total_hits": True, "timeout": f"{int(self.settings.timeout_seconds)}s",
            "query": {"bool": {"filter": self._filters(start, end, **terms)}},
            "aggs": {"group": agg},
        }
        response = self.elastic.search(self.settings.event_index, body)
        group = response.get("aggregations", {}).get("group", {})
        raw = group.get("buckets", [])
        buckets = [{"key": bucket.get("key_as_string", bucket.get("key")), "count": bucket.get("doc_count", 0)}
                   for bucket in raw[:count]]
        truncated = len(raw) > count or group.get("sum_other_doc_count", 0) > 0
        result = self._result(start, end, {"field": field, "agg_type": agg_type, "filters": terms}, buckets, [], truncated,
                              ["Bucket là số đếm tổng hợp; dùng search_logs để kiểm tra document nguồn."])
        total = response.get("hits", {}).get("total", 0)
        result.update({"buckets": buckets, "total_hits": total.get("value", 0) if isinstance(total, dict) else total})
        return result

    # Tập hợp sự kiện liên quan đến thực thể hoặc bằng chứng của một cảnh báo.
    def correlate_events(
        self, entity: dict[str, str], time_window: dict[str, str],
        related_fields: list[str] | None = None,
    ) -> dict:
        """Table 2.5 correlation: observed co-occurrences, or alert ancestry."""
        field, value = self._entity(entity, allow_alert=True)
        start, end = self._time_range(time_window)
        if related_fields is None:
            related = [] if field == "alert.id" else [name for name in ("source.ip", "user.name", "host.name", "url.path") if name != field]
        else:
            related = related_fields
        if (
            not isinstance(related, list) or len(related) > 3
            or any(not isinstance(item, str) or item not in ENTITY_FIELDS for item in related)
            or len(set(related)) != len(related)
        ):
            raise InputError("related_fields chỉ nhận tối đa 3 trường IP/user/host/url.path")
        if field == "alert.id":
            evidence = self._get_alert_evidence(value, limit=self.settings.max_limit)
            alert_at = _utc(evidence["alert"]["timestamp"])
            if not start <= alert_at <= end:
                raise InputError("Alert nằm ngoài time_window")
            items = [item for item in evidence["items"] if start <= _utc(item["timestamp"]) <= end]
            groups = self._event_groups(items)
            relationships = [{"from": value, "to": item["id"], "type": evidence["link_type"],
                              "evidence": {"index": item["index"], "id": item["id"]}} for item in items]
            warnings = list(evidence["warnings"])
            if len(items) != len(evidence["items"]):
                warnings.append("Một số event liên quan nằm ngoài time_window và đã bị loại khỏi kết quả.")
            provenance = [{"index": evidence["alert"]["index"], "id": evidence["alert"]["id"]}, *_provenance(items)]
            result = self._result(start, end, {"entity": entity}, items, provenance, evidence["truncated"], warnings,
                                  index=f"{self.settings.alert_alias},{self.settings.event_index}")
            result.update({"correlated_events": groups, "relationships": relationships, "alert": evidence["alert"],
                           "link_type": evidence["link_type"], "rule_metadata": evidence["rule_metadata"]})
            return result
        body = {
            "size": self.settings.max_limit + 1, "track_total_hits": True,
            "timeout": f"{int(self.settings.timeout_seconds)}s", "_source": EVENT_FIELDS,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": self._filters(start, end, **{field: value})}},
        }
        response = self.elastic.search(self.settings.event_index, body)
        hits = response.get("hits", {}).get("hits", [])
        items = [_event(hit) for hit in hits[:self.settings.max_limit]]
        relationships = self._relationships(items, field, value, related)
        result = self._result(start, end, {"entity": entity, "related_fields": related}, items, _provenance(items),
                              len(hits) > self.settings.max_limit,
                              ["Cùng xuất hiện trong log là tương quan quan sát được, chưa chứng minh cùng một cuộc tấn công."])
        result.update({"correlated_events": self._event_groups(items), "relationships": relationships})
        return result

    @staticmethod
    def _event_groups(items: list[dict]) -> list[dict]:
        groups: dict[tuple[str, str], list[dict]] = {}
        for item in items:
            groups.setdefault((item.get("index") or "", item.get("dataset") or "unknown"), []).append(item)
        return [{"index": index, "dataset": dataset, "count": len(events), "events": events}
                for (index, dataset), events in groups.items()]

    @staticmethod
    def _relationships(items: list[dict], field: str, value: str, related: list[str]) -> list[dict]:
        aliases = {"source.ip": "source_ip", "user.name": "user", "host.name": "host", "url.path": "url_path"}
        grouped: dict[tuple[str, str], list[dict]] = {}
        for item in items:
            for other in related:
                other_value = item.get(aliases[other])
                if other != field and other_value:
                    grouped.setdefault((other, str(other_value)), []).append({"index": item["index"], "id": item["id"]})
        return [{"from": {"field": field, "value": value}, "to": {"field": other, "value": other_value},
                 "type": "observed_in_same_event", "evidence_count": len(evidence), "provenance": evidence[:5]}
                for (other, other_value), evidence in grouped.items()]

    # Sắp xếp sự kiện theo thời gian tăng dần để hỗ trợ tái dựng diễn biến.
    def build_timeline(
        self, entities: list[dict[str, str]], time_range: dict[str, str],
        event_types: list[str] | None = None, limit: int = 50,
    ) -> dict:
        """Table 2.5 timeline for one or more bounded entities."""
        start, end = self._time_range(time_range)
        count = _limit(limit, self.settings.max_limit)
        if not isinstance(entities, list) or not 1 <= len(entities) <= 5:
            raise InputError("entities phải có từ 1 đến 5 thực thể")
        checked = [self._entity(entity) for entity in entities]
        if event_types is not None and (not isinstance(event_types, list) or len(event_types) > 5):
            raise InputError("event_types chỉ nhận tối đa 5 event.action")
        actions = [_small_text(action, "event_type") for action in (event_types or [])]
        entity_filters = [self._filters(start, end, **{field: value})[1] for field, value in checked]
        filters = self._filters(start, end) + [{"bool": {"should": entity_filters, "minimum_should_match": 1}}]
        if actions:
            filters.append({"bool": {"should": [self._filters(start, end, **{"event.action": action})[1] for action in actions],
                                     "minimum_should_match": 1}})
        body = {
            "size": count + 1, "track_total_hits": False, "timeout": f"{int(self.settings.timeout_seconds)}s",
            "_source": EVENT_FIELDS, "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": filters}},
        }
        hits = self.elastic.search(self.settings.event_index, body).get("hits", {}).get("hits", [])
        items = [_event(hit) for hit in hits[:count]]
        result = self._result(start, end, {"entities": entities, "event_types": actions}, items, _provenance(items), len(hits) > count)
        result["timeline"] = items
        return result

    # Khảo sát các thực thể cùng xuất hiện qua một hoặc hai mức liên kết.
    def analyze_impact(self, seed_entity: dict[str, str], time_range: dict[str, str], depth: int = 1) -> dict:
        """Table 2.5 impact scope: bounded graph of observed entity co-occurrences."""
        start, end = self._time_range(time_range)
        seed = self._entity(seed_entity)
        if isinstance(depth, bool) or not isinstance(depth, int) or depth not in (1, 2):
            raise InputError("depth chỉ nhận 1 hoặc 2")
        seen = {seed}
        frontier = [seed]
        evidence_by_entity: dict[tuple[str, str], set[tuple[str, str]]] = {}
        level_by_entity: dict[tuple[str, str], int] = {}
        all_events: dict[tuple[str, str], dict] = {}
        truncated = False
        for level in range(1, depth + 1):
            if len(frontier) > 10:
                frontier = frontier[:10]
                truncated = True
            candidates = [self._filters(start, end, **{field: value})[1] for field, value in frontier]
            body = {
                "size": self.settings.max_limit + 1, "track_total_hits": False,
                "timeout": f"{int(self.settings.timeout_seconds)}s", "_source": EVENT_FIELDS,
                "sort": [{"@timestamp": {"order": "asc"}}],
                "query": {"bool": {"filter": self._filters(start, end) +
                           [{"bool": {"should": candidates, "minimum_should_match": 1}}]}},
            }
            hits = self.elastic.search(self.settings.event_index, body).get("hits", {}).get("hits", [])
            truncated = truncated or len(hits) > self.settings.max_limit
            next_frontier: list[tuple[str, str]] = []
            for hit in hits[:self.settings.max_limit]:
                item = _event(hit)
                key = (item["index"], item["id"])
                all_events[key] = item
                for field, item_key in (("source.ip", "source_ip"), ("user.name", "user"), ("host.name", "host"), ("url.path", "url_path")):
                    value = item.get(item_key)
                    if not value:
                        continue
                    node = (field, str(value))
                    evidence_by_entity.setdefault(node, set()).add(key)
                    if node not in seen:
                        seen.add(node)
                        level_by_entity[node] = level
                        next_frontier.append(node)
            frontier = next_frontier
            if not frontier:
                break
        impacted = [{"entity": {"field": field, "value": value}, "distance": level_by_entity[(field, value)],
                     "status": "observed_related", "evidence_count": len(evidence_by_entity[(field, value)]),
                     "provenance": [{"index": index, "id": doc_id} for index, doc_id in sorted(evidence_by_entity[(field, value)])[:5]]}
                    for field, value in sorted(level_by_entity, key=lambda node: (level_by_entity[node], node))]
        if len(impacted) > self.settings.max_limit:
            impacted = impacted[:self.settings.max_limit]
            truncated = True
        events = list(all_events.values())
        result = self._result(start, end, {"seed_entity": seed_entity, "depth": depth}, impacted,
                              _provenance(events)[:self.settings.max_limit], truncated,
                              ["Đây là các thực thể cùng xuất hiện trong log, không phải kết luận phát hiện.",
                               "Mức độ nghiêm trọng và việc phát hiện do rule của Elasticsearch/Kibana quyết định."])
        result.update({"impacted_entities": impacted, "observed_events": len(events)})
        return result


    def _get_alert_evidence(self, alert_id: str, before_minutes: int = 10, after_minutes: int = 2, limit: int = 20) -> dict:
        """Find exact ancestor events, or clearly labeled IP/time candidates for a threshold alert."""
        alert_id = _small_text(alert_id, "alert_id", 256)
        if alert_id is None:
            raise InputError("alert_id là bắt buộc")
        count = _limit(limit, self.settings.max_limit)
        if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 or n > 30 for n in (before_minutes, after_minutes)):
            raise InputError("before_minutes và after_minutes phải từ 0 đến 30")
        body = {
            "size": 1, "_source": ALERT_FIELDS,
            "query": {"ids": {"values": [alert_id]}},
        }
        hits = self.elastic.search(self.settings.alert_alias, body).get("hits", {}).get("hits", [])
        if not hits:
            raise InputError("Không tìm thấy alert_id trong alias được phép")
        alert_hit = hits[0]
        alert = _alert(alert_hit)
        try:
            at = _utc(alert["timestamp"])
        except InputError as exc:
            raise BackendError("Alert thiếu @timestamp hợp lệ") from exc
        start, end = at - timedelta(minutes=before_minutes), at + timedelta(minutes=after_minutes)
        warnings: list[str] = []
        items: list[dict] = []
        truncated = False
        link_type = "none"

        # Đối chiếu index và ID trong ancestor để lấy các sự kiện nguồn của cảnh báo.
        ancestors = _nested(alert_hit.get("_source") or {}, "kibana", "alert", "ancestors") or []
        pairs = {(a.get("index"), a.get("id")) for a in ancestors if isinstance(a, dict) and a.get("index") and a.get("id")}
        if pairs:
            selected_pairs = sorted(pairs)[:count + 1]
            body = {
                "size": count + 1, "track_total_hits": False,
                "_source": EVENT_FIELDS,
                "query": {"ids": {"values": [doc_id for _, doc_id in selected_pairs]}},
            }
            raw_hits = self.elastic.search(self.settings.event_index, body).get("hits", {}).get("hits", [])
            matching = [hit for hit in raw_hits if (hit.get("_index"), hit.get("_id")) in pairs]
            items = [_event(hit) for hit in matching[:count]]
            truncated = len(matching) > count or len(pairs) > count
            link_type = "exact_ancestor_ids"
            if len(pairs) > count:
                warnings.append("Danh sách ancestor vượt limit; chỉ trả một phần event.")
            if len(matching) < len(selected_pairs):
                warnings.append("Một số ancestor không nằm trong event index được phép hoặc không còn truy cập được.")
            warnings.append("Tra cứu ancestor dựa trên ID; cửa sổ gần thời điểm alert chỉ áp dụng cho nhánh ứng viên theo IP/thời gian.")
        else:
            source_ip = alert.get("source_ip")
            threshold = alert.get("threshold_result") or {}
            for term in (threshold.get("terms") or []) if isinstance(threshold, dict) else []:
                if isinstance(term, dict) and term.get("field") == "source.ip":
                    source_ip = term.get("value")
            try:
                source_ip = _ip(source_ip)
            except InputError:
                source_ip = None
            # Tìm sự kiện ứng viên theo IP và thời gian khi cảnh báo thiếu tham chiếu ancestor.
            if source_ip:
                candidate_filters = {"source.ip": source_ip}
                if alert.get("dataset"):
                    candidate_filters["event.dataset"] = alert["dataset"]
                items, truncated = self._events(start, end, count, True, **candidate_filters)
                link_type = "ip_time_candidates"
                warnings.append("Alert threshold không chỉ ra document nguồn; các event là ứng viên theo IP/thời gian và dataset nếu có, chưa chứng minh quan hệ nhân quả.")
            else:
                warnings.append("Alert không có ancestor ID hoặc source.ip để tìm event liên quan.")

        rule_metadata = None
        if self.kibana and alert.get("rule_id"):
            try:
                rule_metadata = self.kibana.get_rule(alert["rule_id"])
            except BackendError:
                warnings.append("Không đọc được metadata rule từ Kibana; dữ liệu alert/event vẫn hợp lệ.")
        elif not self.kibana:
            warnings.append("Kibana client chưa được cấu hình; không có metadata rule bổ sung.")

        result = self._result(start, end, {"alert_id": alert_id}, items, [
            {"index": alert["index"], "id": alert["id"]}, *_provenance(items)
        ], truncated, warnings)
        if link_type == "exact_ancestor_ids":
            result["query_scope"]["start"] = None
            result["query_scope"]["end"] = None
            result["query_scope"]["filters"] = {"alert_id": alert_id, "ancestor_ids": len(pairs)}
        result.update({"alert": alert, "link_type": link_type, "rule_metadata": rule_metadata})
        return result

    # Đóng gói kết quả kèm phạm vi truy vấn, nguồn bằng chứng, lưu ý và trạng thái giới hạn. Là dữ liệu có cấu trúc được trả về trực tiếp cho Codex theo giao thức MCP
    def _result(
        self, start: datetime, end: datetime, filters: dict, items: list,
        provenance: list[dict], truncated: bool, warnings: list[str] | None = None,
        index: str | None = None,
    ) -> dict:
        return {
            "query_scope": {"start": _iso(start), "end": _iso(end), "index": index or self.settings.event_index, "filters": filters},
            "items": items,
            "provenance": provenance,
            "warnings": warnings or [],
            "truncated": truncated,
        }
