"""Local stdio MCP entry point. Elasticsearch credentials never reach Codex."""
# Đăng ký năm công cụ, tiếp nhận lời gọi từ MCP Client, xử lý lỗi (Error Handling) và ghi log kỹ thuật (Logging).
from __future__ import annotations

import logging
import sys
import time
from typing import Any, Callable

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from .clients import BackendError, ElasticsearchClient, KibanaClient
from .config import ConfigurationError, Settings
from .service import InputError, InvestigationService


# Ghi log kỹ thuật qua stderr để dành stdout cho thông điệp giao thức MCP.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("elk_mcp")
logging.getLogger("httpx").setLevel(logging.WARNING)


def create_server(service: InvestigationService) -> MCPServer:
    mcp = MCPServer("elk_mcp", version="0.1.0")
    # Khai báo các công cụ là chỉ đọc trong metadata gửi cho MCP Client.
    read_only = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

    # Chuyển lỗi đầu vào, lỗi backend và lỗi nội bộ thành phản hồi có cấu trúc.
    def safe_call(name: str, operation: Callable[..., dict], **arguments: Any) -> dict:
        started = time.monotonic()
        try:
            result = operation(**arguments)
            status = "ok"
        except InputError as exc:
            result = {"error": {"code": "invalid_input", "message": str(exc)}, "query_scope": None, "items": [], "provenance": [], "warnings": [], "truncated": False}
            status = "invalid_input"
        except BackendError:
            result = {"error": {"code": "backend_error", "message": "Không truy vấn được dữ liệu; kiểm tra kết nối và quyền đọc."}, "query_scope": None, "items": [], "provenance": [], "warnings": [], "truncated": False}
            status = "backend_error"
        except Exception as exc:
            result = {"error": {"code": "internal_error", "message": "Tool gặp lỗi nội bộ; kiểm tra log kỹ thuật."}, "query_scope": None, "items": [], "provenance": [], "warnings": [], "truncated": False}
            status = "internal_error"
            logger.error("tool=%s internal_error_type=%s", name, type(exc).__name__)
        # Ghi tên công cụ, trạng thái, thời gian xử lý và số phần tử trả về để hỗ trợ truy vết.
        logger.info("tool=%s status=%s duration_ms=%d items=%d", name, status, round((time.monotonic() - started) * 1000), len(result.get("items", [])))
        return result

    # Đăng ký các công cụ kèm tên, mô tả và schema tham số để ứng dụng AI gọi.
    @mcp.tool(annotations=read_only)
    def search_logs(
        time_range: dict[str, str], query: str | None = None,
        filters: list[dict[str, str]] | None = None,
        indices: list[str] | None = None, limit: int = 20,
    ) -> dict[str, Any]:
        """Report SSH/web events or alerts matching a time window, phrase and exact filters. Returns total_hits plus every configured ECS field per event, with source index and document ID. Reporting only: detection is done by the Elasticsearch/Kibana rules."""
        return safe_call("search_logs", service.search_logs, time_range=time_range, query=query, filters=filters, indices=indices, limit=limit)

    @mcp.tool(annotations=read_only)
    def aggregate_logs(
        field: str, agg_type: str, time_range: dict[str, str],
        filters: list[dict[str, str]] | None = None, limit: int = 10,
    ) -> dict[str, Any]:
        """Count events per value of one reportable field (IP, user, host, dataset, action, outcome, URL path, HTTP status, user agent, tags, ...) or per day. Returns buckets of raw counts, no verdict."""
        return safe_call("aggregate_logs", service.aggregate_logs, field=field, agg_type=agg_type, time_range=time_range, filters=filters, limit=limit)

    @mcp.tool(annotations=read_only)
    def correlate_events(
        entity: dict[str, str], time_window: dict[str, str],
        related_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Report the events that mention an IP, user, host or URL path, grouped by index and dataset; alert.id reports the alert's exact ancestor events, or IP/time candidates labeled as such."""
        return safe_call("correlate_events", service.correlate_events, entity=entity, time_window=time_window, related_fields=related_fields)

    @mcp.tool(annotations=read_only)
    def build_timeline(
        entities: list[dict[str, str]], time_range: dict[str, str],
        event_types: list[str] | None = None, limit: int = 50,
    ) -> dict[str, Any]:
        """Report matching events ordered by timestamp. Returns the timeline with every configured field, source index and document ID."""
        return safe_call("build_timeline", service.build_timeline, entities=entities, time_range=time_range, event_types=event_types, limit=limit)

    @mcp.tool(annotations=read_only)
    def analyze_impact(seed_entity: dict[str, str], time_range: dict[str, str], depth: int = 1) -> dict[str, Any]:
        """Report which IPs, users, hosts and URL paths appear in the same events as the seed, at depth 1 or 2, with evidence counts. Co-occurrence only: it asserts no compromise and no severity."""
        return safe_call("analyze_impact", service.analyze_impact, seed_entity=seed_entity, time_range=time_range, depth=depth)

    return mcp


# Nạp cấu hình, kết nối backend và khởi chạy MCP Server qua stdio.
def main() -> None:
    try:
        settings = Settings.from_env()
    except ConfigurationError as exc:
        logger.error("configuration_error: %s", exc)
        raise SystemExit(2) from exc
    elastic = ElasticsearchClient(settings)
    kibana = KibanaClient(settings) if settings.kibana_url else None
    service = InvestigationService(settings, elastic, kibana)
    try:
        create_server(service).run(transport="stdio")
    finally:
        elastic.close()
        if kibana:
            kibana.close()


if __name__ == "__main__":
    main()
