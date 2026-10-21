"""Small, read-only HTTP clients for Elasticsearch and Kibana."""
# Giao tiếp với Elasticsearch để truy vấn dữ liệu và với Kibana để đọc thông tin rule khi được cấu hình.
from __future__ import annotations

import httpx

from .config import Settings


class BackendError(RuntimeError):
    """An upstream request failed; details stay out of MCP responses."""


# Thiết lập API key, chứng chỉ CA và thời gian chờ cho kết nối backend.
def _client(url: str, api_key: str, ca_cert: str, timeout: float) -> httpx.Client:
    return httpx.Client(
        base_url=url,
        headers={"Authorization": f"ApiKey {api_key}", "Accept": "application/json"},
        verify=ca_cert,
        timeout=timeout,
        trust_env=False,
    )


class ElasticsearchClient:
    def __init__(self, settings: Settings, http: httpx.Client | None = None):
        self.http = http or _client(
            settings.elastic_url, settings.elastic_api_key, settings.ca_cert, settings.timeout_seconds
        )
        self.settings = settings

    # Gửi truy vấn tìm kiếm đến nguồn dữ liệu được phép và nhận phản hồi JSON.
    def search(self, index: str, body: dict) -> dict:
        if index not in (self.settings.event_index, self.settings.alert_alias):
            raise BackendError("Index ngoài phạm vi cấu hình")
        try:
            response = self.http.post(
                f"/{index}/_search",
                json=body,
            )
            response.raise_for_status()
            result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError("Không truy vấn được Elasticsearch") from exc
        # Từ chối phản hồi bị timeout hoặc có shard lỗi để tránh coi kết quả thiếu là đầy đủ.
        if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
            raise BackendError("Elasticsearch trả kết quả chưa đầy đủ")
        return result

    # Đọc khả năng tổng hợp của trường để lựa chọn trường thống kê phù hợp.
    def field_caps(self, fields: list[str]) -> dict:
        """Read field types from the configured event index before aggregating."""
        try:
            response = self.http.get(
                f"/{self.settings.event_index}/_field_caps",
                params={"fields": ",".join(fields)},
            )
            response.raise_for_status()
            return response.json().get("fields", {})
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError("Không đọc được mapping của event index") from exc

    def close(self) -> None:
        self.http.close()


class KibanaClient:
    def __init__(self, settings: Settings, http: httpx.Client | None = None):
        if not settings.kibana_url:
            raise ValueError("KIBANA_URL chưa được cấu hình")
        self.http = http or _client(
            settings.kibana_url,
            settings.kibana_api_key or settings.elastic_api_key,
            settings.ca_cert,
            settings.timeout_seconds,
        )

    # Đọc metadata của rule từ Kibana để bổ sung thông tin đối chiếu cảnh báo.
    def get_rule(self, rule_id: str) -> dict:
        try:
            response = self.http.get("/api/detection_engine/rules", params={"rule_id": rule_id})
            response.raise_for_status()
            rule = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError("Không đọc được metadata rule từ Kibana") from exc
        return {
            "rule_id": rule.get("rule_id"),
            "name": rule.get("name"),
            "type": rule.get("type"),
            "enabled": rule.get("enabled"),
            "interval": rule.get("interval"),
            "from": rule.get("from"),
            "threshold": rule.get("threshold"),
        }

    def close(self) -> None:
        self.http.close()
