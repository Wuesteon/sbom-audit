"""Host mode: read-only audits of servers over ssh (`hosts check`, `hosts.json`, baselines)."""
from .checker import check
from .store import HOSTS_JSON, HOSTS_MD, read

__all__ = ["check", "read", "HOSTS_JSON", "HOSTS_MD"]
