"""Control de alcance: el escáner nunca envía peticiones fuera de los dominios autorizados."""

from collections.abc import Iterable
from urllib.parse import urlsplit


class FueraDeAlcance(Exception):
    """Se intentó tocar una URL que no está autorizada."""


class Alcance:
    """Lista de dominios permitidos. Acepta nombres exactos ("ejemplo.com")
    o comodines de subdominio ("*.ejemplo.com", que no incluye "ejemplo.com")."""

    def __init__(self, dominios: Iterable[str]):
        self.exactos: set[str] = set()
        self.comodines: set[str] = set()
        for d in dominios:
            d = d.strip().lower().rstrip(".")
            if not d:
                continue
            if d.startswith("*."):
                self.comodines.add(d[2:])
            else:
                self.exactos.add(d)
        if not self.exactos and not self.comodines:
            raise ValueError("El alcance no puede estar vacío")

    @classmethod
    def desde_url(cls, url: str, extra: Iterable[str] = ()) -> "Alcance":
        host = urlsplit(url).hostname
        if not host:
            raise ValueError(f"URL sin dominio: {url}")
        return cls([host, *extra])

    def permite(self, url: str) -> bool:
        partes = urlsplit(url)
        if partes.scheme not in ("http", "https"):
            return False
        host = (partes.hostname or "").lower().rstrip(".")
        if host in self.exactos:
            return True
        return any(host.endswith("." + c) for c in self.comodines)

    def permite_host(self, host: str) -> bool:
        return self.permite(f"https://{host}/")

    def verificar(self, url: str) -> None:
        if not self.permite(url):
            raise FueraDeAlcance(f"Fuera del alcance autorizado: {url}")

    def __str__(self) -> str:
        return ", ".join(sorted(self.exactos) + sorted("*." + c for c in self.comodines))
