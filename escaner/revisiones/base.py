from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlsplit

from escaner.cliente import Cliente, Respuesta
from escaner.modelos import Hallazgo


@dataclass
class Sitio:
    """Lo que ya se sabe del objetivo antes de correr las revisiones."""

    url_pedida: str
    inicio: Respuesta  # respuesta de la página principal, después de redirecciones

    @property
    def url(self) -> str:
        return self.inicio.url

    @property
    def raiz(self) -> str:
        p = urlsplit(self.inicio.url)
        return f"{p.scheme}://{p.netloc}"

    @property
    def host(self) -> str:
        return urlsplit(self.inicio.url).hostname or ""

    @property
    def es_https(self) -> bool:
        return self.inicio.url.startswith("https://")


class Revision(ABC):
    id: str
    nombre: str
    tipo: str = "pasiva"  # "pasiva": solo observa. "activa": envía pruebas de ataque.

    @abstractmethod
    async def ejecutar(self, sitio: Sitio, cliente: Cliente) -> list[Hallazgo]: ...
