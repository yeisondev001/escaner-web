"""Cliente HTTP del escáner: respeta el alcance (también en redirecciones),
limita la velocidad y corta las respuestas demasiado grandes."""

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from escaner import __version__
from escaner.alcance import Alcance

AGENTE = f"escaner-web/{__version__} (escaneo autorizado)"
MAX_REDIRECCIONES = 5


@dataclass
class Respuesta:
    url: str
    estado: int
    cabeceras: httpx.Headers
    cuerpo: bytes
    redirecciones: list[str] = field(default_factory=list)  # URLs anteriores, en orden

    @property
    def texto(self) -> str:
        return self.cuerpo.decode("utf-8", errors="replace")

    @property
    def es_html(self) -> bool:
        return "html" in self.cabeceras.get("content-type", "").lower()

    @property
    def set_cookies(self) -> list[str]:
        return self.cabeceras.get_list("set-cookie")


class Cliente:
    def __init__(
        self,
        alcance: Alcance,
        por_segundo: float = 5.0,
        tiempo_max: float = 15.0,
        max_bytes: int = 2_000_000,
        transporte: httpx.AsyncBaseTransport | None = None,
    ):
        self.alcance = alcance
        self.max_bytes = max_bytes
        self.peticiones = 0
        self._intervalo = 1.0 / por_segundo if por_segundo > 0 else 0.0
        self._ultimo = 0.0
        self._turno = asyncio.Lock()
        # verify=False: un certificado malo no debe impedir revisar lo demás;
        # la revisión TLS es la que reporta el certificado.
        self._http = httpx.AsyncClient(
            follow_redirects=False,
            timeout=tiempo_max,
            verify=False,
            headers={"User-Agent": AGENTE},
            transport=transporte,
        )

    async def __aenter__(self) -> "Cliente":
        return self

    async def __aexit__(self, *_) -> None:
        await self._http.aclose()

    async def _esperar_turno(self) -> None:
        async with self._turno:
            espera = self._ultimo + self._intervalo - time.monotonic()
            if espera > 0:
                await asyncio.sleep(espera)
            self._ultimo = time.monotonic()

    async def get(self, url: str, *, seguir: bool = True, cabeceras: dict[str, str] | None = None,
                  max_bytes: int | None = None) -> Respuesta:
        limite = max_bytes or self.max_bytes
        anteriores: list[str] = []
        for _ in range(MAX_REDIRECCIONES + 1):
            self.alcance.verificar(url)
            await self._esperar_turno()
            async with self._http.stream("GET", url, headers=cabeceras) as r:
                cuerpo = bytearray()
                async for trozo in r.aiter_bytes():
                    cuerpo += trozo
                    if len(cuerpo) >= limite:
                        break
                self.peticiones += 1
                destino = r.headers.get("location")
                if seguir and r.is_redirect and destino:
                    anteriores.append(url)
                    url = urljoin(url, destino)
                    continue
                return Respuesta(str(r.url), r.status_code, r.headers, bytes(cuerpo[:limite]), anteriores)
        raise httpx.TooManyRedirects(f"Más de {MAX_REDIRECCIONES} redirecciones desde {anteriores[0]}")
