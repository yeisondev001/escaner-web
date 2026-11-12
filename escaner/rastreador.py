"""Recorre el sitio para descubrir páginas, formularios y parámetros.

Solo hace GET, no envía formularios y no abre enlaces que parezcan de cerrar sesión
o de borrar algo (en sitios mal hechos, un GET a /eliminar?id=3 borra de verdad)."""

import re
from collections import deque
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from selectolax.lexbor import LexborHTMLParser

from escaner.alcance import FueraDeAlcance
from escaner.cliente import Cliente, Respuesta
from escaner.modelos import Campo, Formulario, Mapa

NO_HTML = re.compile(r"\.(pdf|jpe?g|png|gif|svg|webp|ico|bmp|css|js|mjs|map|zip|rar|7z|gz|tar|mp4|webm|mp3|wav|"
                     r"woff2?|ttf|otf|eot|json|xml|txt|csv|apk|ipa|exe|msi|dmg|docx?|xlsx?|pptx?)$", re.I)
PELIGROSA = re.compile(r"log-?out|sign-?out|salir|cerrar-?sesion|delete|eliminar|borrar|remove|destroy|unsubscribe|darse-?de-?baja", re.I)
MAX_SITEMAP = 200


def _limpiar(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def _clave(url: str) -> tuple[str, frozenset[str]]:
    """Dos URLs con la misma ruta y los mismos nombres de parámetros cuentan como la misma página."""
    p = urlsplit(url)
    return p.path or "/", frozenset(k for k, _ in parse_qsl(p.query, keep_blank_values=True))


class Rastreador:
    def __init__(self, cliente: Cliente, max_paginas: int = 30, max_profundidad: int = 3):
        self.cliente = cliente
        self.max_paginas = max_paginas
        self.max_profundidad = max_profundidad

    async def rastrear(self, inicio: Respuesta) -> tuple[Mapa, list[Respuesta]]:
        self.host = urlsplit(inicio.url).hostname
        self.mapa = Mapa()
        self._vistas: set[tuple] = {_clave(inicio.url)}
        self._formularios: set[tuple] = set()
        self._cola: deque[tuple[str, int]] = deque()
        paginas = [inicio]
        self._registrar(inicio, 0)
        await self._semillas(inicio)

        while self._cola and len(paginas) < self.max_paginas:
            url, prof = self._cola.popleft()
            try:
                r = await self.cliente.get(url)
            except FueraDeAlcance:
                continue  # redirigió a otro dominio
            except Exception:
                continue  # página caída o lenta: se sigue con las demás
            if urlsplit(r.url).hostname != self.host or r.estado >= 400:
                continue
            paginas.append(r)
            self._registrar(r, prof)
        return self.mapa, paginas

    async def _semillas(self, inicio: Respuesta) -> None:
        """URLs de sitemap.xml (y de los sitemaps que indique robots.txt)."""
        raiz = f"{urlsplit(inicio.url).scheme}://{urlsplit(inicio.url).netloc}"
        sitemaps = [raiz + "/sitemap.xml"]
        try:
            robots = await self.cliente.get(raiz + "/robots.txt")
            if robots.estado == 200 and not robots.es_html:
                sitemaps += re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots.texto)
        except Exception:
            pass
        for s in dict.fromkeys(sitemaps):
            if urlsplit(s).hostname != self.host:
                continue
            try:
                r = await self.cliente.get(s)
            except Exception:
                continue
            if r.estado == 200 and "<urlset" in r.texto[:2000]:
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.texto)[:MAX_SITEMAP]:
                    self._encolar(loc, 1)

    def _registrar(self, r: Respuesta, prof: int) -> None:
        self.mapa.paginas.append(r.url)
        self._parametros(r.url)
        if not r.es_html:
            return
        html = LexborHTMLParser(r.texto)
        if prof < self.max_profundidad:
            for n in html.css("a[href], area[href], iframe[src], frame[src]"):
                self._encolar(urljoin(r.url, n.attributes.get("href") or n.attributes.get("src") or ""), prof + 1)
        for f in html.css("form"):
            self._formulario(r.url, f)

    def _encolar(self, url: str, prof: int) -> None:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or p.hostname != self.host or NO_HTML.search(p.path):
            return
        url = _limpiar(url)
        if PELIGROSA.search(p.path + "?" + p.query):
            if url not in self.mapa.omitidas:
                self.mapa.omitidas.append(url)
            return
        clave = _clave(url)
        if clave in self._vistas or len(self._vistas) >= self.max_paginas * 3:
            return
        self._vistas.add(clave)
        self._parametros(url)
        self._cola.append((url, prof))

    def _parametros(self, url: str) -> None:
        p = urlsplit(url)
        nombres = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        if nombres:
            base = urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))
            actuales = self.mapa.parametros.setdefault(base, [])
            actuales.extend(n for n in nombres if n not in actuales)

    def _formulario(self, pagina: str, f) -> None:
        campos = []
        for c in f.css("input[name], select[name], textarea[name], button[name]"):
            tipo = c.tag if c.tag != "input" else (c.attributes.get("type") or "text").lower()
            campos.append(Campo(nombre=c.attributes["name"], tipo=tipo))
        metodo = (f.attributes.get("method") or "get").upper()
        accion = _limpiar(urljoin(pagina, f.attributes.get("action") or pagina))
        clave = (accion, metodo, tuple(sorted(c.nombre for c in campos)))
        if clave in self._formularios:
            return
        self._formularios.add(clave)
        self.mapa.formularios.append(Formulario(
            pagina=pagina, accion=accion, metodo=metodo, campos=campos,
            metodo_declarado="method" in f.attributes, accion_declarada="action" in f.attributes))
