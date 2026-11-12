"""Pruebas con un servidor simulado (httpx.MockTransport): no se toca ningún sitio real."""

import httpx
import pytest

from escaner import reportes
from escaner.alcance import Alcance, FueraDeAlcance
from escaner.cliente import Cliente
from escaner.modelos import Severidad
from escaner.motor import escanear
from escaner.revisiones import ArchivosExpuestos, Cabeceras, Cookies, Cors, Divulgacion

PAGINA = b"<!doctype html><html><head><title>Inicio</title></head><body>Hola</body></html>"
CABECERAS_BUENAS = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def servidor(rutas: dict[str, httpx.Response] | None = None, por_defecto=None):
    """Simula un sitio. Las rutas que no están responden con `por_defecto` (o 404)."""
    rutas = rutas or {}

    def responder(req: httpx.Request) -> httpx.Response:
        if req.url.path in rutas:
            r = rutas[req.url.path]
            return r(req) if callable(r) else r
        return por_defecto(req) if por_defecto else httpx.Response(404, text="no existe")

    return httpx.MockTransport(responder)


async def correr(revisiones, transporte, url="https://sitio.test/"):
    return await escanear(url, Alcance.desde_url(url), revisiones, por_segundo=0, transporte=transporte)


def titulos(resultado):
    return [h.titulo for h in resultado.hallazgos]


# ---------------------------------------------------------------- alcance
def test_alcance_exacto_y_comodin():
    a = Alcance(["sitio.test", "*.api.test"])
    assert a.permite("https://sitio.test/x")
    assert not a.permite("https://otro.test/")
    assert not a.permite("https://sub.sitio.test/")  # subdominios solo con comodín
    assert a.permite("https://v1.api.test/")
    assert not a.permite("https://api.test/")
    assert not a.permite("ftp://sitio.test/")
    with pytest.raises(FueraDeAlcance):
        a.verificar("https://evil.test/")


async def test_no_sigue_redirecciones_fuera_del_alcance():
    t = servidor({"/": httpx.Response(302, headers={"location": "https://otro.test/robar"})})
    async with Cliente(Alcance(["sitio.test"]), por_segundo=0, transporte=t) as c:
        with pytest.raises(FueraDeAlcance):
            await c.get("https://sitio.test/")


# ---------------------------------------------------------------- cabeceras
async def test_cabeceras_faltantes():
    t = servidor({"/": httpx.Response(200, content=PAGINA, headers={"content-type": "text/html"})})
    r = await correr([Cabeceras()], t)
    ts = titulos(r)
    assert "Falta Strict-Transport-Security (HSTS)" in ts
    assert "Falta Content-Security-Policy (CSP)" in ts
    assert any("iframe" in x for x in ts)


async def test_cabeceras_completas_sin_hallazgos():
    t = servidor({"/": httpx.Response(200, content=PAGINA, headers=CABECERAS_BUENAS)})
    r = await correr([Cabeceras()], t)
    assert r.hallazgos == []


# ---------------------------------------------------------------- cookies
async def test_cookie_de_sesion_insegura_y_valor_oculto():
    t = servidor({"/": httpx.Response(200, content=PAGINA, headers=[
        ("content-type", "text/html"), ("set-cookie", "sessionid=SECRETO123; Path=/"),
        ("set-cookie", "tema=oscuro; Secure; HttpOnly; SameSite=Lax")])})
    r = await correr([Cookies()], t)
    sesion = [h for h in r.hallazgos if "sessionid" in h.titulo]
    assert {h.severidad for h in sesion} >= {Severidad.MEDIA}
    assert not [h for h in r.hallazgos if "tema" in h.titulo]
    assert all("SECRETO123" not in (h.evidencia or "") for h in r.hallazgos)


# ---------------------------------------------------------------- archivos
async def test_app_de_una_pagina_no_da_falsos_positivos():
    # Responde 200 con el mismo HTML a cualquier ruta, como Firebase Hosting con rewrites.
    t = servidor(por_defecto=lambda req: httpx.Response(200, content=PAGINA, headers={"content-type": "text/html"}))
    r = await correr([ArchivosExpuestos()], t)
    assert r.hallazgos == []


async def test_git_y_env_expuestos():
    t = servidor({
        "/": httpx.Response(200, content=PAGINA),
        "/.git/HEAD": httpx.Response(200, text="ref: refs/heads/main\n"),
        "/.env": httpx.Response(200, text="DB_HOST=localhost\nDB_PASSWORD=supersecreta\n"),
    })
    r = await correr([ArchivosExpuestos()], t)
    assert {h.titulo for h in r.hallazgos} == {"Repositorio Git expuesto", "Archivo .env expuesto"}
    assert all(h.severidad == Severidad.CRITICA for h in r.hallazgos)
    env = next(h for h in r.hallazgos if ".env" in h.titulo)
    assert "supersecreta" not in env.evidencia


# ---------------------------------------------------------------- cors
async def test_cors_refleja_origen_con_credenciales():
    def responder(req):
        origen = req.headers.get("origin")
        cab = {"content-type": "text/html"}
        if origen:
            cab |= {"access-control-allow-origin": origen, "access-control-allow-credentials": "true"}
        return httpx.Response(200, content=PAGINA, headers=cab)

    r = await correr([Cors()], servidor({"/": responder}))
    assert r.hallazgos and all(h.severidad == Severidad.ALTA for h in r.hallazgos)


async def test_cors_sin_reflejo():
    t = servidor({"/": httpx.Response(200, content=PAGINA, headers={"access-control-allow-origin": "https://sitio.test"})})
    r = await correr([Cors()], t)
    assert r.hallazgos == []


# ---------------------------------------------------------------- divulgación
async def test_divulgacion_version_jquery_y_contenido_mixto():
    html = (b'<html><head><script src="http://cdn.test/jquery-1.12.4.min.js"></script></head>'
            b'<body><form action="/entrar"><input type="password"></form></body></html>')
    t = servidor({"/": httpx.Response(200, content=html, headers={"content-type": "text/html", "server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"})})
    r = await correr([Divulgacion()], t)
    ts = " | ".join(titulos(r))
    assert "server" in ts and "x-powered-by" in ts
    assert "jQuery 1.12.4" in ts
    assert "Contenido mixto" in ts


# ---------------------------------------------------------------- de punta a punta
async def test_escaneo_completo_y_reporte(tmp_path):
    t = servidor({"/": httpx.Response(200, content=PAGINA, headers={"content-type": "text/html"}),
                  "/.env": httpx.Response(200, text="A=1\nB=2\n")})
    r = await correr([Cabeceras(), Cookies(), Cors(), Divulgacion(), ArchivosExpuestos()], t)
    assert r.errores == []
    assert r.hallazgos[0].severidad == Severidad.CRITICA  # ordenados de peor a menor
    assert r.peticiones > 10
    destino = tmp_path / "reporte.html"
    reportes.html(r, destino)
    contenido = destino.read_text(encoding="utf-8")
    assert "Archivo .env expuesto" in contenido and "Crítica" in contenido
