"""Rastreador y revisiones que usan todas las páginas, contra un sitio simulado."""

import httpx

from escaner.alcance import Alcance
from escaner.cliente import Cliente
from escaner.modelos import Severidad
from escaner.motor import escanear
from escaner.rastreador import Rastreador
from escaner.revisiones import Cookies, Divulgacion
from escaner.revisiones.formularios import Formularios


def html(cuerpo: str, **cabeceras) -> httpx.Response:
    return httpx.Response(200, text=f"<html><body>{cuerpo}</body></html>", headers={"content-type": "text/html", **cabeceras})


SITIO = {
    "/": html('<a href="/productos">p</a> <a href="/contacto">c</a> <a href="https://externo.test/x">e</a>'
              '<a href="/logout">salir</a> <a href="/eliminar?id=3">borrar</a> <a href="/logo.png">img</a>'
              '<a href="/productos?page=1">1</a> <a href="/productos?page=2">2</a> <a href="#arriba">a</a>'),
    "/productos": html('<a href="/">inicio</a>'),
    "/contacto": html('<form method="post" action="/enviar"><input name="nombre"><input name="email" type="email">'
                      '<textarea name="mensaje"></textarea></form>'
                      '<form action="/entrar"><input name="usuario"><input name="clave" type="password"></form>'
                      '<form method="post" action="/buscar"><input type="hidden" name="csrf_token" value="x"><input name="q"></form>'
                      '<a href="/nivel2">más</a>',
                      **{"set-cookie": "sesion=abc; Path=/"}),
    "/nivel2": html('<a href="/nivel3">más</a>'
                    # Login manejado por JavaScript (sin method ni action), como en las apps React o Flutter.
                    '<form><input name="correo"><input name="pin" type="password"></form>'),
    "/nivel3": html('<a href="/nivel4">más</a>'),
    "/nivel4": html("demasiado lejos"),
    "/oculta": html('<script src="http://cdn.test/app.js"></script>'),
    "/sitemap.xml": httpx.Response(200, text="<urlset><url><loc>https://sitio.test/oculta</loc></url></urlset>",
                                   headers={"content-type": "application/xml"}),
}


def transporte(pedidas: list | None = None):
    def responder(req: httpx.Request) -> httpx.Response:
        if pedidas is not None:
            pedidas.append(str(req.url))
        if req.url.host != "sitio.test":
            return httpx.Response(200, text="no debería llegar aquí")
        r = SITIO.get(req.url.path)
        return r if r is not None else httpx.Response(404, text="no existe")
    return httpx.MockTransport(responder)


async def rastrear(max_paginas=30, pedidas=None):
    async with Cliente(Alcance(["sitio.test"]), por_segundo=0, transporte=transporte(pedidas)) as c:
        inicio = await c.get("https://sitio.test/")
        return await Rastreador(c, max_paginas=max_paginas, max_profundidad=3).rastrear(inicio)


def rutas(urls):
    return {httpx.URL(u).raw_path.decode() for u in urls}


async def test_recorre_el_sitio_sin_salirse_ni_abrir_enlaces_peligrosos():
    pedidas: list[str] = []
    mapa, paginas = await rastrear(pedidas=pedidas)
    vistas = rutas(mapa.paginas)
    assert {"/", "/productos", "/contacto", "/nivel2", "/nivel3", "/oculta"} <= vistas
    assert "/nivel4" not in vistas                       # más allá de la profundidad
    assert not any("externo.test" in u for u in pedidas)  # nunca sale del dominio
    assert not any("logout" in u or "eliminar" in u or "logo.png" in u for u in pedidas)
    assert rutas(mapa.omitidas) == {"/logout", "/eliminar?id=3"}
    assert len([v for v in vistas if v.startswith("/productos?")]) == 1  # page=1 y page=2 cuentan como una
    assert mapa.parametros["https://sitio.test/productos"] == ["page"]
    assert len(mapa.formularios) == 4
    assert len(paginas) == len(mapa.paginas)


async def test_respeta_el_maximo_de_paginas():
    mapa, paginas = await rastrear(max_paginas=3)
    assert len(paginas) == 3


async def test_revisiones_usan_todas_las_paginas():
    r = await escanear("https://sitio.test/", Alcance(["sitio.test"]), [Cookies(), Divulgacion(), Formularios()],
                       por_segundo=0, max_paginas=30, transporte=transporte())
    assert r.mapa and len(r.mapa.paginas) >= 6
    por_titulo = {h.titulo: h for h in r.hallazgos}

    # La cookie aparece en /contacto, no en la portada.
    assert any("sesion" in t for t in por_titulo)
    # El contenido mixto está en /oculta, que solo aparece en sitemap.xml.
    mixto = por_titulo["Contenido mixto (recursos por HTTP en una página HTTPS)"]
    assert mixto.url.endswith("/oculta")
    # Formularios: login por GET (alta) y contacto sin token (media); el buscador con csrf_token no se reporta.
    assert por_titulo["Formulario envía la contraseña en la URL (method=GET)"].severidad == Severidad.ALTA
    # El login sin method ni action lo maneja JavaScript: no es Alta, solo Baja.
    js = por_titulo['Formulario de contraseña sin method="post"']
    assert js.severidad == Severidad.BAJA and js.url.endswith("/nivel2")
    sin_token = [h for h in r.hallazgos if h.titulo == "Formulario POST sin token anti-CSRF"]
    assert len(sin_token) == 1 and "/enviar" in sin_token[0].evidencia
