"""Genera docs/reporte-ejemplo.html escaneando un sitio SIMULADO con fallas a propósito.

Sirve para la captura del README sin usar datos de ningún sitio real:
    python docs/demo.py
"""

import asyncio
from pathlib import Path

import httpx

from escaner import reportes
from escaner.alcance import Alcance
from escaner.motor import escanear
from escaner.revisiones import ArchivosExpuestos, Cabeceras, Cookies, Cors, Divulgacion
from escaner.revisiones.formularios import Formularios

PAGINA = ('<html><head><title>Tienda Demo</title><script src="http://cdn.demo.test/jquery-1.12.4.min.js"></script></head>'
          '<body><a href="/contacto">Contacto</a><a href="/salir">Salir</a></body></html>')
CONTACTO = ('<html><body><form method="post" action="/enviar"><input name="nombre"><input name="email">'
            '<textarea name="mensaje"></textarea></form>'
            '<form method="get" action="/entrar"><input name="usuario"><input name="clave" type="password"></form></body></html>')


def responder(req: httpx.Request) -> httpx.Response:
    html = {"content-type": "text/html", "server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"}
    if req.url.path == "/":
        cab = dict(html)
        if req.headers.get("origin"):
            cab |= {"access-control-allow-origin": req.headers["origin"], "access-control-allow-credentials": "true"}
        return httpx.Response(200, text=PAGINA, headers=[*cab.items(), ("set-cookie", "PHPSESSID=abc123; path=/")])
    if req.url.path == "/contacto":
        return httpx.Response(200, text=CONTACTO, headers=html)
    if req.url.path == "/.env":
        return httpx.Response(200, text="APP_KEY=base64:xxxx\nDB_PASSWORD=secreto\n")
    if req.url.path == "/.git/HEAD":
        return httpx.Response(200, text="ref: refs/heads/main\n")
    return httpx.Response(404, text="no existe")


async def main():
    url = "https://tienda.demo.test/"
    r = await escanear(url, Alcance.desde_url(url),
                       [Cabeceras(), Cookies(), Cors(), Divulgacion(), Formularios(), ArchivosExpuestos()],
                       por_segundo=0, max_paginas=10, transporte=httpx.MockTransport(responder))
    destino = Path(__file__).parent / "reporte-ejemplo.html"
    reportes.html(r, destino)
    print(destino, len(r.hallazgos), "hallazgos")


asyncio.run(main())
