"""Revisión de Firebase contra un proyecto simulado (no se toca Google)."""

import json

import httpx

from escaner.alcance import Alcance
from escaner.modelos import Severidad
from escaner.motor import escanear
from escaner.revisiones import HOSTS_FIREBASE
from escaner.revisiones.firebase import Firebase

CONFIG = {"apiKey": "AIza" + "x" * 35, "projectId": "demo-tienda", "storageBucket": "demo-tienda.appspot.com",
          "databaseURL": "https://demo-tienda-default-rtdb.firebaseio.com"}
HTML = b'<html><head><script src="/main.js"></script></head><body></body></html>'
JS = b'const db=getFirestore(app); getDocs(collection(db, "pedidos")); doc(collection(db,"productos"),"x");'
NEGADO = httpx.Response(403, json={"error": {"status": "PERMISSION_DENIED"}})


def proyecto(abierto: bool):
    def responder(req: httpx.Request) -> httpx.Response:
        host, ruta = req.url.host, req.url.path
        if host == "sitio.test":
            return {"/": httpx.Response(200, content=HTML, headers={"content-type": "text/html"}),
                    "/main.js": httpx.Response(200, content=JS),
                    "/__/firebase/init.json": httpx.Response(200, json=CONFIG)}.get(ruta, httpx.Response(404))
        if not abierto:
            return httpx.Response(401, json={"error": "Permission denied"}) if "firebaseio" in host else NEGADO
        if host.endswith("firebaseio.com"):
            return httpx.Response(200, json={"usuarios": True, "pedidos": True})
        if host == "firestore.googleapis.com":
            col = ruta.rsplit("/", 1)[-1]
            if col in ("pedidos", "productos"):
                return httpx.Response(200, json={"documents": [{"name": f"x/{col}/1", "fields": {
                    "cliente": {"stringValue": "Juan Perez"}, "total": {"integerValue": "500"}}}]})
            return httpx.Response(200, json={})
        if host == "firebasestorage.googleapis.com":
            return httpx.Response(200, json={"items": [{"name": "facturas/juan.pdf"}]})
        return httpx.Response(404)
    return httpx.MockTransport(responder)


async def correr(transporte, con_firebase=True):
    alcance = Alcance(["sitio.test", *(HOSTS_FIREBASE if con_firebase else [])])
    return await escanear("https://sitio.test/", alcance, [Firebase()], por_segundo=0, transporte=transporte)


async def test_proyecto_protegido_solo_informa():
    r = await correr(proyecto(abierto=False))
    assert r.errores == []
    assert [h.severidad for h in r.hallazgos] == [Severidad.INFO]
    assert "demo-tienda" in r.hallazgos[0].titulo


async def test_proyecto_abierto():
    r = await correr(proyecto(abierto=True))
    por_titulo = {h.titulo: h for h in r.hallazgos}
    assert por_titulo["Realtime Database legible por cualquiera"].severidad == Severidad.CRITICA
    assert por_titulo["Firestore: la colección 'pedidos' se puede leer sin iniciar sesión"].severidad == Severidad.CRITICA
    assert por_titulo["Firestore: la colección 'productos' se puede leer sin iniciar sesión"].severidad == Severidad.MEDIA
    assert por_titulo["Firebase Storage permite listar los archivos sin sesión"].severidad == Severidad.ALTA
    # El reporte no copia datos: ni valores de Firestore ni nombres de archivos.
    todo = json.dumps([h.model_dump(mode="json") for h in r.hallazgos])
    assert "Juan Perez" not in todo and "juan.pdf" not in todo
    assert "cliente, total" in por_titulo["Firestore: la colección 'pedidos' se puede leer sin iniciar sesión"].evidencia


async def test_sin_permiso_de_firebase_no_toca_google():
    tocados = []

    def responder(req):
        tocados.append(req.url.host)
        return proyecto(abierto=True).handle_request(req)

    r = await correr(httpx.MockTransport(responder), con_firebase=False)
    assert set(tocados) == {"sitio.test"}
    assert any("omitida" in h.titulo for h in r.hallazgos)


async def test_sitio_sin_firebase():
    t = httpx.MockTransport(lambda req: httpx.Response(200, content=b"<html></html>", headers={"content-type": "text/html"})
                            if req.url.path == "/" else httpx.Response(404))
    r = await correr(t)
    assert r.hallazgos == []
