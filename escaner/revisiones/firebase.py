"""Revisa si el proyecto de Firebase del sitio deja leer datos sin iniciar sesión.

Solo hace lecturas (GET), nunca escribe ni crea usuarios. Necesita que el alcance
autorice los servicios de Google (la CLI los agrega con --firebase)."""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import quote, urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser

from escaner.alcance import FueraDeAlcance
from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

# Hosts que la CLI agrega al alcance cuando se usa --firebase.
HOSTS_FIREBASE = ["firestore.googleapis.com", "firebasestorage.googleapis.com", "*.firebaseio.com", "*.firebasedatabase.app"]

REF_REGLAS = "https://firebase.google.com/docs/rules/insecure-rules?hl=es-419"
SENSIBLES = re.compile(r"user|usuario|client|customer|order|pedido|pago|payment|factura|invoice|token|admin|mensaje|message|chat|perfil|profile|empleado|employee", re.I)
COMUNES = ["users", "usuarios", "clientes", "customers", "orders", "pedidos", "products", "productos",
           "messages", "mensajes", "chats", "config", "settings", "admins", "pagos", "facturas"]
EN_JS = {
    "apiKey": re.compile(r"""apiKey["']?\s*[:=]\s*["'](AIza[0-9A-Za-z_-]{35})["']"""),
    "projectId": re.compile(r"""projectId["']?\s*[:=]\s*["']([a-z0-9-]{4,40})["']"""),
    "databaseURL": re.compile(r"""databaseURL["']?\s*[:=]\s*["'](https://[^"']+)["']"""),
    "storageBucket": re.compile(r"""storageBucket["']?\s*[:=]\s*["']([a-z0-9._-]+)["']"""),
}
# .collection("x"), collection(db, "x") y lo que deja Flutter Web compilado: collection$1$x(a, "x")
COLECCION = re.compile(r"""collection[\w$]*\([^()"']{0,40}?["']([A-Za-z0-9_-]{1,60})["']""")
MAX_JS = 8_000_000
MAX_COLECCIONES = 25


@dataclass
class Config:
    projectId: str | None = None
    databaseURL: str | None = None
    storageBucket: str | None = None
    apiKey: str | None = None
    colecciones: set[str] = field(default_factory=set)
    origen: str = ""


class Firebase(Revision):
    id = "firebase"
    nombre = "Firebase: datos legibles sin iniciar sesión"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        config = await _detectar(sitio, cliente)
        if not config.projectId:
            return []
        h = [Hallazgo(
            revision=self.id, severidad=Severidad.INFO, url=config.origen,
            titulo=f"Proyecto de Firebase detectado: {config.projectId}",
            descripcion="La configuración web de Firebase es pública por diseño; la seguridad depende de las reglas de Firestore, Realtime Database y Storage.",
            recomendacion="Restringir la API key a los dominios del sitio en Google Cloud Console y mantener reglas que exijan sesión.",
            evidencia=f"projectId: {config.projectId}\nstorageBucket: {config.storageBucket or '-'}\ndatabaseURL: {config.databaseURL or '-'}",
            referencias=["https://firebase.google.com/docs/projects/api-keys?hl=es-419"])]

        try:
            h += await _realtime(config, cliente, self.id)
            h += await _firestore(config, cliente, self.id)
            h += await _storage(config, cliente, self.id)
        except FueraDeAlcance:
            h.append(Hallazgo(
                revision=self.id, severidad=Severidad.INFO, url=sitio.url, titulo="Revisión de Firebase omitida",
                descripcion="Los servicios de Google no están en el alcance autorizado.",
                recomendacion="Volver a escanear con --firebase si el proyecto de Firebase también es tuyo."))
        return h


async def _detectar(sitio: Sitio, cliente) -> Config:
    c = Config()
    # Firebase Hosting publica la configuración del proyecto en esta URL reservada.
    try:
        r = await cliente.get(sitio.raiz + "/__/firebase/init.json", seguir=False)
        if r.estado == 200 and r.texto.lstrip().startswith("{"):
            datos = json.loads(r.texto)
            c.projectId, c.databaseURL = datos.get("projectId"), datos.get("databaseURL")
            c.storageBucket, c.apiKey = datos.get("storageBucket"), datos.get("apiKey")
            c.origen = r.url
    except (ValueError, OSError):
        pass

    # Buscar también en el HTML y en los scripts del mismo sitio (configuración y nombres de colecciones).
    textos = [sitio.inicio.texto]
    if sitio.inicio.es_html:
        html = LexborHTMLParser(sitio.inicio.texto)
        for n in html.css("script[src]")[:8]:
            url = urljoin(sitio.url, n.attributes.get("src") or "")
            if urlsplit(url).hostname == sitio.host:
                try:
                    textos.append((await cliente.get(url, max_bytes=MAX_JS)).texto)
                except Exception:
                    continue
    for texto in textos:
        for clave, patron in EN_JS.items():
            if not getattr(c, clave) and (m := patron.search(texto)):
                setattr(c, clave, m.group(1))
                c.origen = c.origen or sitio.url
        c.colecciones.update(m.group(1) for m in COLECCION.finditer(texto))
    return c


async def _realtime(c: Config, cliente, rev: str) -> list[Hallazgo]:
    candidatas = [c.databaseURL] if c.databaseURL else [
        f"https://{c.projectId}-default-rtdb.firebaseio.com", f"https://{c.projectId}.firebaseio.com"]
    for base in candidatas:
        url = base.rstrip("/") + "/.json?shallow=true"
        r = await cliente.get(url, seguir=False)
        if r.estado != 200:
            continue  # 401 = protegida, 404 = no existe
        try:
            datos = json.loads(r.texto)
        except ValueError:
            continue
        if datos is None:
            return [Hallazgo(
                revision=rev, severidad=Severidad.MEDIA, url=url, titulo="Realtime Database con lectura pública (vacía por ahora)",
                descripcion="Las reglas permiten leer sin iniciar sesión. Hoy no tiene datos, pero cualquier dato que se guarde quedará expuesto.",
                recomendacion='Cambiar las reglas a ".read": "auth != null" o más restrictivas.', referencias=[REF_REGLAS])]
        claves = len(datos) if isinstance(datos, dict) else 1
        return [Hallazgo(
            revision=rev, severidad=Severidad.CRITICA, url=url, titulo="Realtime Database legible por cualquiera",
            descripcion="Cualquier persona puede descargar toda la base de datos sin iniciar sesión.",
            recomendacion='Cambiar las reglas a ".read": "auth != null" (o por usuario) y revisar qué datos se expusieron.',
            evidencia=f"Se leyó la raíz sin sesión: {claves} nodo(s) de primer nivel (contenido no copiado).",
            referencias=[REF_REGLAS])]
    return []


async def _firestore(c: Config, cliente, rev: str) -> list[Hallazgo]:
    base = f"https://firestore.googleapis.com/v1/projects/{c.projectId}/databases/(default)/documents"
    nombres = sorted(c.colecciones)[:MAX_COLECCIONES] + [n for n in COMUNES if n not in c.colecciones]
    h = []
    for col in nombres:
        url = f"{base}/{quote(col)}?pageSize=1"
        r = await cliente.get(url, seguir=False)
        if r.estado == 404 and "database" in r.texto.lower() and "not exist" in r.texto.lower():
            return h  # el proyecto no usa Firestore
        if r.estado != 200:
            continue  # 403 = las reglas lo protegen
        try:
            docs = json.loads(r.texto).get("documents") or []
        except ValueError:
            continue
        if not docs:
            continue  # colección vacía o inexistente: no se puede confirmar nada
        campos = ", ".join(sorted(docs[0].get("fields", {}))[:12]) or "(sin campos)"
        sensible = bool(SENSIBLES.search(col))
        h.append(Hallazgo(
            revision=rev, url=url, severidad=Severidad.CRITICA if sensible else Severidad.MEDIA,
            titulo=f"Firestore: la colección '{col}' se puede leer sin iniciar sesión",
            descripcion=("Por el nombre, parece tener datos privados y cualquiera puede descargarlos."
                         if sensible else
                         "Cualquiera puede leer esta colección. Puede ser intencional (por ejemplo, un catálogo público); confirmar que no tenga datos privados."),
            recomendacion="Ajustar las reglas de Firestore para exigir sesión (request.auth != null) o permitir solo los campos públicos.",
            evidencia=f"Se leyó 1 documento sin sesión. Campos: {campos} (valores no copiados).",
            referencias=[REF_REGLAS]))
    return h


async def _storage(c: Config, cliente, rev: str) -> list[Hallazgo]:
    buckets = [c.storageBucket] if c.storageBucket else [f"{c.projectId}.appspot.com", f"{c.projectId}.firebasestorage.app"]
    for b in buckets:
        url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=5"
        r = await cliente.get(url, seguir=False)
        if r.estado != 200:
            continue
        try:
            items = json.loads(r.texto).get("items") or []
        except ValueError:
            continue
        return [Hallazgo(
            revision=rev, url=url, severidad=Severidad.ALTA, titulo="Firebase Storage permite listar los archivos sin sesión",
            descripcion="Cualquiera puede ver la lista de archivos del bucket y descargarlos.",
            recomendacion="Cambiar las reglas de Storage: allow read: if request.auth != null; (o por usuario).",
            evidencia=f"Bucket {b}: se listaron {len(items)} archivo(s) sin sesión (nombres no copiados).",
            referencias=[REF_REGLAS])]
    return []
