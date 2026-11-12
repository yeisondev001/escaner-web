"""Información que el sitio revela de más y problemas visibles en el HTML."""

import re

from selectolax.lexbor import LexborHTMLParser

from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

CON_VERSION = re.compile(r"\d+\.\d+")
JQUERY = re.compile(r"jquery[.-]?(\d+)\.(\d+)\.(\d+)", re.I)


class Divulgacion(Revision):
    id = "divulgacion"
    nombre = "Información expuesta y contenido de la página"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        r = sitio.inicio
        h: list[Hallazgo] = []

        def agregar(titulo, severidad, descripcion, recomendacion, evidencia, referencias=()):
            h.append(Hallazgo(revision=self.id, titulo=titulo, severidad=severidad, url=sitio.url, descripcion=descripcion,
                              recomendacion=recomendacion, evidencia=evidencia, referencias=list(referencias)))

        for cabecera in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            valor = r.cabeceras.get(cabecera)
            if valor and (cabecera != "server" or CON_VERSION.search(valor)):
                agregar(f"El servidor revela su software ({cabecera})", Severidad.BAJA,
                        "Conocer la versión exacta ayuda a un atacante a buscar fallas conocidas para ese software.",
                        "Quitar la cabecera o la versión (por ejemplo, server_tokens off en nginx, expose_php = Off en PHP).",
                        f"{cabecera}: {valor}")

        # Problemas del HTML: se revisan en todas las páginas y se reporta cada uno una sola vez,
        # con la lista de páginas donde aparece.
        encontrados: dict[str, dict] = {}

        def anotar(clave: str, pagina: str, detalle: str, **datos):
            e = encontrados.setdefault(clave, {"paginas": [], "detalles": [], **datos})
            e["paginas"].append(pagina)
            if detalle not in e["detalles"]:
                e["detalles"].append(detalle)

        for p in sitio.paginas:
            if not p.es_html:
                continue
            html = LexborHTMLParser(p.texto)
            https = p.url.startswith("https://")

            titulo = html.css_first("title")
            if titulo and titulo.text().strip().startswith("Index of /"):
                anotar("listado", p.url, titulo.text().strip())

            if https:
                for n in html.css("script[src], iframe[src], link[rel=stylesheet][href]"):
                    recurso = n.attributes.get("src") or n.attributes.get("href") or ""
                    if recurso.startswith("http://"):
                        anotar("mixto", p.url, recurso)

            for form in html.css("form"):
                accion = form.attributes.get("action") or ""
                if form.css_first("input[type=password]") and (accion.startswith("http://") or not https):
                    anotar("clave_sin_cifrar", p.url, f"action={accion or '(misma página)'}")

            for n in html.css("script[src]"):
                m = JQUERY.search(n.attributes.get("src") or "")
                if m and tuple(map(int, m.groups())) < (3, 5, 0):
                    anotar("jquery", p.url, n.attributes.get("src"), version=".".join(m.groups()))

        textos = {
            "listado": ("Listado de directorio activado", Severidad.MEDIA,
                        "Cualquiera puede ver todos los archivos de la carpeta.",
                        "Desactivar el listado (Options -Indexes en Apache, autoindex off en nginx).", []),
            "mixto": ("Contenido mixto (recursos por HTTP en una página HTTPS)", Severidad.MEDIA,
                      "Scripts o estilos cargados sin cifrar pueden ser modificados en el camino.",
                      "Cargar todos los recursos por https://.",
                      ["https://developer.mozilla.org/es/docs/Web/Security/Mixed_content"]),
            "clave_sin_cifrar": ("Formulario con contraseña se envía sin cifrar", Severidad.ALTA,
                                 "La contraseña viaja en texto plano y puede ser capturada en la red.",
                                 "Servir la página y el destino del formulario solo por HTTPS.", []),
            "jquery": ("jQuery {version} tiene fallas XSS conocidas", Severidad.MEDIA,
                       "Las versiones de jQuery anteriores a 3.5.0 permiten XSS al insertar HTML (CVE-2020-11022, CVE-2020-11023).",
                       "Actualizar jQuery a la versión 3.5.0 o superior.", ["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"]),
        }
        for clave, e in encontrados.items():
            titulo, severidad, descripcion, recomendacion, refs = textos[clave]
            paginas = list(dict.fromkeys(e["paginas"]))
            evidencia = "\n".join(e["detalles"][:5])
            if len(paginas) > 1:
                evidencia += f"\n\nAparece en {len(paginas)} páginas:\n" + "\n".join(paginas[:10])
            h.append(Hallazgo(revision=self.id, titulo=titulo.format(**e), severidad=severidad, url=paginas[0],
                              descripcion=descripcion, recomendacion=recomendacion, evidencia=evidencia, referencias=refs))
        return h
