"""Revisa los formularios que encontró el rastreador (sin enviarlos)."""

import re

from escaner.modelos import Formulario, Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

TOKEN_CSRF = re.compile(r"csrf|xsrf|_token|authenticity|verificationtoken|nonce|state", re.I)
REF_CSRF = "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"


class Formularios(Revision):
    id = "formularios"
    nombre = "Formularios"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        if not sitio.mapa:
            return []
        h: list[Hallazgo] = []
        for f in sitio.mapa.formularios:
            tipos = {c.tipo for c in f.campos}
            if f.metodo == "GET" and "password" in tipos:
                if f.metodo_declarado or f.accion_declarada:
                    h.append(Hallazgo(
                        revision=self.id, severidad=Severidad.ALTA, url=f.pagina,
                        titulo="Formulario envía la contraseña en la URL (method=GET)",
                        descripcion="La contraseña queda en el historial del navegador, en los registros del servidor y en la cabecera Referer.",
                        recomendacion='Usar method="POST" en el formulario.', evidencia=_resumen(f)))
                else:
                    h.append(Hallazgo(
                        revision=self.id, severidad=Severidad.BAJA, url=f.pagina,
                        titulo="Formulario de contraseña sin method=\"post\"",
                        descripcion="Lo envía JavaScript, así que normalmente no pasa nada. Pero si el JavaScript no carga o falla y "
                                    "el usuario presiona Enter, el navegador manda la contraseña en la URL.",
                        recomendacion='Agregar method="post" al <form> como respaldo.', evidencia=_resumen(f)))
            if f.metodo == "POST" and not any(TOKEN_CSRF.search(c.nombre) for c in f.campos if c.tipo == "hidden"):
                h.append(Hallazgo(
                    revision=self.id, severidad=Severidad.MEDIA, url=f.pagina,
                    titulo="Formulario POST sin token anti-CSRF",
                    descripcion="Otro sitio podría enviar este formulario en nombre de un usuario con sesión iniciada (CSRF). "
                                "Si el sitio protege de otra forma (cookies SameSite=Strict, cabeceras), puede no aplicar.",
                    recomendacion="Agregar un token anti-CSRF por sesión en un campo oculto y validarlo en el servidor.",
                    evidencia=_resumen(f), referencias=[REF_CSRF]))
        return h


def _resumen(f: Formulario) -> str:
    campos = ", ".join(f"{c.nombre} ({c.tipo})" for c in f.campos) or "(sin campos con nombre)"
    return f"{f.metodo} {f.accion}\nCampos: {campos}"
