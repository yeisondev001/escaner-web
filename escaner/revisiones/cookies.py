import re

from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

PARECE_SESION = re.compile(r"sess|sid|token|auth|jwt|login|user", re.I)
REFERENCIA = "https://developer.mozilla.org/es/docs/Web/HTTP/Cookies#restringir_el_acceso_a_las_cookies"


class Cookies(Revision):
    id = "cookies"
    nombre = "Atributos de las cookies"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        h: list[Hallazgo] = []
        for cruda in sitio.inicio.set_cookies:
            nombre, atributos = _leer(cruda)
            if not nombre:
                continue
            sesion = bool(PARECE_SESION.search(nombre))

            def agregar(titulo, severidad, descripcion, recomendacion):
                h.append(Hallazgo(revision=self.id, titulo=f"{titulo}: {nombre}", severidad=severidad, url=sitio.url,
                                  descripcion=descripcion, recomendacion=recomendacion,
                                  evidencia=_sin_valor(cruda), referencias=[REFERENCIA]))

            if sitio.es_https and "secure" not in atributos:
                agregar("Cookie sin Secure", Severidad.MEDIA if sesion else Severidad.BAJA,
                        "La cookie también se envía por HTTP sin cifrar, donde se puede robar.",
                        "Agregar el atributo Secure.")
            if "httponly" not in atributos:
                agregar("Cookie sin HttpOnly", Severidad.MEDIA if sesion else Severidad.INFO,
                        "JavaScript puede leer la cookie; con una falla de XSS se puede robar la sesión.",
                        "Agregar HttpOnly si el JavaScript del sitio no necesita leerla.")
            if "samesite" not in atributos:
                agregar("Cookie sin SameSite", Severidad.BAJA,
                        "Sin SameSite la cookie viaja en peticiones desde otros sitios, lo que facilita ataques CSRF.",
                        "Agregar SameSite=Lax (o Strict).")
            elif atributos["samesite"].lower() == "none" and "secure" not in atributos:
                agregar("Cookie con SameSite=None sin Secure", Severidad.BAJA,
                        "Los navegadores rechazan SameSite=None sin Secure.",
                        "Agregar Secure o cambiar a SameSite=Lax.")
        return h


def _leer(cruda: str) -> tuple[str, dict[str, str]]:
    partes = [p.strip() for p in cruda.split(";")]
    nombre = partes[0].split("=", 1)[0].strip() if partes else ""
    atributos = {}
    for p in partes[1:]:
        clave, _, valor = p.partition("=")
        atributos[clave.strip().lower()] = valor.strip()
    return nombre, atributos


def _sin_valor(cruda: str) -> str:
    """Oculta el valor de la cookie en el reporte (puede ser una sesión real)."""
    primera, _, resto = cruda.partition(";")
    nombre = primera.split("=", 1)[0]
    return f"{nombre}=***;{resto}" if resto else f"{nombre}=***"
