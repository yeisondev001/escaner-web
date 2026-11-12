from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

OWASP_CABECERAS = "https://owasp.org/www-project-secure-headers/"
SEIS_MESES = 15_552_000


class Cabeceras(Revision):
    id = "cabeceras"
    nombre = "Cabeceras de seguridad"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        c = sitio.inicio.cabeceras
        h: list[Hallazgo] = []

        def falta(titulo, severidad, descripcion, recomendacion, evidencia=None):
            h.append(Hallazgo(revision=self.id, titulo=titulo, severidad=severidad, url=sitio.url,
                              descripcion=descripcion, recomendacion=recomendacion, evidencia=evidencia,
                              referencias=[OWASP_CABECERAS]))

        if sitio.es_https:
            hsts = c.get("strict-transport-security")
            if not hsts:
                falta("Falta Strict-Transport-Security (HSTS)", Severidad.MEDIA,
                      "Sin HSTS, un atacante en la misma red puede forzar al navegador a usar HTTP en la primera visita.",
                      "Enviar: Strict-Transport-Security: max-age=31536000; includeSubDomains")
            else:
                edad = _max_age(hsts)
                if edad is not None and edad < SEIS_MESES:
                    falta("HSTS con duración corta", Severidad.BAJA,
                          f"max-age es {edad} segundos; se recomienda al menos 6 meses.",
                          "Subir max-age a 31536000 (un año).", hsts)

        csp = c.get("content-security-policy")
        if not csp:
            falta("Falta Content-Security-Policy (CSP)", Severidad.MEDIA,
                  "Sin CSP, si hay una falla de XSS el navegador ejecuta cualquier script inyectado.",
                  "Definir una política, por ejemplo: default-src 'self'; y ajustar según los recursos que use el sitio.")
        elif "'unsafe-inline'" in _directiva(csp, "script-src", "default-src"):
            falta("CSP permite scripts en línea ('unsafe-inline')", Severidad.BAJA,
                  "'unsafe-inline' en script-src anula buena parte de la protección contra XSS.",
                  "Usar nonces o hashes en lugar de 'unsafe-inline'.", csp)

        if not c.get("x-frame-options") and "frame-ancestors" not in (csp or ""):
            falta("El sitio se puede meter dentro de un iframe (clickjacking)", Severidad.MEDIA,
                  "Sin X-Frame-Options ni frame-ancestors, otra página puede mostrar este sitio oculto y engañar al usuario para que haga clic.",
                  "Enviar X-Frame-Options: DENY (o SAMEORIGIN), o en la CSP: frame-ancestors 'none'.")

        if c.get("x-content-type-options", "").lower() != "nosniff":
            falta("Falta X-Content-Type-Options: nosniff", Severidad.BAJA,
                  "El navegador puede adivinar el tipo de un archivo y ejecutarlo como script.",
                  "Enviar: X-Content-Type-Options: nosniff")

        if not c.get("referrer-policy"):
            falta("Falta Referrer-Policy", Severidad.BAJA,
                  "Las URLs completas (con parámetros) pueden filtrarse a otros sitios en la cabecera Referer.",
                  "Enviar: Referrer-Policy: strict-origin-when-cross-origin")

        if not c.get("permissions-policy"):
            falta("Falta Permissions-Policy", Severidad.INFO,
                  "No se restringe el acceso a cámara, micrófono, ubicación, etc. desde el sitio o sus iframes.",
                  "Enviar por ejemplo: Permissions-Policy: camera=(), microphone=(), geolocation=()")
        return h


def _max_age(hsts: str) -> int | None:
    for parte in hsts.split(";"):
        clave, _, valor = parte.strip().partition("=")
        if clave.lower() == "max-age":
            try:
                return int(valor.strip().strip('"'))
            except ValueError:
                return None
    return None


def _directiva(csp: str, *nombres: str) -> str:
    """Devuelve la primera directiva de la lista que exista en la CSP."""
    directivas = {}
    for parte in csp.split(";"):
        trozos = parte.strip().split(None, 1)
        if trozos:
            directivas[trozos[0].lower()] = trozos[1] if len(trozos) > 1 else ""
    for n in nombres:
        if n in directivas:
            return directivas[n]
    return ""
