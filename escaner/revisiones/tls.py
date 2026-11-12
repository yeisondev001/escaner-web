import asyncio
import socket
import ssl
from datetime import datetime, timezone

from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

REF_TLS = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"


class TLS(Revision):
    id = "tls"
    nombre = "HTTPS y certificado"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        h: list[Hallazgo] = []

        # ¿La versión HTTP manda a HTTPS?
        url_http = f"http://{sitio.inicio.url.split('://', 1)[1].split('/', 1)[0]}/"
        try:
            r = await cliente.get(url_http, seguir=False)
            destino = r.cabeceras.get("location", "")
            if not (300 <= r.estado < 400 and destino.startswith("https://")):
                h.append(Hallazgo(
                    revision=self.id, url=url_http, severidad=Severidad.ALTA if not sitio.es_https else Severidad.MEDIA,
                    titulo="La versión HTTP no redirige a HTTPS",
                    descripcion="Quien entra por http:// navega sin cifrar: contraseñas y cookies viajan en texto plano.",
                    recomendacion="Redirigir todo http:// a https:// con un 301.",
                    evidencia=f"HTTP {r.estado} {destino}".strip(), referencias=[REF_TLS]))
        except Exception:
            pass  # el puerto 80 cerrado no es un problema

        if not sitio.es_https:
            return h

        cliente.alcance.verificar(f"https://{sitio.host}/")
        try:
            info = await asyncio.to_thread(_certificado, sitio.host, 443)
        except ssl.SSLCertVerificationError as e:
            h.append(Hallazgo(
                revision=self.id, url=sitio.url, severidad=Severidad.ALTA,
                titulo="Certificado SSL no válido",
                descripcion="El navegador mostrará una advertencia de seguridad y el cifrado no protege contra suplantación.",
                recomendacion="Instalar un certificado válido para este dominio (por ejemplo, Let's Encrypt).",
                evidencia=e.verify_message or str(e), referencias=[REF_TLS]))
            return h
        except (OSError, ssl.SSLError) as e:
            h.append(Hallazgo(
                revision=self.id, url=sitio.url, severidad=Severidad.INFO, titulo="No se pudo revisar el certificado",
                descripcion="Falló la conexión TLS directa al puerto 443.", recomendacion="Revisar manualmente.",
                evidencia=str(e)))
            return h

        dias = (info["vence"] - datetime.now(timezone.utc)).days
        if dias < 0:
            sev, titulo = Severidad.ALTA, "Certificado SSL vencido"
        elif dias < 14:
            sev, titulo = Severidad.ALTA, f"El certificado SSL vence en {dias} días"
        elif dias < 30:
            sev, titulo = Severidad.MEDIA, f"El certificado SSL vence en {dias} días"
        else:
            sev = None
        if sev is not None:
            h.append(Hallazgo(
                revision=self.id, url=sitio.url, severidad=sev, titulo=titulo,
                descripcion="Cuando vence, los navegadores bloquean el sitio con una advertencia.",
                recomendacion="Renovar el certificado y activar la renovación automática.",
                evidencia=f"Vence: {info['vence']:%Y-%m-%d}", referencias=[REF_TLS]))

        if info["version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
            h.append(Hallazgo(
                revision=self.id, url=sitio.url, severidad=Severidad.ALTA,
                titulo=f"El servidor negocia un protocolo obsoleto ({info['version']})",
                descripcion="TLS 1.0 y 1.1 tienen debilidades conocidas y los navegadores ya no los aceptan.",
                recomendacion="Permitir solo TLS 1.2 y TLS 1.3.", evidencia=info["version"], referencias=[REF_TLS]))
        return h


def _certificado(host: str, puerto: int) -> dict:
    contexto = ssl.create_default_context()
    with socket.create_connection((host, puerto), timeout=10) as s:
        with contexto.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
            vence = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
            return {"vence": vence, "version": t.version()}
