from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

ORIGEN_PRUEBA = "https://origen-de-prueba.invalid"
REF = "https://portswigger.net/web-security/cors"


class Cors(Revision):
    """Envía un Origin inventado y mira si el servidor lo acepta. No modifica nada."""

    id = "cors"
    nombre = "Configuración de CORS"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        h: list[Hallazgo] = []
        for origen in (ORIGEN_PRUEBA, "null"):
            r = await cliente.get(sitio.url, seguir=False, cabeceras={"Origin": origen})
            permitido = r.cabeceras.get("access-control-allow-origin", "")
            credenciales = r.cabeceras.get("access-control-allow-credentials", "").lower() == "true"
            if permitido != origen:
                continue
            h.append(Hallazgo(
                revision=self.id, url=sitio.url,
                severidad=Severidad.ALTA if credenciales else Severidad.BAJA,
                titulo=f"CORS acepta cualquier origen{' con credenciales' if credenciales else ''} (Origin: {origen})",
                descripcion=("Cualquier página puede leer las respuestas de este sitio usando la sesión del visitante."
                             if credenciales else
                             "El servidor copia el Origin que recibe; otros sitios pueden leer sus respuestas públicas."),
                recomendacion="Responder Access-Control-Allow-Origin solo con una lista fija de dominios de confianza.",
                evidencia=f"Access-Control-Allow-Origin: {permitido}\nAccess-Control-Allow-Credentials: {str(credenciales).lower()}",
                referencias=[REF]))
        return h
