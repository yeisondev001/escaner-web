"""Busca archivos que nunca deberían estar publicados (.env, .git, respaldos...).

Para no dar falsos positivos con sitios que responden 200 a cualquier ruta
(como las apps de una sola página), cada archivo se confirma por su contenido."""

import re
from collections.abc import Callable
from dataclasses import dataclass

from escaner.cliente import Respuesta
from escaner.modelos import Hallazgo, Severidad
from escaner.revisiones.base import Revision, Sitio

REF = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"


def _no_html(r: Respuesta) -> bool:
    inicio = r.cuerpo[:300].lstrip().lower()
    return not (inicio.startswith(b"<!doctype") or inicio.startswith(b"<html"))


def _texto(r: Respuesta, patron: str, flags=0) -> bool:
    return _no_html(r) and re.search(patron, r.texto, flags) is not None


@dataclass
class Sonda:
    ruta: str
    titulo: str
    severidad: Severidad
    descripcion: str
    confirma: Callable[[Respuesta], bool]


SONDAS = [
    Sonda("/.git/HEAD", "Repositorio Git expuesto", Severidad.CRITICA,
          "Se puede descargar el código fuente completo del sitio, incluido su historial y posibles contraseñas.",
          lambda r: _texto(r, r"^(ref: refs/|[0-9a-f]{40}\s*$)")),
    Sonda("/.env", "Archivo .env expuesto", Severidad.CRITICA,
          "El .env suele tener contraseñas de base de datos, llaves de API y secretos.",
          lambda r: _no_html(r) and len(re.findall(r"^[A-Z][A-Z0-9_]*=", r.texto, re.M)) >= 2),
    Sonda("/.vscode/sftp.json", "Configuración SFTP de VS Code expuesta", Severidad.CRITICA,
          "Este archivo suele tener el servidor, usuario y contraseña de publicación.",
          lambda r: _texto(r, r'"(host|password|username)"\s*:')),
    Sonda("/backup.sql", "Respaldo de base de datos expuesto", Severidad.CRITICA,
          "Un volcado de la base de datos se puede descargar.",
          lambda r: _texto(r, r"CREATE TABLE|INSERT INTO", re.I)),
    Sonda("/database.sql", "Respaldo de base de datos expuesto", Severidad.CRITICA,
          "Un volcado de la base de datos se puede descargar.",
          lambda r: _texto(r, r"CREATE TABLE|INSERT INTO", re.I)),
    Sonda("/backup.zip", "Respaldo comprimido expuesto", Severidad.ALTA,
          "Un archivo de respaldo se puede descargar; puede contener código y configuraciones.",
          lambda r: r.cuerpo.startswith(b"PK\x03\x04")),
    Sonda("/wp-config.php.bak", "Copia de wp-config.php expuesta", Severidad.CRITICA,
          "La copia se descarga como texto y muestra las credenciales de la base de datos de WordPress.",
          lambda r: _texto(r, r"DB_PASSWORD|DB_USER")),
    Sonda("/.svn/entries", "Repositorio SVN expuesto", Severidad.ALTA,
          "Se puede reconstruir el código fuente del sitio.",
          lambda r: _texto(r, r"^\d+\s*$|svn", re.M)),
    Sonda("/phpinfo.php", "phpinfo() publicado", Severidad.MEDIA,
          "Muestra versiones, rutas internas y variables del servidor.",
          lambda r: "PHP Version" in r.texto and "phpinfo" in r.texto.lower()),
    Sonda("/info.php", "phpinfo() publicado", Severidad.MEDIA,
          "Muestra versiones, rutas internas y variables del servidor.",
          lambda r: "PHP Version" in r.texto and "phpinfo" in r.texto.lower()),
    Sonda("/server-status", "Estado del servidor Apache público", Severidad.MEDIA,
          "Muestra las peticiones en curso, incluidas URLs e IPs de los visitantes.",
          lambda r: "Apache Server Status" in r.texto),
    Sonda("/.DS_Store", "Archivo .DS_Store expuesto", Severidad.BAJA,
          "Revela la lista de archivos y carpetas del directorio.",
          lambda r: r.cuerpo[:8] == b"\x00\x00\x00\x01Bud1"),
    Sonda("/.htaccess", "Archivo .htaccess legible", Severidad.BAJA,
          "Revela reglas internas del servidor.",
          lambda r: _texto(r, r"RewriteEngine|RewriteRule|Deny from|Require all", re.I)),
]


class ArchivosExpuestos(Revision):
    id = "archivos"
    nombre = "Archivos sensibles expuestos"

    async def ejecutar(self, sitio: Sitio, cliente) -> list[Hallazgo]:
        h: list[Hallazgo] = []
        for s in SONDAS:
            url = sitio.raiz + s.ruta
            try:
                r = await cliente.get(url, seguir=False)
            except Exception:
                continue
            if r.estado == 200 and r.cuerpo and s.confirma(r):
                h.append(Hallazgo(
                    revision=self.id, titulo=s.titulo, severidad=s.severidad, url=url, descripcion=s.descripcion,
                    recomendacion="Borrar el archivo del servidor o bloquear su acceso, y cambiar cualquier contraseña o llave que contenga.",
                    evidencia=_muestra(r), referencias=[REF]))
        return h


def _muestra(r: Respuesta) -> str:
    """Primeras líneas del archivo, con los valores tapados (no copiar secretos al reporte)."""
    if not _no_html(r) or b"\x00" in r.cuerpo[:200]:
        return f"HTTP 200, {len(r.cuerpo)} bytes"
    lineas = r.texto.splitlines()[:5]
    return "\n".join(re.sub(r"([=:]\s*)\S.*", r"\1***", l)[:120] for l in lineas)
