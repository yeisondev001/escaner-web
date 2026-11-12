# escaner-web

Escáner de vulnerabilidades web en Python. Ver README.md para uso y estructura.

## Reglas del proyecto
- Solo se escanean sitios del usuario o con permiso escrito. Toda petición pasa por `Cliente`, que verifica el alcance (también en redirecciones); no hacer peticiones por fuera de él.
- Las revisiones activas (que envían pruebas de ataque) se prueban solo contra laboratorios locales (OWASP Juice Shop, DVWA), nunca contra sitios reales.
- Los reportes no deben copiar secretos: ocultar valores de cookies y de archivos expuestos.
- Cada revisión nueva lleva su prueba en `tests/` usando `httpx.MockTransport`.

## Comandos
- Pruebas: `.venv\Scripts\python -m pytest -q`
- Escanear: `.venv\Scripts\escaner escanear https://sitio --reporte salidas/sitio.html`
- En la terminal de Git Bash, usar `PYTHONIOENCODING=utf-8` para que se vean los acentos.
