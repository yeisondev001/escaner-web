# escaner-web

Escáner de vulnerabilidades web. Revisa un sitio y genera un reporte HTML con cada problema, su gravedad y cómo arreglarlo.

> **Solo para sitios propios o con permiso escrito del dueño.** Escanear sitios ajenos sin autorización es delito (en RD, Ley 53-07). El escáner nunca envía peticiones fuera de los dominios autorizados, ni siquiera siguiendo redirecciones.

## Instalar

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

## Usar

```bash
.venv\Scripts\escaner escanear https://misitio.com
```

Pregunta si el sitio es tuyo o tienes permiso; con `--tengo-permiso` se salta la pregunta.

| Opción | Para qué |
|---|---|
| `--reporte salidas/x.html` | Dónde guardar el reporte (por defecto `reporte.html`) |
| `--json salidas/x.json` | Guardar también el resultado en JSON |
| `--permitir api.misitio.com` | Autorizar otro dominio (se repite; acepta `*.misitio.com`) |
| `--velocidad 3` | Peticiones por segundo (por defecto 5) |
| `--solo cabeceras --solo tls` | Correr solo algunas revisiones |
| `--fallar-en alta` | Termina con error si hay hallazgos de esa gravedad o mayor (para CI) |
| `--firebase` | Revisar también las reglas del proyecto de Firebase del sitio (solo lectura) |

`escaner revisiones` lista las revisiones disponibles.

## Qué revisa (todo pasivo: solo lectura)

| Revisión | Qué busca |
|---|---|
| `tls` | HTTP que no redirige a HTTPS, certificado inválido o por vencer, TLS 1.0/1.1 |
| `cabeceras` | HSTS, CSP, protección contra iframes (clickjacking), nosniff, Referrer-Policy, Permissions-Policy |
| `cookies` | Cookies sin Secure, HttpOnly o SameSite (el valor de la cookie se oculta en el reporte) |
| `cors` | Servidor que acepta cualquier Origin, sobre todo con credenciales |
| `divulgacion` | Versión del servidor/PHP expuesta, listado de directorios, contenido mixto, formularios con contraseña sin HTTPS, jQuery viejo |
| `archivos` | `.git`, `.env`, respaldos SQL/ZIP, `phpinfo`, `server-status`, `.DS_Store`, etc. Cada archivo se confirma por su contenido para no dar falsos positivos en apps de una sola página |
| `firebase` | Detecta el proyecto (por `/__/firebase/init.json` o en los scripts) y prueba sin sesión: Realtime Database, colecciones de Firestore (las que aparecen en el código + nombres comunes) y listado de Storage. Solo lee; en el reporte van nombres de campos y conteos, nunca los datos. Necesita `--firebase` |

## Estructura

```
escaner/
  alcance.py      dominios autorizados
  cliente.py      HTTP con límite de velocidad y control de alcance en cada redirección
  motor.py        corre las revisiones y junta los hallazgos
  modelos.py      Hallazgo, Severidad, Resultado
  revisiones/     una revisión por archivo (plugin)
  reportes/       HTML (Jinja2) y JSON
  cli.py          comandos de consola
tests/            pruebas con servidor simulado (no tocan sitios reales)
```

Para agregar una revisión: crear una clase que herede de `Revision` en `escaner/revisiones/`, implementar `ejecutar(sitio, cliente)` que devuelva una lista de `Hallazgo`, y agregarla a `TODAS` en `revisiones/__init__.py`.

## Pruebas

```bash
.venv\Scripts\python -m pytest
```

## Próximas fases

1. Firebase, segunda parte: bases de datos con nombre (no solo `(default)`), escritura pública y registro abierto (estas crean datos, así que van como revisiones activas con confirmación aparte).
2. Rastreador: descubrir páginas, formularios y parámetros.
3. Revisiones activas (XSS reflejado, inyección SQL por errores, open redirect), probadas solo contra OWASP Juice Shop / DVWA.
4. API FastAPI + cola (Redis + arq) + Postgres (Neon) + panel React.
