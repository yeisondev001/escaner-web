import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from escaner import reportes
from escaner.alcance import Alcance, FueraDeAlcance
from escaner.modelos import Severidad
from escaner.motor import escanear
from escaner.revisiones import HOSTS_FIREBASE, TODAS

app = typer.Typer(add_completion=False, help="Escáner de vulnerabilidades web. Solo para sitios propios o con permiso escrito.")
consola = Console()
COLORES = {Severidad.CRITICA: "bold white on red", Severidad.ALTA: "bold red", Severidad.MEDIA: "yellow",
           Severidad.BAJA: "cyan", Severidad.INFO: "dim"}


@app.command("escanear")
def cmd_escanear(
    url: Annotated[str, typer.Argument(help="Sitio a revisar, por ejemplo https://misitio.com")],
    permitir: Annotated[list[str], typer.Option("--permitir", "-p", help="Otro dominio autorizado (se puede repetir; acepta *.dominio.com)")] = [],
    velocidad: Annotated[float, typer.Option(help="Máximo de peticiones por segundo")] = 5.0,
    reporte: Annotated[Path, typer.Option(help="Archivo HTML del reporte")] = Path("reporte.html"),
    json_salida: Annotated[Path | None, typer.Option("--json", help="Guardar también el resultado en JSON")] = None,
    solo: Annotated[list[str], typer.Option(help="Correr solo estas revisiones (ver: escaner revisiones)")] = [],
    fallar_en: Annotated[str | None, typer.Option(help="Salir con error si hay hallazgos de esta severidad o mayor (útil en CI)")] = None,
    firebase: Annotated[bool, typer.Option("--firebase", help="Revisar también las reglas del proyecto de Firebase del sitio (solo lectura)")] = False,
    tengo_permiso: Annotated[bool, typer.Option("--tengo-permiso", help="Confirmo que el sitio es mío o tengo permiso escrito")] = False,
):
    """Revisa un sitio y genera un reporte."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    alcance = Alcance.desde_url(url, [*permitir, *(HOSTS_FIREBASE if firebase else [])])

    if not tengo_permiso:
        consola.print(f"[bold]Alcance:[/bold] {alcance}")
        if firebase:
            consola.print("Con --firebase también se leen (sin escribir) Firestore, Realtime Database y Storage del proyecto que use el sitio.")
        if not typer.confirm("¿Estos sitios (y su proyecto de Firebase) son tuyos o tienes permiso escrito para escanearlos?", default=False):
            consola.print("[red]Cancelado. Solo se pueden escanear sitios propios o autorizados.[/red]")
            raise typer.Exit(2)

    revisiones = [r for r in TODAS if not solo or r.id in solo]
    if not revisiones:
        consola.print(f"[red]Ninguna revisión coincide con {solo}.[/red]")
        raise typer.Exit(2)

    def avance(rev, n):
        consola.print(f"  [green]✓[/green] {rev.nombre} [dim]({n} hallazgos)[/dim]")

    consola.print(f"Escaneando [bold]{url}[/bold] con {len(revisiones)} revisiones…")
    try:
        resultado = asyncio.run(escanear(url, alcance, revisiones, por_segundo=velocidad, al_terminar_revision=avance))
    except FueraDeAlcance as e:
        consola.print(f"[red]{e}[/red]")
        raise typer.Exit(2)

    _resumen(resultado)
    reportes.html(resultado, reporte)
    consola.print(f"\nReporte: [bold]{reporte.resolve()}[/bold]")
    if json_salida:
        reportes.json(resultado, json_salida)
        consola.print(f"JSON: [bold]{json_salida.resolve()}[/bold]")

    if fallar_en:
        limite = Severidad.desde_texto(fallar_en)
        peor = resultado.peor()
        if peor is not None and peor >= limite:
            raise typer.Exit(1)


@app.command("revisiones")
def cmd_revisiones():
    """Lista las revisiones disponibles."""
    t = Table("id", "nombre", "tipo")
    for r in TODAS:
        t.add_row(r.id, r.nombre, r.tipo)
    consola.print(t)


def _resumen(resultado):
    for e in resultado.errores:
        consola.print(f"[yellow]Aviso:[/yellow] {e}")
    if not resultado.hallazgos:
        consola.print("\n[green]Sin hallazgos.[/green]")
        return
    t = Table("Severidad", "Hallazgo", "Revisión", title=f"\n{len(resultado.hallazgos)} hallazgos · {resultado.peticiones} peticiones")
    for h in resultado.hallazgos:
        t.add_row(f"[{COLORES[h.severidad]}]{h.severidad.etiqueta}[/]", h.titulo, h.revision)
    consola.print(t)
