from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from escaner.modelos import Resultado, Severidad

_entorno = Environment(loader=PackageLoader("escaner", "reportes/plantillas"), autoescape=select_autoescape(["j2", "html"]))


def html(resultado: Resultado, destino: Path) -> None:
    plantilla = _entorno.get_template("reporte.html.j2")
    destino.write_text(plantilla.render(r=resultado, Severidad=Severidad, conteo=resultado.conteo()), encoding="utf-8")


def json(resultado: Resultado, destino: Path) -> None:
    destino.write_text(resultado.model_dump_json(indent=2), encoding="utf-8")
