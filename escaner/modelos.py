from datetime import datetime
from enum import IntEnum

from pydantic import BaseModel, Field


class Severidad(IntEnum):
    INFO = 0
    BAJA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4

    @property
    def etiqueta(self) -> str:
        return ["Info", "Baja", "Media", "Alta", "Crítica"][self]

    @classmethod
    def desde_texto(cls, texto: str) -> "Severidad":
        texto = texto.strip().lower().replace("í", "i")
        for s in cls:
            if s.etiqueta.lower().replace("í", "i") == texto or s.name.lower() == texto:
                return s
        raise ValueError(f"Severidad desconocida: {texto}")


class Hallazgo(BaseModel):
    revision: str
    titulo: str
    severidad: Severidad
    url: str
    descripcion: str
    recomendacion: str
    evidencia: str | None = None
    referencias: list[str] = Field(default_factory=list)


class Campo(BaseModel):
    nombre: str
    tipo: str


class Formulario(BaseModel):
    pagina: str
    accion: str
    metodo: str
    campos: list[Campo] = Field(default_factory=list)
    # Sin method ni action en el HTML casi siempre lo envía JavaScript (apps React, Flutter, etc.).
    metodo_declarado: bool = True
    accion_declarada: bool = True


class Mapa(BaseModel):
    """Lo que encontró el rastreador."""

    paginas: list[str] = Field(default_factory=list)
    formularios: list[Formulario] = Field(default_factory=list)
    parametros: dict[str, list[str]] = Field(default_factory=dict)  # URL sin query -> nombres de parámetros
    omitidas: list[str] = Field(default_factory=list)  # enlaces que no se abrieron por parecer peligrosos


class Resultado(BaseModel):
    objetivo: str
    inicio: datetime
    fin: datetime | None = None
    peticiones: int = 0
    hallazgos: list[Hallazgo] = Field(default_factory=list)
    errores: list[str] = Field(default_factory=list)
    mapa: Mapa | None = None

    def conteo(self) -> dict[Severidad, int]:
        cuenta = {s: 0 for s in Severidad}
        for h in self.hallazgos:
            cuenta[h.severidad] += 1
        return cuenta

    def peor(self) -> Severidad | None:
        return max((h.severidad for h in self.hallazgos), default=None)
