import asyncio
from collections.abc import Callable
from datetime import datetime, timezone

import httpx

from escaner.alcance import Alcance
from escaner.cliente import Cliente
from escaner.modelos import Resultado
from escaner.rastreador import Rastreador
from escaner.revisiones import TODAS, Revision, Sitio


async def escanear(
    url: str,
    alcance: Alcance,
    revisiones: list[Revision] | None = None,
    por_segundo: float = 5.0,
    max_paginas: int = 1,
    max_profundidad: int = 3,
    al_terminar_revision: Callable[[Revision, int], None] | None = None,
    al_rastrear: Callable[[int, int], None] | None = None,
    transporte: httpx.AsyncBaseTransport | None = None,
) -> Resultado:
    revisiones = TODAS if revisiones is None else revisiones
    resultado = Resultado(objetivo=url, inicio=datetime.now(timezone.utc))
    alcance.verificar(url)

    async with Cliente(alcance, por_segundo=por_segundo, transporte=transporte) as cliente:
        try:
            inicio = await cliente.get(url)
        except Exception as e:
            resultado.errores.append(f"No se pudo abrir {url}: {e}")
            resultado.fin = datetime.now(timezone.utc)
            resultado.peticiones = cliente.peticiones
            return resultado
        sitio = Sitio(url_pedida=url, inicio=inicio)
        if max_paginas > 1:
            mapa, paginas = await Rastreador(cliente, max_paginas, max_profundidad).rastrear(inicio)
            sitio.paginas, sitio.mapa, resultado.mapa = paginas, mapa, mapa
            if al_rastrear:
                al_rastrear(len(paginas), len(mapa.formularios))

        async def correr(rev: Revision) -> None:
            try:
                hallados = await rev.ejecutar(sitio, cliente)
                resultado.hallazgos.extend(hallados)
                if al_terminar_revision:
                    al_terminar_revision(rev, len(hallados))
            except Exception as e:
                resultado.errores.append(f"{rev.nombre}: {type(e).__name__}: {e}")

        # Corren a la vez; el cliente igual respeta el límite de peticiones por segundo.
        await asyncio.gather(*(correr(r) for r in revisiones))
        resultado.peticiones = cliente.peticiones

    resultado.hallazgos.sort(key=lambda h: (-h.severidad, h.revision, h.titulo))
    resultado.fin = datetime.now(timezone.utc)
    return resultado
