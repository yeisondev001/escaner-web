from escaner.revisiones.archivos import ArchivosExpuestos
from escaner.revisiones.base import Revision, Sitio
from escaner.revisiones.cabeceras import Cabeceras
from escaner.revisiones.cookies import Cookies
from escaner.revisiones.cors import Cors
from escaner.revisiones.divulgacion import Divulgacion
from escaner.revisiones.firebase import HOSTS_FIREBASE, Firebase
from escaner.revisiones.formularios import Formularios
from escaner.revisiones.tls import TLS

TODAS: list[Revision] = [TLS(), Cabeceras(), Cookies(), Cors(), Divulgacion(), Formularios(), ArchivosExpuestos(), Firebase()]

__all__ = ["TODAS", "HOSTS_FIREBASE", "Revision", "Sitio"]
