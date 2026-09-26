"""Registro local: JSON y contraseñas derivadas con PBKDF2-HMAC-SHA256.

El archivo se crea al registrar la primera cuenta; no existen usuarios predefinidos.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile

ITERACIONES = 600_000
ALGORITMO = 'pbkdf2-sha256'


class ArchivoCuentasInvalido(ValueError):
    """Se detiene la operación para evitar sobrescribir datos dañados."""


def normalizar_usuario(usuario):
    nombre = usuario.strip().casefold()
    if not re.fullmatch(r'[a-z0-9_.-]{3,30}', nombre):
        raise ValueError('Usa de 3 a 30 letras sin acentos, números, puntos, guiones o guion bajo.')
    return nombre


def derivar_contrasena(contrasena, sal):
    return hashlib.pbkdf2_hmac('sha256', contrasena.encode('utf-8'), sal, ITERACIONES).hex()


class RegistroCuentas:
    def __init__(self, ruta=None):
        self.ruta = Path(ruta) if ruta is not None else Path(__file__).resolve().parent.parent / 'usuarios.json'

    def _leer(self):
        if not self.ruta.exists():
            return {'version': 1, 'usuarios': {}}
        try:
            datos = json.loads(self.ruta.read_text(encoding='utf-8'))
            if not isinstance(datos, dict) or datos.get('version') != 1:
                raise ValueError('Versión inválida')
            usuarios = datos['usuarios']
            if not isinstance(usuarios, dict):
                raise ValueError('Registro inválido')
            for nombre, ficha in usuarios.items():
                if normalizar_usuario(nombre) != nombre or not isinstance(ficha, dict):
                    raise ValueError('Usuario inválido')
                if ficha.get('algoritmo') != ALGORITMO or ficha.get('iteraciones') != ITERACIONES:
                    raise ValueError('Parámetros inválidos')
                for campo, longitud in [('sal', 32), ('derivado', 64)]:
                    valor = ficha.get(campo)
                    if not isinstance(valor, str) or not re.fullmatch(f'[0-9a-f]{{{longitud}}}', valor):
                        raise ValueError('Resumen inválido')
            return datos
        except (ValueError, KeyError, TypeError) as error:
            raise ArchivoCuentasInvalido('El archivo de cuentas está dañado; no se modificó.') from error

    def _guardar(self, datos):
        # Escribir y reemplazar dentro del mismo directorio evita archivos parciales.
        temporal = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.ruta.parent,
                                             prefix='.cuentas-', suffix='.tmp', delete=False) as archivo:
                temporal = Path(archivo.name)
                json.dump(datos, archivo, ensure_ascii=False, indent=2)
                archivo.flush()
                os.fsync(archivo.fileno())
            os.replace(temporal, self.ruta)
        finally:
            if temporal is not None and temporal.exists():
                temporal.unlink()

    def registrar(self, usuario, contrasena):
        nombre = normalizar_usuario(usuario)
        if not 8 <= len(contrasena) <= 1024:
            raise ValueError('La contraseña debe tener entre 8 y 1024 caracteres.')
        datos = self._leer()
        if nombre in datos['usuarios']:
            raise ValueError('Ese nombre de usuario ya está registrado.')
        sal = os.urandom(16)
        datos['usuarios'][nombre] = {
            'algoritmo': ALGORITMO, 'iteraciones': ITERACIONES,
            'sal': sal.hex(), 'derivado': derivar_contrasena(contrasena, sal),
        }
        self._guardar(datos)
        return nombre

    def autenticar(self, usuario, contrasena):
        datos = self._leer()
        try:
            nombre = normalizar_usuario(usuario)
        except ValueError:
            return False
        if not 8 <= len(contrasena) <= 1024:
            return False
        ficha = datos['usuarios'].get(nombre)
        if ficha is None:
            return False
        candidato = derivar_contrasena(contrasena, bytes.fromhex(ficha['sal']))
        return hmac.compare_digest(candidato, ficha['derivado'])
