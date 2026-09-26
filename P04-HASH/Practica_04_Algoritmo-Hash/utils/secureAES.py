"""Práctica 4: SHA-256 para texto, archivos y verificación de integridad."""
import hashlib
import hmac
import re


def hash_texto(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()


def hash_archivo(ruta) -> str:
    resumen = hashlib.sha256()
    with open(ruta, 'rb') as archivo:
        for bloque in iter(lambda: archivo.read(65536), b''):
            resumen.update(bloque)
    return resumen.hexdigest()


def verificar_archivo(ruta, esperado: str) -> bool:
    if not re.fullmatch(r'[0-9a-fA-F]{64}', esperado):
        raise ValueError('El hash esperado debe tener 64 caracteres hexadecimales.')
    return hmac.compare_digest(hash_archivo(ruta), esperado.lower())


def bits_distintos(texto_a: str, texto_b: str) -> int:
    a = bytes.fromhex(hash_texto(texto_a))
    b = bytes.fromhex(hash_texto(texto_b))
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))



def cifrar_aes(texto, clave):
    """Ejercicio auxiliar AES-CBC; no interviene en las contraseñas del login."""
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    if len(clave) != 32:
        raise ValueError('AES-256 requiere una clave de 32 bytes')
    iv = os.urandom(16)
    relleno = PKCS7(128).padder()
    datos = relleno.update(texto.encode('utf-8')) + relleno.finalize()
    cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv)).encryptor()
    return iv, cifrador.update(datos) + cifrador.finalize()


def descifrar_aes(iv, cifrado, clave):
    """Complemento académico: CBC no verifica la autenticidad del mensaje."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    if len(clave) != 32 or len(iv) != 16:
        raise ValueError('Clave o IV de tamaño incorrecto')
    descifrador = Cipher(algorithms.AES(clave), modes.CBC(iv)).decryptor()
    datos = descifrador.update(cifrado) + descifrador.finalize()
    relleno = PKCS7(128).unpadder()
    return (relleno.update(datos) + relleno.finalize()).decode('utf-8')
