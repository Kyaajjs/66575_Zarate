"""
Práctica 3 - Algoritmo Híbrido RSA + AES
Seguridad Informática - UACAM

Implementa:
  - get_Msj_And_Key(mensaje, RSA_Publica)
  - decifrar_mensaje(mensajeCifrado_AES, iv_cifrado_RSA, RSA_Privada)
  - Cifrado_AES_enviar_mensaje(mensaje, clave_aes, iv)

Nota de diseño (ver documentación / análisis de seguridad para el detalle):
  - AES-256 (clave de 32 bytes) tal como pide el enunciado.
  - El IV de AES-CBC se genera de 16 bytes (tamaño de bloque de AES), no de 32.
    Un IV de 32 bytes no es válido para CBC porque el bloque de AES es de 128 bits (16 bytes);
    se documenta y justifica este ajuste en el reporte.
  - La clave AES y el IV se empaquetan juntos y se cifran en una sola operación RSA-OAEP
    (OAEP en vez de PKCS#1 v1.5 por ser el esquema recomendado actualmente).
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

AES_KEY_SIZE = 32   # AES-256
AES_IV_SIZE = 16    # tamaño de bloque de AES (obligatorio para CBC)
RSA_KEY_SIZE = 2048


def generar_par_rsa(bits: int = RSA_KEY_SIZE):
    """Genera un par de llaves RSA (privada, pública)."""
    privada = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return privada, privada.public_key()


def _oaep():
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def Cifrado_AES_enviar_mensaje(mensaje: bytes, clave_aes: bytes, iv: bytes) -> bytes:
    """
    Función auxiliar: cifra 'mensaje' con AES-256 en modo CBC usando la clave y el IV dados.
    Aplica relleno PKCS7 porque CBC exige que el texto plano sea múltiplo del tamaño de bloque.
    """
    if isinstance(mensaje, str):
        mensaje = mensaje.encode("utf-8")

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    datos_padded = padder.update(mensaje) + padder.finalize()

    cifrador = Cipher(algorithms.AES(clave_aes), modes.CBC(iv)).encryptor()
    return cifrador.update(datos_padded) + cifrador.finalize()


def _descifrar_aes(mensajeCifrado_AES: bytes, clave_aes: bytes, iv: bytes) -> bytes:
    descifrador = Cipher(algorithms.AES(clave_aes), modes.CBC(iv)).decryptor()
    datos_padded = descifrador.update(mensajeCifrado_AES) + descifrador.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(datos_padded) + unpadder.finalize()


def get_Msj_And_Key(mensaje, RSA_Publica):
    """
    Cifrado híbrido:
      1. Genera clave AES-256 aleatoria y un IV aleatorio (16 bytes).
      2. Cifra el mensaje con AES-CBC.
      3. Empaqueta (clave || iv) y lo cifra con RSA-OAEP usando la llave pública del receptor.

    Retorna: (iv_cifrado_RSA, mensajeCifrado_AES)
      - iv_cifrado_RSA: en realidad contiene clave_aes + iv cifrados juntos con RSA
        (se mantiene el nombre pedido en el enunciado; ver justificación en la documentación).
    """
    clave_aes = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(AES_IV_SIZE)

    mensajeCifrado_AES = Cifrado_AES_enviar_mensaje(mensaje, clave_aes, iv)

    paquete = clave_aes + iv
    iv_cifrado_RSA = RSA_Publica.encrypt(paquete, _oaep())

    return iv_cifrado_RSA, mensajeCifrado_AES


def decifrar_mensaje(mensajeCifrado_AES: bytes, iv_cifrado_RSA: bytes, RSA_Privada) -> bytes:
    """
    1. Descifra con RSA-OAEP el paquete (clave_aes + iv) usando la llave privada.
    2. Separa clave_aes e iv.
    3. Descifra el mensaje con AES-CBC usando clave_aes e iv.
    Retorna el mensaje original en bytes.
    """
    paquete = RSA_Privada.decrypt(iv_cifrado_RSA, _oaep())
    clave_aes = paquete[:AES_KEY_SIZE]
    iv = paquete[AES_KEY_SIZE:AES_KEY_SIZE + AES_IV_SIZE]

    return _descifrar_aes(mensajeCifrado_AES, clave_aes, iv)


def main():
    """Demostración ejecutable, sin guardar las claves privadas en disco."""
    import argparse
    from base64 import b64encode

    parser = argparse.ArgumentParser(description='Práctica 3: cifrado híbrido RSA + AES')
    parser.add_argument('--mensaje', default='La seguridad comienza con un mensaje protegido.')
    parser.add_argument('--pruebas', action='store_true', help='Ejecutar las nueve pruebas integradas')
    args = parser.parse_args()
    if args.pruebas:
        ejecutar_pruebas()
        return
    privada, publica = generar_par_rsa()
    paquete, cifrado = get_Msj_And_Key(args.mensaje, publica)
    recuperado = decifrar_mensaje(cifrado, paquete, privada).decode('utf-8')
    print('PRACTICA 3 | RSA-2048 + AES-256-CBC')
    print('Original:   ', args.mensaje)
    print('Paquete RSA:', len(paquete), 'bytes (clave AES + IV protegidos)')
    print('Cifrado AES:', b64encode(cifrado).decode('ascii'))
    print('Recuperado: ', recuperado)
    if recuperado != args.mensaje:
        raise RuntimeError('El mensaje recuperado no coincide')
    print('Comprobacion: CORRECTA')
    print('Nota: CBC no autentica el mensaje. Ver analisis del reporte.')


"""
Pruebas para el algoritmo híbrido RSA + AES.
Ejecutar: python algoritmo_hibrido.py --pruebas
"""

import os
import time



def prueba_flujo_completo():
    print("\n[Prueba 1] Flujo completo (cifrar -> descifrar, mensaje normal)")
    priv, pub = generar_par_rsa()
    mensaje = "Hola, este es un mensaje secreto para la práctica de Seguridad Informática."

    iv_cifrado_RSA, mensajeCifrado_AES = get_Msj_And_Key(mensaje, pub)
    recuperado = decifrar_mensaje(mensajeCifrado_AES, iv_cifrado_RSA, priv)

    assert recuperado.decode("utf-8") == mensaje, "El mensaje recuperado no coincide"
    print("  Mensaje original: ", mensaje)
    print("  Mensaje recuperado:", recuperado.decode("utf-8"))
    print("  OK: coinciden")


def prueba_mensaje_vacio():
    print("\n[Prueba 2] Mensaje vacío")
    priv, pub = generar_par_rsa()
    mensaje = ""
    iv_cifrado_RSA, mensajeCifrado_AES = get_Msj_And_Key(mensaje, pub)
    recuperado = decifrar_mensaje(mensajeCifrado_AES, iv_cifrado_RSA, priv)
    assert recuperado.decode("utf-8") == mensaje
    print("  OK: mensaje vacío cifrado/descifrado correctamente")


def prueba_mensaje_largo():
    print("\n[Prueba 3] Mensaje largo (no múltiplo del tamaño de bloque)")
    priv, pub = generar_par_rsa()
    mensaje = "A" * 501  # longitud arbitraria, no múltiplo de 16
    iv_cifrado_RSA, mensajeCifrado_AES = get_Msj_And_Key(mensaje, pub)
    recuperado = decifrar_mensaje(mensajeCifrado_AES, iv_cifrado_RSA, priv)
    assert recuperado.decode("utf-8") == mensaje
    print(f"  OK: mensaje de {len(mensaje)} caracteres recuperado íntegro")


def prueba_unicode():
    print("\n[Prueba 4] Caracteres especiales / acentos / emoji")
    priv, pub = generar_par_rsa()
    mensaje = "Contraseña: áéíóú ñ 🔐 中文"
    iv_cifrado_RSA, mensajeCifrado_AES = get_Msj_And_Key(mensaje, pub)
    recuperado = decifrar_mensaje(mensajeCifrado_AES, iv_cifrado_RSA, priv)
    assert recuperado.decode("utf-8") == mensaje
    print("  OK: texto con acentos/emoji recuperado correctamente")


def prueba_claves_aes_distintas_por_llamada():
    print("\n[Prueba 5] Dos cifrados del mismo mensaje son distintos")
    priv, pub = generar_par_rsa()
    mensaje = "mismo mensaje"
    _, cifrado1 = get_Msj_And_Key(mensaje, pub)
    _, cifrado2 = get_Msj_And_Key(mensaje, pub)
    assert cifrado1 != cifrado2, "Dos cifrados del mismo mensaje no deberían ser iguales"
    print("  OK: los cifrados difieren aunque el mensaje sea el mismo (clave/IV aleatorios)")


def prueba_clave_privada_incorrecta():
    print("\n[Prueba 6] Descifrar con una llave privada que NO corresponde debe fallar")
    priv1, pub1 = generar_par_rsa()
    priv2, _pub2 = generar_par_rsa()  # otro par, no relacionado
    mensaje = "mensaje confidencial"
    iv_cifrado_RSA, mensajeCifrado_AES = get_Msj_And_Key(mensaje, pub1)

    fallo = False
    try:
        decifrar_mensaje(mensajeCifrado_AES, iv_cifrado_RSA, priv2)
    except Exception as e:
        fallo = True
        print(f"  OK: la llave incorrecta fue rechazada ({type(e).__name__})")
    assert fallo, "Se descifró con una llave privada incorrecta: esto es un fallo de seguridad"


def prueba_mensaje_alterado_en_transito():
    print("\n[Prueba 7] Manipulación NO detectada por CBC")
    priv, pub = generar_par_rsa()
    mensaje = "transferencia: 1000 pesos a cuenta A"
    iv_cifrado_RSA, mensajeCifrado_AES = get_Msj_And_Key(mensaje, pub)

    # Un atacante modifica un byte del criptograma AES
    alterado = bytearray(mensajeCifrado_AES)
    alterado[0] ^= 0xFF
    alterado = bytes(alterado)

    recuperado = decifrar_mensaje(alterado, iv_cifrado_RSA, priv)
    distinto = recuperado != mensaje.encode("utf-8")
    assert distinto, "La alteración debe cambiar el mensaje"
    print(f"  El mensaje descifrado tras la alteración {'SÍ' if distinto else 'NO'} cambió respecto al original")
    print("  NOTA: CBC descifra 'algo' sin lanzar error -> no hay verificación de integridad.")
    print("  Esto se documenta en el análisis de seguridad (falta de autenticación, ver reporte).")


def prueba_funcion_auxiliar_directa():
    print("\n[Prueba 8] Uso directo de Cifrado_AES_enviar_mensaje")
    clave = os.urandom(32)
    iv = os.urandom(16)
    mensaje = "prueba de la función auxiliar"
    cifrado = Cifrado_AES_enviar_mensaje(mensaje, clave, iv)
    assert cifrado != mensaje.encode("utf-8")
    print(f"  OK: se generaron {len(cifrado)} bytes cifrados")


def prueba_rendimiento():
    print("\n[Prueba 9] Rendimiento aproximado (10 ciclos cifrar+descifrar)")
    priv, pub = generar_par_rsa()
    mensaje = "X" * 10_000  # 10 KB
    inicio = time.time()
    for _ in range(10):
        iv_c, msg_c = get_Msj_And_Key(mensaje, pub)
        assert decifrar_mensaje(msg_c, iv_c, priv) == mensaje.encode("utf-8")
    total = time.time() - inicio
    print(f"  10 ciclos de cifrado+descifrado de 10 KB: {total:.3f} s ({total/10*1000:.1f} ms/ciclo)")


def ejecutar_pruebas():
    prueba_flujo_completo()
    prueba_mensaje_vacio()
    prueba_mensaje_largo()
    prueba_unicode()
    prueba_claves_aes_distintas_por_llamada()
    prueba_clave_privada_incorrecta()
    prueba_mensaje_alterado_en_transito()
    prueba_funcion_auxiliar_directa()
    prueba_rendimiento()
    print("\n✅ Todas las pruebas pasaron correctamente.")


if __name__ == '__main__':
    main()
