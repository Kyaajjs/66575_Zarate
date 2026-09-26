"""Práctica 04: python main.py | python main.py --pruebas | python main.py --demo."""
import sys
sys.dont_write_bytecode = True  # Evitar carpetas __pycache__ en esta entrega.
import argparse
"""Pruebas de SHA-256 integradas: python main.py --pruebas."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from utils.secureAES import hash_texto, hash_archivo, verificar_archivo, bits_distintos


class PruebasHash(unittest.TestCase):
    def test_vector_abc(self):
        self.assertEqual(hash_texto('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_vector_vacio(self):
        self.assertEqual(hash_texto(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_unicode_y_determinismo(self):
        texto = 'Contraseña: áéíóú ñ 🔐 中文'
        self.assertEqual(hash_texto(texto), hash_texto(texto))
        self.assertEqual(len(hash_texto(texto)), 64)
        self.assertNotEqual(hash_texto('ñ'), hash_texto('n'))

    def test_archivo_por_bloques_e_integridad(self):
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = Path(carpeta) / 'datos.bin'
            datos = bytes(range(256)) * 1024
            ruta.write_bytes(datos)
            esperado = hashlib.sha256(datos).hexdigest()
            self.assertEqual(hash_archivo(ruta), esperado)
            self.assertTrue(verificar_archivo(ruta, esperado.upper()))
            ruta.write_bytes(b'X' + datos[1:])
            self.assertFalse(verificar_archivo(ruta, esperado))

    def test_archivo_vacio(self):
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = Path(carpeta) / 'vacio'
            ruta.touch()
            self.assertEqual(hash_archivo(ruta), hash_texto(''))

    def test_hash_invalido(self):
        for valor in ('abc', 'g' * 64, '0' * 63):
            with self.assertRaises(ValueError):
                verificar_archivo('no_necesita_existir', valor)

    def test_archivo_inexistente(self):
        with tempfile.TemporaryDirectory() as carpeta:
            with self.assertRaises(FileNotFoundError):
                hash_archivo(Path(carpeta) / 'ausente')

    def test_avalancha(self):
        self.assertEqual(bits_distintos('igual', 'igual'), 0)
        self.assertGreater(bits_distintos('Hola mundo', 'hola mundo'), 0)



"""Pruebas de cuentas en carpetas temporales; no modifican usuarios reales."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from utils.saveJson import RegistroCuentas, ArchivoCuentasInvalido


class PruebasCuentas(unittest.TestCase):
    def setUp(self):
        self.temporal = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporal.cleanup)
        self.ruta = Path(self.temporal.name) / 'usuarios.json'
        self.cuentas = RegistroCuentas(self.ruta)

    def test_registro_login_y_persistencia(self):
        self.assertEqual(self.cuentas.registrar(' Estudiante ', 'Mi clave 2026!'), 'estudiante')
        otra = RegistroCuentas(self.ruta)
        self.assertTrue(otra.autenticar('ESTUDIANTE', 'Mi clave 2026!'))
        self.assertFalse(otra.autenticar('estudiante', 'clave equivocada'))

    def test_usuario_ausente_no_crea_archivo(self):
        self.assertFalse(self.cuentas.autenticar('ausente', 'Una clave 123'))
        self.assertFalse(self.ruta.exists())

    def test_duplicado_no_sobrescribe(self):
        self.cuentas.registrar('alumno', 'primera-clave')
        previo = self.ruta.read_bytes()
        with self.assertRaises(ValueError):
            self.cuentas.registrar('ALUMNO', 'otra-clave')
        self.assertEqual(previo, self.ruta.read_bytes())

    def test_contrasena_no_se_guarda_y_sales_distintas(self):
        self.cuentas.registrar('alumno1', 'Compartida-secreta')
        self.cuentas.registrar('alumno2', 'Compartida-secreta')
        texto = self.ruta.read_text(encoding='utf-8')
        self.assertNotIn('Compartida-secreta', texto)
        a, b = json.loads(texto)['usuarios'].values()
        self.assertNotEqual(a['sal'], b['sal'])
        self.assertNotEqual(a['derivado'], b['derivado'])

    def test_espacios_en_contrasena_se_conservan(self):
        self.cuentas.registrar('alumno', ' clave con espacios ')
        self.assertTrue(self.cuentas.autenticar('alumno', ' clave con espacios '))
        self.assertFalse(self.cuentas.autenticar('alumno', 'clave con espacios'))

    def test_validacion_campos(self):
        for nombre, clave in [('', '12345678'), ('ab', '12345678'), ('a/b', '12345678'), ('valido', 'corta'), ('valido', 'a' * 1025)]:
            with self.subTest(nombre=nombre), self.assertRaises(ValueError):
                self.cuentas.registrar(nombre, clave)
        self.assertFalse(self.ruta.exists())

    def test_archivo_danado_no_se_reemplaza(self):
        for contenido in ['{invalido', '[]', '{"version":1,"usuarios":{"alumno":{}}}']:
            self.ruta.write_text(contenido, encoding='utf-8')
            with self.assertRaises(ArchivoCuentasInvalido):
                self.cuentas.registrar('nuevo', '12345678')
            self.assertEqual(self.ruta.read_text(encoding='utf-8'), contenido)

    def test_fallo_escritura_preserva_datos(self):
        self.cuentas.registrar('alumno', '12345678')
        previo = self.ruta.read_bytes()
        with patch('utils.saveJson.os.replace', side_effect=OSError('fallo simulado')):
            with self.assertRaises(OSError):
                self.cuentas.registrar('nuevo', '12345678')
        self.assertEqual(self.ruta.read_bytes(), previo)
        self.assertEqual(len(list(self.ruta.parent.iterdir())), 1)



class PruebasInterfaz(unittest.TestCase):
    @patch('builtins.print')
    def test_registro_entrada_y_salida(self, salida):
        import tkinter as tk
        from utils.login_app import Aplicacion
        with tempfile.TemporaryDirectory() as carpeta:
            ventana = tk.Tk()
            ventana.withdraw()
            self.addCleanup(ventana.destroy)
            app = Aplicacion(ventana, RegistroCuentas(Path(carpeta) / 'cuentas.json'))
            app.usuario.insert(0, 'alumno')
            app.clave.insert(0, 'Una clave 2026')
            app.crear_cuenta()
            self.assertEqual(app.clave.get(), '')
            app.clave.insert(0, 'equivocada')
            app.entrar()
            self.assertIsNone(app.usuario_actual)
            app.clave.insert(0, 'Una clave 2026')
            app.entrar()
            self.assertEqual(app.usuario_actual, 'alumno')
            app.salir()
            self.assertIsNone(app.usuario_actual)
            self.assertTrue(app.usuario.winfo_exists())

    def test_laboratorio(self):
        import tkinter as tk
        from utils.login_app import Aplicacion
        ventana = tk.Tk()
        ventana.withdraw()
        self.addCleanup(ventana.destroy)
        app = Aplicacion(ventana)
        app.texto_a.set('abc')
        app.texto_b.set('abc')
        app.comparar()
        self.assertIn('0/256', app.resumen.get('1.0', tk.END))
        self.assertIn(hash_texto('abc'), app.resumen.get('1.0', tk.END))


class PruebasAESAuxiliar(unittest.TestCase):
    def test_cifrar_recuperar(self):
        from utils.secureAES import cifrar_aes, descifrar_aes
        clave = bytes(range(32))
        iv, datos = cifrar_aes('Mensaje con acento: á', clave)
        self.assertEqual(descifrar_aes(iv, datos, clave), 'Mensaje con acento: á')

    def test_clave_invalida(self):
        from utils.secureAES import cifrar_aes
        with self.assertRaises(ValueError):
            cifrar_aes('hola', b'corta')


def main():
    parser = argparse.ArgumentParser(description='Acceso con cuentas y laboratorio Hash')
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument('--pruebas', action='store_true', help='Ejecutar pruebas integradas')
    modo.add_argument('--demo', action='store_true', help='Demostración de hash por consola')
    args = parser.parse_args()
    if args.pruebas:
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(caso)
            for caso in (PruebasHash, PruebasCuentas, PruebasInterfaz, PruebasAESAuxiliar))
        import sys
        class ResultadoLegible(unittest.TextTestResult):
            def getDescription(self, test):
                return test._testMethodName
        resultado = unittest.TextTestRunner(stream=sys.stdout, verbosity=2,
                                             resultclass=ResultadoLegible).run(suite)
        return 0 if resultado.wasSuccessful() else 1
    if args.demo:
        for texto in ('Hola mundo', 'hola mundo'):
            print(f'{texto!r}: {hash_texto(texto)}')
        print('Bits distintos:', bits_distintos('Hola mundo', 'hola mundo'), '/256')
        return 0
    from utils.login_app import main as abrir_interfaz
    abrir_interfaz()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
