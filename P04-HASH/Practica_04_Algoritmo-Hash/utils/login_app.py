"""Interfaz propia de cuentas y laboratorio SHA-256. Abrir mediante main.py."""
import tkinter as tk
from tkinter import ttk
from .saveJson import RegistroCuentas, normalizar_usuario
from .secureAES import hash_texto, bits_distintos


class Aplicacion:
    def __init__(self, ventana, registro=None):
        self.ventana = ventana
        self.registro = registro if registro is not None else RegistroCuentas()
        self.usuario_actual = None
        ventana.title('Práctica 04 | Acceso y laboratorio Hash | Ulises Zarate')
        ventana.geometry('860x650')
        ventana.minsize(760, 600)
        ventana.configure(bg='#edf2f7')
        estilo = ttk.Style(ventana)
        estilo.theme_use('clam')
        estilo.configure('TFrame', background='#edf2f7')
        estilo.configure('TLabel', background='#edf2f7', font=('Segoe UI', 11))
        estilo.configure('Titulo.TLabel', font=('Segoe UI', 23, 'bold'), foreground='#163b52')
        estilo.configure('TButton', font=('Segoe UI', 11), padding=(12, 8))
        estilo.configure('TNotebook.Tab', padding=(16, 9), font=('Segoe UI', 11))
        marco = ttk.Frame(ventana, padding=28)
        marco.pack(fill='both', expand=True)
        ttk.Label(marco, text='Acceso seguro · Laboratorio Hash', style='Titulo.TLabel').pack(anchor='w')
        ttk.Label(marco, text='Ulises Zarate Concha  /  Seguridad Informática  /  Práctica 04').pack(anchor='w', pady=(5, 20))
        self.pestanas = ttk.Notebook(marco)
        self.pestanas.pack(fill='both', expand=True)
        self.acceso = ttk.Frame(self.pestanas, padding=24)
        self.lab = ttk.Frame(self.pestanas, padding=24)
        self.pestanas.add(self.acceso, text='Cuenta y sesión')
        self.pestanas.add(self.lab, text='Explorar SHA-256')
        self.dibujar_acceso()
        self.dibujar_laboratorio()

    def dibujar_acceso(self):
        for elemento in self.acceso.winfo_children():
            elemento.destroy()
        ttk.Label(self.acceso, text='Crea tu cuenta o inicia sesión', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        ttk.Label(self.acceso, text='Las cuentas se conservan en usuarios.json, junto a main.py.').pack(anchor='w', pady=(5, 16))
        ttk.Label(self.acceso, text='Usuario · de 3 a 30 caracteres').pack(anchor='w')
        self.usuario = ttk.Entry(self.acceso, font=('Segoe UI', 12), width=45)
        self.usuario.pack(anchor='w', fill='x', pady=(4, 12))
        ttk.Label(self.acceso, text='Contraseña · mínimo 8 caracteres').pack(anchor='w')
        self.clave = ttk.Entry(self.acceso, show='•', font=('Segoe UI', 12), width=45)
        self.clave.pack(anchor='w', fill='x', pady=(4, 16))
        botones = ttk.Frame(self.acceso)
        botones.pack(anchor='w')
        ttk.Button(botones, text='Entrar', command=self.entrar).pack(side='left', padx=(0, 10))
        ttk.Button(botones, text='Crear cuenta', command=self.crear_cuenta).pack(side='left')
        self.estado = ttk.Label(self.acceso, text='No hay una cuenta predeterminada. Regístrate para comenzar.', wraplength=700)
        self.estado.pack(anchor='w', pady=(20, 10))
        ttk.Label(self.acceso, text='Protección: PBKDF2-HMAC-SHA256 + sal aleatoria por cuenta.\nLa contraseña original no se guarda.', foreground='#41606e').pack(anchor='w', pady=8)
        self.clave.bind('<Return>', lambda evento: self.entrar())

    def crear_cuenta(self):
        try:
            nombre = self.registro.registrar(self.usuario.get(), self.clave.get())
        except (OSError, ValueError) as error:
            self.estado.config(text=str(error), foreground='#a12a34')
            return
        self.clave.delete(0, tk.END)
        self.estado.config(text=f'Cuenta {nombre} creada. Introduce tu contraseña para entrar.', foreground='#176e4b')
        print('Registro completado; contraseña no almacenada en texto plano.', flush=True)

    def entrar(self):
        try:
            correcto = self.registro.autenticar(self.usuario.get(), self.clave.get())
        except (OSError, ValueError) as error:
            self.estado.config(text=str(error), foreground='#a12a34')
            return
        if not correcto:
            self.estado.config(text='Usuario o contraseña incorrectos.', foreground='#a12a34')
            self.clave.delete(0, tk.END)
            return
        self.usuario_actual = normalizar_usuario(self.usuario.get())
        self.clave.delete(0, tk.END)
        for elemento in self.acceso.winfo_children():
            elemento.destroy()
        ttk.Label(self.acceso, text=f'Bienvenido, {self.usuario_actual}', font=('Segoe UI', 20, 'bold')).pack(anchor='w', pady=(25, 12))
        ttk.Label(self.acceso, text='Sesión iniciada correctamente.\nExplora la segunda pestaña para comparar resúmenes SHA-256.').pack(anchor='w', pady=15)
        ttk.Button(self.acceso, text='Cerrar sesión', command=self.salir).pack(anchor='w', pady=15)
        print('Inicio de sesión correcto.', flush=True)

    def salir(self):
        self.usuario_actual = None
        self.dibujar_acceso()
        print('Sesión cerrada.', flush=True)

    def dibujar_laboratorio(self):
        ttk.Label(self.lab, text='Un pequeño cambio, otro resumen', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        self.texto_a = tk.StringVar(value='Hola mundo')
        self.texto_b = tk.StringVar(value='hola mundo')
        for titulo, variable in [('Texto A', self.texto_a), ('Texto B', self.texto_b)]:
            ttk.Label(self.lab, text=titulo).pack(anchor='w', pady=(12, 4))
            ttk.Entry(self.lab, textvariable=variable, font=('Segoe UI', 12)).pack(fill='x')
        ttk.Button(self.lab, text='Calcular y comparar', command=self.comparar).pack(anchor='w', pady=16)
        self.resumen = tk.Text(self.lab, height=7, font=('Consolas', 10), wrap='char', bg='#163b52', fg='white', relief='flat', padx=12, pady=12)
        self.resumen.pack(fill='x')
        self.resumen.config(state='disabled')
        ttk.Label(self.lab, text='SHA-256 simple se usa aquí para observar hashes de texto.\nLas contraseñas usan PBKDF2, que añade sal e iteraciones.', foreground='#41606e').pack(anchor='w', pady=12)
        self.comparar()

    def comparar(self):
        a, b = self.texto_a.get(), self.texto_b.get()
        bits = bits_distintos(a, b)
        self.resumen.config(state='normal')
        self.resumen.delete('1.0', tk.END)
        self.resumen.insert('1.0', f'SHA-256 A:\n{hash_texto(a)}\nSHA-256 B:\n{hash_texto(b)}\nBits diferentes: {bits}/256 ({bits / 256:.2%})')
        self.resumen.config(state='disabled')


def main():
    ventana = tk.Tk()
    Aplicacion(ventana)
    ventana.mainloop()


if __name__ == '__main__':
    main()
