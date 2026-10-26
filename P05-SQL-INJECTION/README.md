# Práctica SQL Injection: versión segura

La versión vulnerable construía una consulta concatenando las entradas del formulario. Una contraseña como `' OR '1'='1` concedía acceso con el usuario inexistente `nadie`.

Esta versión ejecuta `SELECT * FROM usuarios WHERE username = ?` con `[usuario]` como parámetro separado, y verifica la contraseña mediante scrypt con salt. No incluye endpoint vulnerable. Solo escucha en `127.0.0.1:3102` y crea una base SQLite local independiente; la base y node_modules están excluidos de Git.

## Ejecutar

Requisitos usados: Node.js 24.11.1 y npm 11.3.0.

```powershell
cd P05-SQL-INJECTION
npm ci
npm start
```

Abrir http://127.0.0.1:3102. Cuenta ficticia de laboratorio: `admin` / `12345`. Detener con Ctrl+C.

## Verificar

Con el servidor anterior detenido, ejecutar `npm test`. El test arranca el servidor, repite los 11 casos documentados y lo detiene. Las credenciales válidas deben conceder acceso; las inválidas y todas las entradas de inyección deben denegarlo.

En `evidencias/` se incluyen capturas del formulario antes y después, y el registro de las 22 ejecuciones de navegador. Las contraseñas del registro son exclusivamente datos ficticios o payloads de prueba. El campo contraseña se oculta en las capturas de la versión segura.

El login demuestra la verificación de credenciales. No implementa una sesión ni autorización de recursos y no se presenta como un sistema de autenticación listo para producción.
