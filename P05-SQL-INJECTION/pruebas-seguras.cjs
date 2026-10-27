const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
const casos = require('./evidencias/resultados-formulario.json').filter(c => c.modo === 'corregida');
const base = 'http://127.0.0.1:3102';
(async () => {
  let ocupado = false;
  try { await fetch(base, {signal: AbortSignal.timeout(500)}); ocupado = true; } catch {}
  if (ocupado) throw new Error('Detén el servidor del puerto 3102 antes de ejecutar npm test.');
  const servidor = spawn(process.execPath, ['server.js'], {cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe']});
  let log = '';
  servidor.stdout.on('data', b => { log += b; });
  servidor.stderr.on('data', b => { log += b; });
  try {
    let listo = false;
    for (let intento = 0; intento < 50; intento++) {
      if (servidor.exitCode !== null) throw new Error(log);
      try { const r = await fetch(base, {signal: AbortSignal.timeout(500)}); listo = r.ok; } catch {}
      if (listo) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.ok(listo, 'El servidor debe iniciar: ' + log);
    for (const caso of casos) {
      const r = await fetch(base + '/login', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(caso.entrada)});
      assert.equal(r.status, 200, 'Estado HTTP caso ' + caso.id);
      const body = await r.json();
      assert.equal(body.mensaje, caso.resultado, 'Resultado caso ' + caso.id);
      console.log('PASS ' + caso.id + ': ' + body.mensaje);
    }
  } finally { servidor.kill(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
