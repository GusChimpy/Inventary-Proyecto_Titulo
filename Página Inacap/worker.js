// ============================================================================
// WORKER: API Inventario TI — Las Majadas de Pirque
// Ahora con autenticación real (usuario/contraseña por persona), sesiones
// firmadas y control de roles en el servidor (no solo en el navegador).
// ============================================================================

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 horas

// ---------------------------------------------------------------------------
// Utilidades: hex <-> bytes, base64url, hashing y firma de tokens
// ---------------------------------------------------------------------------
function bytesToHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}
function b64urlEncode(bytesOrStr) {
  const bytes = typeof bytesOrStr === "string" ? new TextEncoder().encode(bytesOrStr) : bytesOrStr;
  let bin = "";
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecodeToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

async function verifyPassword(password, saltHex, expectedHashHex) {
  const { hash } = await hashPassword(password, saltHex);
  // Comparación en tiempo constante básica
  if (hash.length !== expectedHashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
  return diff === 0;
}

async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const body = b64urlEncode(JSON.stringify(payload));
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return body + "." + b64urlEncode(new Uint8Array(sig));
}

async function verifyToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlDecodeToBytes(sig), enc.encode(body));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecodeToBytes(body)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function getBearer(request) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function requireAuth(request, env) {
  const token = getBearer(request);
  if (!token) return null;
  const payload = await verifyToken(token, env.JWT_SECRET);
  if (!payload) return null;

  // No basta con que la firma del token sea válida: si a esa cuenta la
  // desactivaron o le cambiaron el rol después de haber iniciado sesión,
  // eso debe aplicarse de inmediato, no recién cuando el token expire solo.
  try {
    const { results } = await env.DB.prepare("SELECT role, activo FROM usuarios WHERE username = ?").bind(payload.sub).all();
    const user = results[0];
    if (!user || !user.activo) return null;
    payload.role = user.role; // el rol vigente manda, no el que tenía el token al crearse
  } catch (e) {
    return null;
  }
  return payload;
}

function jsonResponse(obj, status, corsHeaders) {
  return new Response(JSON.stringify(obj), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

const SENSIBLES_EQUIPO = ["Contraseña mail", "Clave Windows"];

function enmascararEquipos(equipos) {
  return equipos.map(e => {
    const copia = { ...e };
    SENSIBLES_EQUIPO.forEach(campo => { delete copia[campo]; });
    return copia;
  });
}

// ---------------------------------------------------------------------------
// Auditoría: quién hizo qué y cuándo. Nunca debe tumbar la operación
// principal si falla (por eso el try/catch propio).
// ---------------------------------------------------------------------------
async function registrarAuditoria(env, usuario, rol, accion, detalle) {
  try {
    await env.DB.prepare(
      "INSERT INTO auditoria (fecha, usuario, rol, accion, detalle) VALUES (?, ?, ?, ?, ?)"
    ).bind(new Date().toISOString(), usuario || "?", rol || "?", accion, detalle || "").run();
  } catch (e) {
    // No bloqueamos la operación principal si el log de auditoría falla.
  }
}

// Compara una colección anterior vs la nueva (por ID) y arma un resumen
// legible: creados / editados / eliminados, con hasta 5 IDs de ejemplo.
function diffColeccion(anterioresRaw, nuevos, idKey) {
  const anteriores = anterioresRaw.map(row => JSON.parse(row.datos));
  const mapAnt = new Map(anteriores.map(x => [x[idKey], JSON.stringify(x)]));
  const mapNuevo = new Map(nuevos.map(x => [x[idKey] || x.id, JSON.stringify(x)]));
  const creados = [], editados = [], eliminados = [];
  for (const [id, json] of mapNuevo) {
    if (!mapAnt.has(id)) creados.push(id);
    else if (mapAnt.get(id) !== json) editados.push(id);
  }
  for (const id of mapAnt.keys()) {
    if (!mapNuevo.has(id)) eliminados.push(id);
  }
  const listar = (arr) => arr.slice(0, 5).join(", ") + (arr.length > 5 ? ` y ${arr.length - 5} más` : "");
  const partes = [];
  if (creados.length) partes.push(`${creados.length} creado(s) [${listar(creados)}]`);
  if (editados.length) partes.push(`${editados.length} editado(s) [${listar(editados)}]`);
  if (eliminados.length) partes.push(`${eliminados.length} eliminado(s) [${listar(eliminados)}]`);
  return partes.join(" · ") || "sin cambios detectados";
}

// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (!env.JWT_SECRET) {
      return jsonResponse({ error: "El Worker no tiene configurado JWT_SECRET." }, 500, corsHeaders);
    }

    // --- BOOTSTRAP: crear el primer SuperAdmin (solo si no existe ningún usuario) ---
    if (request.method === "POST" && url.pathname === "/setup") {
      try {
        const { results } = await env.DB.prepare("SELECT COUNT(*) as n FROM usuarios").all();
        if (results[0].n > 0) {
          return jsonResponse({ error: "El sistema ya tiene usuarios. /setup ya no está disponible." }, 403, corsHeaders);
        }
        const { username, password, nombre } = await request.json();
        if (!username || !password) return jsonResponse({ error: "Falta usuario o contraseña." }, 400, corsHeaders);
        const { hash, salt } = await hashPassword(password);
        await env.DB.prepare(
          "INSERT INTO usuarios (username, nombre, password_hash, salt, role, activo, creado) VALUES (?, ?, ?, ?, 'SuperAdmin', 1, ?)"
        ).bind(username, nombre || username, hash, salt, new Date().toISOString()).run();
        await registrarAuditoria(env, username, "SuperAdmin", "setup_inicial", "Creación del primer usuario SuperAdmin del sistema");
        return jsonResponse({ success: true, message: "SuperAdmin creado. Ya puedes iniciar sesión." }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message }, 500, corsHeaders);
      }
    }

    // --- LOGIN ---
    if (request.method === "POST" && url.pathname === "/login") {
      try {
        const { username, password } = await request.json();
        if (!username || !password) return jsonResponse({ error: "Falta usuario o contraseña." }, 400, corsHeaders);

        const { results } = await env.DB.prepare("SELECT * FROM usuarios WHERE username = ?").bind(username).all();
        const user = results[0];
        if (!user || !user.activo) {
          return jsonResponse({ error: "Usuario o contraseña incorrectos." }, 401, corsHeaders);
        }

        // Protección contra fuerza bruta: si ya falló varias veces seguidas, se
        // bloquea la cuenta un rato antes de dejar intentar de nuevo.
        if (user.bloqueado_hasta && Date.now() < user.bloqueado_hasta) {
          const minutos = Math.ceil((user.bloqueado_hasta - Date.now()) / 60000);
          return jsonResponse({ error: `Demasiados intentos fallidos. Intenta de nuevo en ${minutos} minuto(s).` }, 429, corsHeaders);
        }

        const ok = await verifyPassword(password, user.salt, user.password_hash);
        if (!ok) {
          const intentos = (user.intentos_fallidos || 0) + 1;
          const bloqueoMs = 15 * 60 * 1000; // 15 minutos
          if (intentos >= 5) {
            await env.DB.prepare("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = ? WHERE username = ?")
              .bind(Date.now() + bloqueoMs, username).run();
            await registrarAuditoria(env, username, user.role, "login_bloqueado", `Cuenta bloqueada 15 minutos tras ${intentos} intentos fallidos seguidos`);
            return jsonResponse({ error: "Demasiados intentos fallidos. Cuenta bloqueada 15 minutos." }, 429, corsHeaders);
          }
          await env.DB.prepare("UPDATE usuarios SET intentos_fallidos = ? WHERE username = ?").bind(intentos, username).run();
          return jsonResponse({ error: "Usuario o contraseña incorrectos." }, 401, corsHeaders);
        }

        // Login correcto: limpiar contador de intentos fallidos.
        if (user.intentos_fallidos || user.bloqueado_hasta) {
          await env.DB.prepare("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE username = ?").bind(username).run();
        }

        const exp = Date.now() + TOKEN_TTL_MS;
        const token = await signToken({ sub: user.username, role: user.role, nombre: user.nombre, exp }, env.JWT_SECRET);
        await registrarAuditoria(env, user.username, user.role, "login", "Inicio de sesión");
        return jsonResponse({ token, username: user.username, nombre: user.nombre, role: user.role, exp }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message }, 500, corsHeaders);
      }
    }

    // --- DESCARGAR DATOS (PÚBLICO: se puede ver la página sin iniciar sesión).
    // Si hay una sesión válida se entregan también los campos sensibles
    // (contraseñas de mail, claves de Windows); sin sesión, esos campos
    // se eliminan de la respuesta antes de enviarla. ---
    if (request.method === "GET" && url.pathname === "/") {
      try {
        const sesionLectura = await requireAuth(request, env); // puede ser null (público)

        const { results: rawEq } = await env.DB.prepare("SELECT datos FROM equipos").all();
        let equipos = rawEq.map(row => JSON.parse(row.datos));
        if (!sesionLectura) equipos = enmascararEquipos(equipos);

        const { results: rawAsig } = await env.DB.prepare("SELECT datos FROM asignaciones").all();
        const asignaciones = rawAsig.map(row => JSON.parse(row.datos));

        const { results: rawMant } = await env.DB.prepare("SELECT datos FROM mantenciones").all();
        const mantenciones = rawMant.map(row => JSON.parse(row.datos));

        let configCamposExtra = {};
        try {
          const { results: rawConf } = await env.DB.prepare("SELECT datos FROM configuracion WHERE id = 'campos'").all();
          if (rawConf.length > 0) configCamposExtra = JSON.parse(rawConf[0].datos);
        } catch (e) {}

        return jsonResponse({ equipos, asignaciones, mantenciones, configCamposExtra }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message }, 500, corsHeaders);
      }
    }

    // A partir de aquí, TODO requiere una sesión válida (crear/editar datos,
    // gestión de usuarios, ajustes del sistema).
    const session = await requireAuth(request, env);
    if (!session) {
      return jsonResponse({ error: "Debes iniciar sesión para realizar esta acción." }, 401, corsHeaders);
    }
    const isSuperAdmin = session.role === "SuperAdmin";

    // --- GESTIÓN DE USUARIOS (SOLO SUPERADMIN) ---
    if (url.pathname === "/usuarios" && request.method === "GET") {
      if (!isSuperAdmin) return jsonResponse({ error: "No tienes permisos para esta acción." }, 403, corsHeaders);
      const { results } = await env.DB.prepare("SELECT username, nombre, role, activo FROM usuarios ORDER BY username").all();
      return jsonResponse({ usuarios: results }, 200, corsHeaders);
    }

    // --- AUDITORÍA (SOLO SUPERADMIN) ---
    if (url.pathname === "/auditoria" && request.method === "GET") {
      if (!isSuperAdmin) return jsonResponse({ error: "No tienes permisos para esta acción." }, 403, corsHeaders);
      const { results } = await env.DB.prepare(
        "SELECT fecha, usuario, rol, accion, detalle FROM auditoria ORDER BY id DESC LIMIT 300"
      ).all();
      return jsonResponse({ auditoria: results }, 200, corsHeaders);
    }

    if (url.pathname === "/usuarios/crear" && request.method === "POST") {
      if (!isSuperAdmin) return jsonResponse({ error: "No tienes permisos para esta acción." }, 403, corsHeaders);
      try {
        const { username, nombre, role, password } = await request.json();
        if (!username || !password) return jsonResponse({ error: "Falta usuario o contraseña." }, 400, corsHeaders);
        const rolFinal = role === "SuperAdmin" ? "SuperAdmin" : "Tecnico";
        const { hash, salt } = await hashPassword(password);
        await env.DB.prepare(
          "INSERT INTO usuarios (username, nombre, password_hash, salt, role, activo, creado) VALUES (?, ?, ?, ?, ?, 1, ?)"
        ).bind(username, nombre || username, hash, salt, rolFinal, new Date().toISOString()).run();
        await registrarAuditoria(env, session.sub, session.role, "crear_usuario", `Creó al usuario "${username}" (rol ${rolFinal})`);
        return jsonResponse({ success: true }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message.includes("UNIQUE") ? "Ese nombre de usuario ya existe." : e.message }, 400, corsHeaders);
      }
    }

    if (url.pathname === "/usuarios/editar" && request.method === "POST") {
      if (!isSuperAdmin) return jsonResponse({ error: "No tienes permisos para esta acción." }, 403, corsHeaders);
      try {
        const { username, nombre, role, activo, password } = await request.json();
        if (!username) return jsonResponse({ error: "Falta el usuario a editar." }, 400, corsHeaders);
        const rolFinal = role === "SuperAdmin" ? "SuperAdmin" : "Tecnico";
        if (password) {
          const { hash, salt } = await hashPassword(password);
          await env.DB.prepare("UPDATE usuarios SET nombre=?, role=?, activo=?, password_hash=?, salt=? WHERE username=?")
            .bind(nombre || username, rolFinal, activo ? 1 : 0, hash, salt, username).run();
        } else {
          await env.DB.prepare("UPDATE usuarios SET nombre=?, role=?, activo=? WHERE username=?")
            .bind(nombre || username, rolFinal, activo ? 1 : 0, username).run();
        }
        await registrarAuditoria(env, session.sub, session.role, "editar_usuario", `Editó al usuario "${username}" (rol ${rolFinal}${activo ? "" : ", desactivado"}${password ? ", contraseña cambiada" : ""})`);
        return jsonResponse({ success: true }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message }, 400, corsHeaders);
      }
    }

    if (url.pathname === "/usuarios/eliminar" && request.method === "POST") {
      if (!isSuperAdmin) return jsonResponse({ error: "No tienes permisos para esta acción." }, 403, corsHeaders);
      try {
        const { username } = await request.json();
        if (username === session.sub) return jsonResponse({ error: "No puedes eliminar tu propio usuario." }, 400, corsHeaders);
        await env.DB.prepare("DELETE FROM usuarios WHERE username = ?").bind(username).run();
        await registrarAuditoria(env, session.sub, session.role, "eliminar_usuario", `Eliminó al usuario "${username}"`);
        return jsonResponse({ success: true }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message }, 400, corsHeaders);
      }
    }

    // --- SUBIR DATOS (FLEXIBLE) ---
    if (request.method === "POST" && url.pathname === "/sync") {
      try {
        const data = await request.json();

        if (data.equipos && data.equipos.length > 0) {
          // Salvaguarda del lado del servidor: un Técnico no puede hacer
          // desaparecer equipos existentes de la base de datos (solo el
          // SuperAdmin puede borrar equipos de forma permanente).
          const { results: actuales } = await env.DB.prepare("SELECT id, datos FROM equipos").all();
          if (!isSuperAdmin) {
            const idsActuales = new Set(actuales.map(r => r.id));
            const idsNuevos = new Set(data.equipos.map(e => e.ID || e.id));
            const faltantes = [...idsActuales].filter(id => !idsNuevos.has(id));
            if (faltantes.length > 0) {
              return jsonResponse(
                { error: "Tu cuenta (Técnico) no puede eliminar equipos de forma permanente. Usa 'Dar de baja'." },
                403,
                corsHeaders
              );
            }
          }
          const resumenEquipos = diffColeccion(actuales, data.equipos, "ID");
          await env.DB.prepare("DELETE FROM equipos").run();
          const stmt = env.DB.prepare("INSERT INTO equipos (id, datos) VALUES (?, ?)");
          const batch = data.equipos.map(e => stmt.bind(e.ID || e.id || "EQ-" + Math.random(), JSON.stringify(e)));
          await env.DB.batch(batch);
          await registrarAuditoria(env, session.sub, session.role, "sync_equipos", resumenEquipos);
        }

        if (data.asignaciones && data.asignaciones.length > 0) {
          const { results: actuales } = await env.DB.prepare("SELECT COUNT(*) as n FROM asignaciones").all();
          if (!isSuperAdmin) {
            if (data.asignaciones.length < actuales[0].n) {
              return jsonResponse(
                { error: "Tu cuenta (Técnico) no puede eliminar registros del historial de asignaciones." },
                403,
                corsHeaders
              );
            }
          }
          await env.DB.prepare("DELETE FROM asignaciones").run();
          const stmt = env.DB.prepare("INSERT INTO asignaciones (id, datos) VALUES (?, ?)");
          const batch = data.asignaciones.map((a, i) => stmt.bind("ASIG-" + i, JSON.stringify(a)));
          await env.DB.batch(batch);
          const delta = data.asignaciones.length - actuales[0].n;
          await registrarAuditoria(env, session.sub, session.role, "sync_asignaciones", `${actuales[0].n} → ${data.asignaciones.length} registros (${delta >= 0 ? "+" : ""}${delta})`);
        }

        if (data.mantenciones && data.mantenciones.length > 0) {
          const { results: actuales } = await env.DB.prepare("SELECT COUNT(*) as n FROM mantenciones").all();
          if (!isSuperAdmin) {
            if (data.mantenciones.length < actuales[0].n) {
              return jsonResponse(
                { error: "Tu cuenta (Técnico) no puede eliminar registros del historial de mantenciones." },
                403,
                corsHeaders
              );
            }
          }
          await env.DB.prepare("DELETE FROM mantenciones").run();
          const stmt = env.DB.prepare("INSERT INTO mantenciones (id, datos) VALUES (?, ?)");
          const batch = data.mantenciones.map((m, i) => stmt.bind("MANT-" + i, JSON.stringify(m)));
          await env.DB.batch(batch);
          const delta = data.mantenciones.length - actuales[0].n;
          await registrarAuditoria(env, session.sub, session.role, "sync_mantenciones", `${actuales[0].n} → ${data.mantenciones.length} registros (${delta >= 0 ? "+" : ""}${delta})`);
        }

        if (data.configCamposExtra) {
          // Solo SuperAdmin puede cambiar la configuración de columnas/campos.
          if (!isSuperAdmin) {
            return jsonResponse({ error: "Solo un SuperAdmin puede modificar la configuración del sistema." }, 403, corsHeaders);
          }
          await env.DB.prepare("DELETE FROM configuracion WHERE id = 'campos'").run();
          await env.DB.prepare("INSERT INTO configuracion (id, datos) VALUES (?, ?)").bind("campos", JSON.stringify(data.configCamposExtra)).run();
          await registrarAuditoria(env, session.sub, session.role, "sync_configuracion", "Actualizó los campos personalizados de los formularios");
        }

        return jsonResponse({ success: true, message: "Sincronizado" }, 200, corsHeaders);
      } catch (e) {
        return jsonResponse({ error: e.message }, 500, corsHeaders);
      }
    }

    return jsonResponse({ error: "Ruta no encontrada" }, 404, corsHeaders);
  },
};
