const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const https = require("https");
const jwt = require("jsonwebtoken");
const { WebSocketServer } = require("ws");
const { Bonjour } = require("bonjour-service");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const KEYWORD = process.env.RC_KEYWORD || "aboba";
// Секрет подписи JWT. Обязательно задайте свой в .env перед деплоем.
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
if (!process.env.JWT_SECRET) {
  console.warn("WARN: JWT_SECRET not set, using insecure default — set it in .env");
}
// Опциональный TLS для работы через интернет (wss). Задайте RC_CERT/RC_KEY —
// пути к PEM-файлам сертификата и ключа. Если пусто — обычный http/ws.
const TLS_CERT = process.env.RC_CERT || "";
const TLS_KEY = process.env.RC_KEY || "";

app.use(cors());
app.use(express.json({ limit: "60mb" })); // uploads и скриншоты

// ---------------------------------------------------------------------------
// Состояние
// ---------------------------------------------------------------------------

// id агента -> { id, name, socket, ip, connectedAt }
const agents = new Map();
// ticket -> { res, timer, agentId } — ожидающие ответы на команды
const pending = new Map();

// ---------------------------------------------------------------------------
// API (все под /api, чтобы авторизация покрывала одним middleware)
// ---------------------------------------------------------------------------

// Вход по ключевому слову. Публичный (не закрыт requireAuth).
app.post("/api/login", (req, res) => {
  const { keyword } = req.body || {};
  if (keyword !== KEYWORD) {
    return res.status(401).json({ error: "wrong keyword" });
  }
  const token = jwt.sign({ scope: "panel" }, JWT_SECRET, { expiresIn: "24h" });
  res.json({ ok: true, token });
});

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).json({ error: "unauthorized" });
  }
}

// Оборачиваем API авторизацией, кроме входа и health (health публичный —
// по нему агент находит сервер в локальной сети).
app.use("/api", (req, res, next) => {
  if (req.path === "/login" || req.path === "/health") return next();
  return requireAuth(req, res, next);
});

app.get("/api/health", (req, res) => {
  res.json({ status: "online", agents: agents.size, auth: !!process.env.JWT_SECRET });
});

app.get("/api/agents", (req, res) => {
  const list = [];
  for (const [id, pc] of agents) {
    list.push({
      id,
      name: pc.name,
      ip: pc.ip,
      connectedAt: pc.connectedAt,
      lastSeen: pc.lastSeen || pc.connectedAt,
    });
  }
  list.sort((a, b) => a.name.localeCompare(b.name));
  res.json(list);
});

// Команда агенту. Отвечает, только когда агент реально выполнил команду
// (или истёк таймаут) — без хрупкого polling с фиксированной задержкой.
app.post("/api/command", (req, res) => {
  const { target, action } = req.body || {};
  if (!target || !action) return res.status(400).json({ error: "target and action required" });

  const pc = agents.get(target);
  if (!pc) return res.status(404).json({ error: "PC offline" });

  const ticket = crypto.randomUUID();
  const timeout = setTimeout(() => {
    pending.delete(ticket);
    if (!res.headersSent) {
      res.status(504).json({ ok: false, error: "command timeout" });
    }
  }, 35000);

  pending.set(ticket, { res, timer: timeout, agentId: target });

  try {
    pc.socket.send(
      JSON.stringify({ type: "command", ticket, ...req.body })
    );
  } catch (e) {
    pending.delete(ticket);
    clearTimeout(timeout);
    return res.status(500).json({ ok: false, error: "send failed" });
  }
});

// ---------------------------------------------------------------------------
// Статика панели (опционально)
// Если dashboard собран (dashboard/dist) — отдаём сайт с этого же сервера.
// ---------------------------------------------------------------------------

const DASHBOARD_DIST = path.join(__dirname, "..", "dashboard", "dist");
if (fs.existsSync(DASHBOARD_DIST)) {
  app.use(express.static(DASHBOARD_DIST));
  // SPA-fallback: любые не-API пути отдают index.html
  app.use((req, res, next) => {
    if (req.path.startsWith("/api/") || req.path.startsWith("/ws")) return next();
    res.sendFile(path.join(DASHBOARD_DIST, "index.html"));
  });
  console.log("SERVING PANEL from", DASHBOARD_DIST);
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

let server;
if (TLS_CERT && TLS_KEY) {
  server = https.createServer(
    { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) },
    app
  );
} else {
  server = require("http").createServer(app);
}
server.listen(PORT, "0.0.0.0", () => {
  console.log("SERVER START " + PORT + (TLS_CERT && TLS_KEY ? " (https/wss)" : " (http/ws)"));
});

const wss = new WebSocketServer({ server, maxPayload: 64 * 1024 * 1024 });

wss.on("connection", (socket, req) => {
  console.log("NEW CONNECTION");
  socket.isAlive = true;

  socket.on("pong", () => {
    socket.isAlive = true;
  });

  socket.on("message", (buffer) => {
    let msg;
    try {
      msg = JSON.parse(buffer.toString());
    } catch (e) {
      return;
    }

    // Регистрация агента
    if (msg.type === "register") {
      const ip = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
      const existing = agents.get(msg.id);
      if (existing && existing.socket !== socket && existing.socket.readyState === 1) {
        existing.socket.close();
      }
      agents.set(msg.id, { id: msg.id, name: msg.name, socket, ip, connectedAt: Date.now() });
      console.log("PC ONLINE", msg.name, ip);
    }

    // Ответ на команду — связываем по ticket
    if (msg.type === "response") {
      const p = pending.get(msg.ticket);
      if (p) {
        pending.delete(msg.ticket);
        clearTimeout(p.timer);
        p.res.json({ ok: msg.ok, data: msg.data, error: msg.error });
      }
    }
  });

  socket.on("error", (e) => console.log("socket error", e.message));

  socket.on("close", () => {
    // Удаляем все агенты на этом сокете и отклоняем их ожидающие команды
    const lost = new Set();
    for (const [id, pc] of agents) {
      if (pc.socket === socket) {
        lost.add(id);
        agents.delete(id);
        console.log("PC OFFLINE", pc.name);
      }
    }
    for (const [ticket, p] of pending) {
      if (lost.has(p.agentId)) {
        pending.delete(ticket);
        clearTimeout(p.timer);
        if (!p.res.headersSent) p.res.json({ ok: false, error: "PC offline" });
      }
    }
  });
});

// Keepalive: пингуем каждые 10s, мёртвые сокеты отрубаем
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 10000);

wss.on("close", () => clearInterval(heartbeat));

// ---------------------------------------------------------------------------
// mDNS
// ---------------------------------------------------------------------------

// mDNS для поиска сервера по локальной сети. На хостинге/в интернете не нужен
// и не должен ронять сервер, если мультикаст недоступен.
try {
  const bonjour = new Bonjour();
  bonjour.publish({
    name: "REMOTE-CONTROL",
    type: "remote-control",
    port: PORT,
  });
  console.log("MDNS START");
} catch (e) {
  console.log("MDNS skipped:", e.message);
}
console.log("AUTH: keyword login enabled (POST /api/login)");
