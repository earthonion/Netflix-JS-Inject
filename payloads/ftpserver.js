// ===== Configuración =====
const FTP = {
  SERVER_IP: null,
  CTRL_PORT: 1337,      // deseado
  ROOT_PATH: "/",
  CHUNK: 8192,
  DEBUG: true
};

function dbg(msg) { try { logger.log("[FTP] " + msg); } catch (_) {} }
function notify(msg) { try { send_notification(msg); } catch (_) {} }

// ===== Extiende SYSCALL con números del payload Lua =====
// Si ya existen en tu objeto SYSCALL, estos complementan lo faltante.
if (!globalThis.SYSCALL) globalThis.SYSCALL = {};
Object.assign(SYSCALL, {
  // ya presentes en tu exploit:
  read: SYSCALL.read ?? 0x3n,
  write: SYSCALL.write ?? 0x4n,
  open: SYSCALL.open ?? 0x5n,
  close: SYSCALL.close ?? 0x6n,
  getsockname: SYSCALL.getsockname ?? 0x20n,
  accept: SYSCALL.accept ?? 0x1en,
  socket: SYSCALL.socket ?? 0x61n,
  connect: SYSCALL.connect ?? 0x62n,
  bind: SYSCALL.bind ?? 0x68n,
  setsockopt: SYSCALL.setsockopt ?? 0x69n,
  listen: SYSCALL.listen ?? 0x6an,
  netgetiflist: SYSCALL.netgetiflist ?? 0x7dn,
  // añadidos de Lua:
  stat: SYSCALL.stat ?? 0xBCn,        // 188
  getdents: SYSCALL.getdents ?? 0x110n, // 272
  mkdir: SYSCALL.mkdir ?? 0x88n,      // 136
  rmdir: SYSCALL.rmdir ?? 0x89n,      // 137
  rename: SYSCALL.rename ?? 0x80n,    // 128
  unlink: SYSCALL.unlink ?? 0xAn,     // 10
  lseek: SYSCALL.lseek ?? 0x1DEn      // 478
});

// ===== Constantes =====
const AF_INET = 2n;
const SOCK_STREAM = 1n;
const SOL_SOCKET = 0xffffn;
const SO_REUSEADDR = 4n;
const O_RDONLY = 0n, O_RDWR = 2n, O_CREAT = 0x100n, O_TRUNC = 0x1000n, O_APPEND = 0x2000n;

// ===== Helpers =====
function htons(n) { return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF); }
function joinPath(a, b) { return a.endsWith("/") ? a + b : a + "/" + b; }
function dirname(p) { if (p === "/") return "/"; const parts = p.split("/").filter(Boolean); parts.pop(); return parts.length ? "/" + parts.join("/") : "/"; }
function normalizePath(root, input, curPath) {
  const sep = "/";
  let raw;
  if (!input || input === "/") raw = root;
  else if (input.startsWith(sep)) raw = input;
  else raw = curPath === "/" ? joinPath(root, input) : joinPath(curPath, input);
  const parts = raw.split("/").filter(Boolean);
  const out = [];
  for (const p of parts) { if (p === ".") continue; if (p === "..") { if (out.length) out.pop(); continue; } out.push(p); }
  const normalized = sep + out.join("/");
  const rootNorm = root === "/" ? "/" : root;
  if (!normalized.startsWith(rootNorm)) return rootNorm;
  return normalized;
}
const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

// ===== Syscalls de red =====
function create_tcp_server_force(portWanted) {
  const sockaddr = malloc(16);
  const opt = malloc(4);
  write32_uncompressed(opt, 1);

  const fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
  if (Number(fd) < 0) throw new Error("socket() falló");

  // Intento 1: puerto deseado
  write8_uncompressed(sockaddr + 1n, AF_INET);
  write16_uncompressed(sockaddr + 2n, htons(portWanted));
  write32_uncompressed(sockaddr + 4n, 0); // INADDR_ANY
  syscall(SYSCALL.setsockopt, fd, SOL_SOCKET, SO_REUSEADDR, opt, 4n);

  let br = syscall(SYSCALL.bind, fd, sockaddr, 16n);
  if (Number(br) < 0) {
    dbg(`bind(${portWanted}) falló, reintentando con puerto 0`);
    // Intento 2: puerto aleatorio
    write16_uncompressed(sockaddr + 2n, 0);
    br = syscall(SYSCALL.bind, fd, sockaddr, 16n);
    if (Number(br) < 0) { syscall(SYSCALL.close, fd); throw new Error("bind() falló"); }
  }

  const lr = syscall(SYSCALL.listen, fd, 128n);
  if (Number(lr) < 0) { syscall(SYSCALL.close, fd); throw new Error("listen() falló"); }

  return { fd, sockaddr };
}

function getsockname(fd) {
  const addr = malloc(16);
  const lenp = malloc(8);
  write32_uncompressed(lenp, 16);
  syscall(SYSCALL.getsockname, fd, addr, lenp);
  const port_be = read16_uncompressed(addr + 2n);
  const p = Number(((port_be & 0xFFn) << 8n) | ((port_be >> 8n) & 0xFFn));
  return { addr, port: p };
}

function accept_blocking(serverFd) {
  const addr = malloc(16);
  const lenp = malloc(8);
  write32_uncompressed(lenp, 16);
  const cfd = syscall(SYSCALL.accept, serverFd, addr, lenp);
  return Number(cfd);
}

function tcp_connect(host, port) {
  const saddr = malloc(16);
  const cfd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
  if (Number(cfd) < 0) throw new Error("socket() connect falló");

  const [a,b,c,d] = host.split(".").map(x => Number(x));
  const ip32 = (a << 24) | (b << 16) | (c << 8) | d;

  write8_uncompressed(saddr + 1n, AF_INET);
  write16_uncompressed(saddr + 2n, htons(port));
  write32_uncompressed(saddr + 4n, ip32);

  const rr = syscall(SYSCALL.connect, cfd, saddr, 16n);
  if (Number(rr) < 0) { syscall(SYSCALL.close, cfd); throw new Error("connect() falló"); }
  return { fd: cfd, sockaddr: saddr };
}

// ===== FS =====
function open_read(path) { const p = alloc_string(path); const fd = syscall(SYSCALL.open, p, O_RDONLY); return Number(fd); }
function open_write(path, { create, append, truncate }) {
  let flags = O_RDWR;
  if (create) flags |= O_CREAT;
  if (append) flags |= O_APPEND;
  if (truncate) flags |= O_TRUNC;
  const p = alloc_string(path);
  const fd = syscall(SYSCALL.open, p, flags);
  return Number(fd);
}
function close_fd(fd) { syscall(SYSCALL.close, BigInt(fd)); }
function read_fd(fd, bufAddr, len) { const r = syscall(SYSCALL.read, BigInt(fd), bufAddr, BigInt(len)); return Number(r); }
function write_fd(fd, bufAddr, len) { const r = syscall(SYSCALL.write, BigInt(fd), bufAddr, BigInt(len)); return Number(r); }

function stat_path(path) {
  const st = malloc(120);
  const p = alloc_string(path);
  const ret = syscall(SYSCALL.stat, p, st);
  if (Number(ret) < 0) return null;
  const mode = Number(read16_uncompressed(st + 8n));
  const size = Number(read32_uncompressed(st + 72n)) | (Number(read32_uncompressed(st + 76n)) << 32);
  return { st, mode, size };
}
function is_dir(mode) { return (mode & parseInt("040000", 8)) === parseInt("040000", 8); }
function is_reg(mode) { return (mode & parseInt("0100000", 8)) === parseInt("0100000", 8); }

function readdir_names(dirPath) {
  const fd = open_read(dirPath);
  if (fd < 0) return null;
  const buf = malloc(4096);
  const names = [];
  while (true) {
    const nread = syscall(SYSCALL.getdents, BigInt(fd), buf, 4096n);
    const n = Number(nread);
    if (n <= 0) break;
    let entry = buf;
    const end = buf + BigInt(n);
    while (entry < end) {
      const length = Number(read8_uncompressed(entry + 4n));
      if (length === 0) break;
      let name = "";
      for (let i = 0; i < 256; i++) {
        const c = Number(read8_uncompressed(entry + 8n + BigInt(i)));
        if (c === 0) break;
        name += String.fromCharCode(c);
      }
      if (name && name !== "." && name !== "..") names.push(name);
      entry = entry + BigInt(length);
    }
  }
  close_fd(fd);
  return names;
}

function mode_string(mode, isDirFlag) {
  const tri = v => ((v & 4) ? "r" : "-") + ((v & 2) ? "w" : "-") + ((v & 1) ? (isDirFlag ? "s" : "x") : (isDirFlag ? "S" : "-"));
  const u = (mode >> 6) & 7, g = (mode >> 3) & 7, o = mode & 7;
  return (isDirFlag ? "d" : "-") + tri(u) + tri(g) + tri(o);
}

// ===== Estado =====
const CONN = { NONE: "none", ACTIVE: "active", PASSIVE: "passive" };

class FTPServer {
  constructor(ip, port, root) {
    this.serverIp = ip;
    this.ctrlPortWanted = port;
    this.root = root;
    this.ctrl = { serverFd: -1, clientFd: -1, portActual: -1 };
    this.data = { mode: CONN.NONE, active: { fd: -1 }, passive: { serverFd: -1, port: 0, clientFd: -1 } };
    this.curPath = root;
    this.transferType = "I";
    this.restorePoint = -1;
    this.renameFrom = "";
    this.buf = malloc(FTP.CHUNK);
  }

  start() {
    const srv = create_tcp_server_force(this.ctrlPortWanted);
    this.ctrl.serverFd = Number(srv.fd);
    const sn = getsockname(srv.fd);
    this.ctrl.portActual = sn.port;

    notify(`FTP control escuchando en ${this.serverIp}:${this.ctrl.portActual}`);
    dbg(`CTRL deseado=${this.ctrlPortWanted} actual=${this.ctrl.portActual}`);

    (async () => {
      while (true) {
        await new Promise(res => nrdp.setTimeout(res, 10));
        const cfd = accept_blocking(BigInt(this.ctrl.serverFd));
        if (cfd >= 0) {
          this.ctrl.clientFd = cfd;
          dbg(`Cliente control conectado fd=${cfd}`);
          this.sendCtrl("220 JS FTP Server\r\n");
          this.controlLoop();
          break;
        }
      }
    })();
  }

  sendCtrl(s) {
    const msg = alloc_string(s);
    write_fd(this.ctrl.clientFd, msg, s.length);
  }

  recvLine() {
    const lineBuf = [];
    while (true) {
      const n = read_fd(this.ctrl.clientFd, this.buf, 1);
      if (n <= 0) return null;
      const ch = Number(read8_uncompressed(this.buf));
      lineBuf.push(ch);
      const L = lineBuf.length;
      if (L >= 2 && lineBuf[L-2] === 13 && lineBuf[L-1] === 10) {
        return String.fromCharCode(...lineBuf.slice(0, -2));
      }
    }
  }

  async controlLoop() {
    while (true) {
      const line = this.recvLine();
      if (line === null) break;
      const cmd = line.trim();
      dbg(`CMD: ${cmd}`);
      const op = cmd.split(" ")[0].toUpperCase();
      if (await this.dispatch(op, cmd)) break;
    }
    this.cleanup();
  }

  async dispatch(op, cmd) {
    const handlers = {
      USER: async () => this.sendCtrl("331 Anonymous login accepted, send your email as password\r\n"),
      PASS: async () => this.sendCtrl("230 User logged in\r\n"),
      NOOP: async () => this.sendCtrl("200 No operation\r\n"),
      PWD:  async () => this.sendCtrl(`257 "${this.curPath}" is the current directory\r\n`),
      TYPE: async () => {
        const m = cmd.match(/^TYPE\s+(.+)/i); const t = m && m[1];
        if (t === "I") { this.transferType = "I"; this.sendCtrl("200 Switching to Binary mode\r\n"); }
        else if (t === "A") { this.transferType = "A"; this.sendCtrl("200 Switching to ASCII mode\r\n"); }
        else this.sendCtrl("504 Command not implemented for that parameter\r\n");
      },
      SYST: async () => this.sendCtrl("215 UNIX Type: L8\r\n"),
      FEAT: async () => { this.sendCtrl("211-extensions\r\n"); this.sendCtrl("REST STREAM\r\n"); this.sendCtrl("211 end\r\n"); },

      PASV: async () => {
        const pasv = create_tcp_server_force(0); // puerto aleatorio
        this.data.passive.serverFd = Number(pasv.fd);
        const sn = getsockname(pasv.fd);
        this.data.passive.port = sn.port;
        this.data.mode = CONN.PASSIVE;
        const ip = this.serverIp.split(".").map(Number);
        const p = sn.port; const p1 = (p >> 8) & 0xFF; const p2 = p & 0xFF;
        this.sendCtrl(`227 Entering Passive Mode (${ip[0]},${ip[1]},${ip[2]},${ip[3]},${p1},${p2})\r\n`);
        (async () => {
          const cfd = accept_blocking(BigInt(this.data.passive.serverFd));
          this.data.passive.clientFd = cfd;
          dbg(`PASV data conectado fd=${cfd}`);
        })();
      },

      PORT: async () => {
        const m = cmd.match(/^PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/i);
        if (!m) return;
        const [_, a,b,c,d,p1,p2] = m;
        const host = `${a}.${b}.${c}.${d}`;
        const port = ((parseInt(p1,10) << 8) | parseInt(p2,10));
        const ds = tcp_connect(host, port);
        this.data.active.fd = Number(ds.fd);
        this.data.mode = CONN.ACTIVE;
        this.sendCtrl("200 PORT command ok\r\n");
      },

      LIST: async () => {
        const st = stat_path(this.curPath);
        if (!st || !is_dir(st.mode)) { this.sendCtrl(`550 Invalid directory. Got ${this.curPath}\r\n`); return; }
        const names = readdir_names(this.curPath) || [];
        this.sendCtrl("150 Opening ASCII mode data transfer for LIST.\r\n");
        const df = await this.ensureDataConn();
        for (const name of names) {
          const full = normalizePath(this.root, `${this.curPath}/${name}`, this.curPath);
          const s = stat_path(full);
          if (!s) continue;
          const ms = mode_string(s.mode, is_dir(s.mode));
          const size = s.size || 0;
          const now = new Date();
          const mon = MONTHS[now.getUTCMonth()];
          const day = String(now.getUTCDate()).padStart(2, "0");
          const hour = String(now.getUTCHours()).padStart(2, "0");
          const mins = String(now.getUTCMinutes()).padStart(2, "0");
          const line = `${ms} 1 ps5 ps5 ${size} ${mon} ${day} ${hour}:${mins} ${name}\r\n`;
          this.writeData(df, line);
        }
        this.closeDataConn();
        this.sendCtrl("226 Transfer complete\r\n");
      },

      SIZE: async () => {
        const st = stat_path(this.curPath);
        if (!st || !is_reg(st.mode)) { this.sendCtrl("550 The file doesn't exist\r\n"); return; }
        this.sendCtrl(`213 ${st.size || 0}\r\n`);
      },

      CWD: async () => {
        const m = cmd.match(/^CWD\s+(.+)/i); const target = m && m[1];
        if (!target) { this.sendCtrl("500 Syntax error, command unrecognized.\r\n"); return; }
        let tmp;
        if (target === "/") tmp = this.root;
        else if (target === "..") tmp = dirname(this.curPath);
        else tmp = normalizePath(this.root, target, this.curPath);
        const st = stat_path(tmp);
        if (!st || !is_dir(st.mode)) { this.sendCtrl("550 Invalid directory.\r\n"); return; }
        this.curPath = tmp;
        this.sendCtrl("250 Requested file action okay, completed.\r\n");
      },

      CDUP: async () => { this.curPath = dirname(this.curPath); this.sendCtrl("200 Command okay\r\n"); },

      RETR: async () => {
        const m = cmd.match(/^RETR\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`RETR ${path}`);
        this.sendCtrl("150 Opening Image mode data transfer\r\n");
        const df = await this.ensureDataConn();
        const fd = open_read(path);
        if (fd < 0) {
          const msg = "File not found. Placeholder payload.\n";
          this.writeData(df, msg);
          this.closeDataConn();
          this.sendCtrl("226 Transfer completed\r\n");
          return;
        }
        if (this.restorePoint > 0) {
          let left = this.restorePoint;
          while (left > 0) {
            const toRead = Math.min(FTP.CHUNK, left);
            const n = read_fd(fd, this.buf, toRead);
            if (n <= 0) break;
            left -= n;
          }
        }
        while (true) {
          const n = read_fd(fd, this.buf, FTP.CHUNK);
          if (n <= 0) break;
          this.writeDataRaw(df, this.buf, n);
        }
        close_fd(fd);
        this.closeDataConn();
        this.sendCtrl("226 Transfer completed\r\n");
      },

      STOR: async () => {
        const m = cmd.match(/^STOR\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`STOR ${path}`);
        const df = await this.ensureDataConn();
        const fd = open_write(path, { create: true, append: this.restorePoint >= 0, truncate: this.restorePoint < 0 });
        if (fd < 0) { this.sendCtrl("500 Error opening file\r\n"); this.closeDataConn(); return; }
        this.sendCtrl("150 Opening Image mode data transfer\r\n");
        while (true) {
          const n = this.readData(df, this.buf, FTP.CHUNK);
          if (n <= 0) break;
          const w = write_fd(fd, this.buf, n);
          if (w < n) { this.sendCtrl("550 File write error\r\n"); break; }
        }
        close_fd(fd);
        this.closeDataConn();
        this.sendCtrl("226 Transfer completed\r\n");
      },

      APPE: async () => {
        const m = cmd.match(/^APPE\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`APPE ${path}`);
        this.restorePoint = -1;
        const df = await this.ensureDataConn();
        const fd = open_write(path, { create: true, append: true, truncate: false });
        if (fd < 0) { this.sendCtrl("500 Error opening file\r\n"); this.closeDataConn(); return; }
        this.sendCtrl("150 Opening Image mode data transfer\r\n");
        while (true) {
          const n = this.readData(df, this.buf, FTP.CHUNK);
          if (n <= 0) break;
          const w = write_fd(fd, this.buf, n);
          if (w < n) { this.sendCtrl("550 File write error\r\n"); break; }
        }
        close_fd(fd);
        this.closeDataConn();
        this.sendCtrl("226 Transfer completed\r\n");
      },

      REST: async () => {
        const m = cmd.match(/^REST\s+(\d+)/i);
        const off = m ? parseInt(m[1], 10) : -1;
        this.restorePoint = off;
        dbg(`REST ${off}`);
        this.sendCtrl(`350 Resuming at ${off}\r\n`);
      },

      MKD: async () => {
        const m = cmd.match(/^MKD\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`MKD ${path}`);
        const p = alloc_string(path);
        const r = syscall(SYSCALL.mkdir, p, BigInt(parseInt("0755", 8)));
        if (Number(r) < 0) this.sendCtrl("501 Syntax error. Not privileged.\r\n");
        else this.sendCtrl(`257 "${rel}" created.\r\n`);
      },

      RMD: async () => {
        const m = cmd.match(/^RMD\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`RMD ${path}`);
        const p = alloc_string(path);
        const r = syscall(SYSCALL.rmdir, p);
        if (Number(r) < 0) this.sendCtrl("550 Directory not found or permission denied\r\n");
        else this.sendCtrl(`250 "${rel}" has been removed\r\n`);
      },

      DELE: async () => {
        const m = cmd.match(/^DELE\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`DELE ${path}`);
        const p = alloc_string(path);
        const r = syscall(SYSCALL.unlink, p);
        if (Number(r) < 0) this.sendCtrl("550 Could not delete the file\r\n");
        else this.sendCtrl("226 File deleted\r\n");
      },

      RNFR: async () => {
        const m = cmd.match(/^RNFR\s+(.+)/i); const rel = (m && m[1]) || "";
        const path = normalizePath(this.root, rel, this.curPath);
        dbg(`RNFR ${path}`);
        const st = stat_path(path);
        if (st) { this.renameFrom = rel; this.sendCtrl("350 Remembered filename\r\n"); }
        else this.sendCtrl("550 The file doesn't exist\r\n");
      },

      RNTO: async () => {
        const m = cmd.match(/^RNTO\s+(.+)/i); const relNew = (m && m[1]) || "";
        const oldPath = normalizePath(this.root, this.renameFrom, this.curPath);
        const newPath = normalizePath(this.root, relNew, this.curPath);
        dbg(`RNTO\n${oldPath}\n${newPath}`);
        const po = alloc_string(oldPath), pn = alloc_string(newPath);
        const r = syscall(SYSCALL.rename, po, pn);
        if (Number(r) < 0) this.sendCtrl("550 Error renaming file\r\n");
        else this.sendCtrl("226 Renamed file\r\n");
      },

      SITE: async () => { this.sendCtrl("550 Syntax error, command unrecognized\r\n"); },

      QUIT: async () => { this.sendCtrl("221 Goodbye\r\n"); return true; }
    };

    const h = handlers[op] || (async () => { this.sendCtrl("500 Syntax error, command unrecognized.\r\n"); dbg(`No implementado: ${cmd}`); });
    return await h();
  }

  async ensureDataConn() {
    if (this.data.mode === CONN.ACTIVE) return this.data.active.fd;
    if (this.data.mode === CONN.PASSIVE) {
      let tries = 0;
      while (this.data.passive.clientFd < 0 && tries++ < 500) {
        await new Promise(res => nrdp.setTimeout(res, 10));
      }
      return this.data.passive.clientFd;
    }
    throw new Error("Sin conexión de datos");
  }

  writeData(fd, str) { const s = alloc_string(str); write_fd(fd, s, str.length); }
  writeDataRaw(fd, bufAddr, len) { write_fd(fd, bufAddr, len); }
  readData(fd, bufAddr, len) { return read_fd(fd, bufAddr, len); }

  closeDataConn() {
    try {
      if (this.data.mode === CONN.ACTIVE && this.data.active.fd >= 0) { close_fd(this.data.active.fd); this.data.active.fd = -1; }
      else if (this.data.mode === CONN.PASSIVE) {
        if (this.data.passive.clientFd >= 0) { close_fd(this.data.passive.clientFd); this.data.passive.clientFd = -1; }
        if (this.data.passive.serverFd >= 0) { close_fd(this.data.passive.serverFd); this.data.passive.serverFd = -1; }
      }
    } catch (_) {}
    this.data.mode = CONN.NONE;
  }

  cleanup() {
    try { this.closeDataConn(); } catch (_) {}
    try { if (this.ctrl.clientFd >= 0) close_fd(this.ctrl.clientFd); } catch (_) {}
    try { if (this.ctrl.serverFd >= 0) close_fd(this.ctrl.serverFd); } catch (_) {}
    notify("FTP Server closed");
    dbg("FTP cerrado");
  }
}

// ===== IP actual =====
function get_current_ip_safe() {
  const ip = get_current_ip();
  if (!ip || ip === "0.0.0.0") throw new Error("Sin red disponible");
  return ip;
}

// ===== Bootstrap =====
(function main_ftp() {
  try {
    logger.init();
    FTP.SERVER_IP = get_current_ip_safe();
    const srv = new FTPServer(FTP.SERVER_IP, FTP.CTRL_PORT, FTP.ROOT_PATH);
    dbg(`Iniciando FTP (deseado ${FTP.CTRL_PORT}) en ${FTP.SERVER_IP}`);
    srv.start();
    notify(`FTP listo en ${FTP.SERVER_IP}:${FTP.CTRL_PORT}`);
  } catch (e) {
    dbg("ERROR FTP: " + e.message);
  }
})();

