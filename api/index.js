// Proofline API — rebuilt from frontend contract + DB forensics (2026-10-01)
// Node 24, zero deps. DB: Neon Postgres (HTTP SQL API). Photos: inline base64 (storage='db'), served token-scoped.
// Auth: pl_users {email, phash, salt, biz, secret}; phash = crypto.scryptSync(pw, salt, 64).hex() (128 hex confirmed)
// Cookie: pl=<ts>.<userId>.<sig>; sig = HMAC-SHA256(user.secret, "ts.userId")

const crypto = require("crypto");

async function sql(query, params) {
  const res = await fetch(`https://${new URL(process.env.DATABASE_URL).hostname}/sql`, {
    method: "POST",
    headers: { "Neon-Connection-String": process.env.DATABASE_URL, "Content-Type": "application/json" },
    body: JSON.stringify(params && params.length ? { query, params } : { query }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error("db: " + text.slice(0, 300));
  return JSON.parse(text).rows || [];
}
const hexId = n => crypto.randomBytes(n).toString("hex");

async function getUser(id) {
  const rows = await sql("SELECT id, email, phash, salt, biz, phone, website, secret, created FROM pl_users WHERE id=$1 LIMIT 1", [id]);
  return rows[0] || null;
}
function hashPassword(password, salt, dklen) {
  return crypto.scryptSync(password, salt, dklen).toString("hex");
}
async function readAuth(req) {
  const cookies = (req.headers.cookie || "").split(/;\s*/);
  const c = cookies.find(x => x.startsWith("pl="));
  if (!c) return null;
  const [ts, userId, sig] = decodeURIComponent(c.slice(3)).split(".");
  if (!ts || !userId || !sig) return null;
  const user = await getUser(userId);
  if (!user) return null;
  const expect = crypto.createHmac("sha256", user.secret).update(`${ts}.${userId}`).digest("hex");
  if (expect !== sig) return null;
  if (Date.now() - Number(ts) > 30 * 24 * 3600 * 1000) return null;
  return user;
}
function setCookie(user) {
  const ts = String(Date.now());
  const sig = crypto.createHmac("sha256", user.secret).update(`${ts}.${user.id}`).digest("hex");
  return `pl=${encodeURIComponent(`${ts}.${user.id}.${sig}`)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}
const CLEAR = "pl=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

function json(res, code, obj, headers) {
  const h = Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, headers || {});
  res.statusCode = code;
  for (const [k, v] of Object.entries(h)) res.setHeader(k, v);
  res.end(JSON.stringify(obj));
}
const err = (res, code, msg) => json(res, code, { error: msg });
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > 12_000_000) { reject(new Error("too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch (e) { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}
function photoUrl(photo, reportToken) {
  return `/api?a=pl-photo&ph=${encodeURIComponent(photo.id)}&t=${encodeURIComponent(reportToken)}`;
}
async function photoList(reportId, kind, reportToken) {
  const rows = await sql("SELECT id, kind FROM pl_photos WHERE report_id=$1 AND kind=$2 ORDER BY created", [reportId, kind]);
  return rows.map(r => ({ id: r.id, kind: r.kind, url: photoUrl(r, reportToken) }));
}
async function servePhoto(req, res, photoId, token) {
  const rows = await sql("SELECT p.id, p.data, p.mime, p.report_id, r.token FROM pl_photos p JOIN pl_reports r ON r.id=p.report_id WHERE p.id=$1 LIMIT 1", [photoId]);
  if (!rows.length || (token ? rows[0].token !== token : true && !(await readAuth(req)))) {
    res.statusCode = token ? 404 : 401; return res.end("not found");
  }
  const buf = Buffer.from(rows[0].data || "", "base64");
  res.statusCode = 200;
  res.setHeader("Content-Type", rows[0].mime || "image/jpeg");
  res.setHeader("Cache-Control", "private, max-age=3600");
  res.end(buf);
}

module.exports = async (req, res) => {
  const url = new URL(req.url, "http://x");
  const a = url.searchParams.get("a") || "";
  let body = {};
  if (req.method === "POST") {
    try { body = await readBody(req); } catch (e) { return err(res, 400, e.message === "too large" ? "File too large." : "Bad request."); }
  }
  try {
    switch (a) {
      case "pl-photo": return servePhoto(req, res, String(url.searchParams.get("ph") || ""), String(url.searchParams.get("t") || ""));

      case "pl-login": {
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (!email || !password) return err(res, 400, "Enter your email and password.");
        const rows = await sql("SELECT id, phash, salt, secret FROM pl_users WHERE email=$1 LIMIT 1", [email]);
        if (!rows.length) return err(res, 401, "Wrong email or password.");
        const u = rows[0];
        const ok = hashPassword(password, u.salt, 64) === u.phash || hashPassword(password, u.salt, 32) === u.phash;
        if (!ok) return err(res, 401, "Wrong email or password.");
        return json(res, 200, { ok: true }, { "Set-Cookie": setCookie(u) });
      }

      case "pl-logout":
        return json(res, 200, { ok: true }, { "Set-Cookie": CLEAR });

      case "pl-signup": {
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        const biz = String(body.biz || "").trim() || "My business";
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(res, 400, "Enter a valid email.");
        if (password.length < 8) return err(res, 400, "Password must be at least 8 characters.");
        const existing = await sql("SELECT id FROM pl_users WHERE email=$1 LIMIT 1", [email]);
        if (existing.length) return err(res, 400, "That email already has an account.");
        const id = hexId(8);
        const salt = crypto.randomBytes(16).toString("hex");
        const secret = hexId(32);
        const phash = hashPassword(password, salt, 64);
        await sql("INSERT INTO pl_users (id, email, phash, salt, biz, secret, created) VALUES ($1,$2,$3,$4,$5,$6,$7)", [id, email, phash, salt, biz, secret, Date.now()]);
        return json(res, 200, { ok: true }, { "Set-Cookie": setCookie({ id, secret }) });
      }

      case "pl-report-info": {
        const token = String(body.t || "");
        const rows = await sql("SELECT r.id, r.title, r.customer, r.jobdate, r.note, r.views, r.user_id, u.biz, u.phone, u.website FROM pl_reports r JOIN pl_users u ON u.id=r.user_id WHERE r.token=$1 LIMIT 1", [token]);
        if (!rows.length) return err(res, 404, "Report not found.");
        const r = rows[0];
        await sql("UPDATE pl_reports SET views = COALESCE(views,0) + 1 WHERE id=$1", [r.id]);
        return json(res, 200, {
          title: r.title, biz: r.biz, customer: r.customer, jobdate: r.jobdate, note: r.note,
          phone: r.phone || "", website: r.website || "", views: Number(r.views || 0),
          before: await photoList(r.id, "before", token),
          after: await photoList(r.id, "after", token),
        });
      }

      default: break;
    }

    // authenticated zone
    const user = await readAuth(req);
    if (!user) return err(res, 401, "Please log in");

    switch (a) {
      case "pl-state": {
        const reports = await sql("SELECT id, title, customer, jobdate, note, token, COALESCE(views,0) AS views FROM pl_reports WHERE user_id=$1 ORDER BY created DESC", [user.id]);
        const counts = {};
        for (const r of reports) {
          const c = await sql("SELECT kind, count(*) AS n FROM pl_photos WHERE report_id=$1 GROUP BY kind", [r.id]);
          counts[r.id] = { before: Number(c.find(x => x.kind === "before")?.n || 0), after: Number(c.find(x => x.kind === "after")?.n || 0) };
        }
        return json(res, 200, { user: { email: user.email, biz: user.biz, phone: user.phone || '', website: user.website || '' }, reports, counts });
      }

      case "pl-save-report": {
        const title = String(body.title == null ? "" : body.title).trim() || "Untitled job";
        if (body.id) {
          const own = await sql("SELECT id FROM pl_reports WHERE id=$1 AND user_id=$2 LIMIT 1", [String(body.id), user.id]);
          if (!own.length) return err(res, 404, "Report not found.");
          await sql("UPDATE pl_reports SET title=$3, customer=$4, jobdate=$5, note=$6 WHERE id=$1 AND user_id=$2", [
            String(body.id), user.id, title,
            String(body.customer == null ? "" : body.customer).slice(0, 120),
            String(body.jobdate == null ? "" : body.jobdate).slice(0, 10),
            String(body.note == null ? "" : body.note).slice(0, 4000),
          ]);
          return json(res, 200, { id: String(body.id) });
        }
        const id = hexId(8), token = hexId(12);
        await sql("INSERT INTO pl_reports (id, user_id, title, customer, jobdate, token, note, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", [id, user.id, title, "", "", token, "", Date.now()]);
        return json(res, 200, { id, token });
      }

      case "pl-dup-report": {
        const own = await sql("SELECT id, title, customer, jobdate, note FROM pl_reports WHERE id=$1 AND user_id=$2 LIMIT 1", [String(body.id || ""), user.id]);
        if (!own.length) return err(res, 404, "Report not found.");
        const id = hexId(8), token = hexId(12);
        await sql("INSERT INTO pl_reports (id, user_id, title, customer, jobdate, token, note, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", [id, user.id, (own[0].title || "Untitled job") + " (copy)", own[0].customer || "", own[0].jobdate || "", token, own[0].note || "", Date.now()]);
        await sql("INSERT INTO pl_photos (id, report_id, user_id, kind, url, storage, key, data, mime, sort, created) SELECT substr(md5(random()::text || p.id || $2),1,16), $3, $4, p.kind, '', 'db', '', p.data, p.mime, p.sort, $5 FROM pl_photos p WHERE p.report_id=$1", [own[0].id, id, id, user.id, Date.now()]);
        return json(res, 200, { id, token });
      }

      case "pl-del-report": {
        await sql("DELETE FROM pl_photos WHERE report_id=$1 AND user_id=$2", [String(body.id || ""), user.id]);
        await sql("DELETE FROM pl_reports WHERE id=$1 AND user_id=$2", [String(body.id || ""), user.id]);
        return json(res, 200, { ok: true });
      }

      case "pl-photos": {
        const own = await sql("SELECT token FROM pl_reports WHERE id=$1 AND user_id=$2 LIMIT 1", [String(body.reportId || ""), user.id]);
        if (!own.length) return err(res, 404, "Report not found.");
        const token = own[0].token;
        return json(res, 200, {
          before: await photoList(String(body.reportId), "before", token),
          after: await photoList(String(body.reportId), "after", token),
        });
      }

      case "pl-upload": {
        const kind = String(body.kind || "");
        if (kind !== "before" && kind !== "after") return err(res, 400, "Bad photo kind.");
        const own = await sql("SELECT token FROM pl_reports WHERE id=$1 AND user_id=$2 LIMIT 1", [String(body.reportId || ""), user.id]);
        if (!own.length) return err(res, 404, "Report not found.");
        const data = String(body.data || "");
        if (!data) return err(res, 400, "No image data.");
        const size = Math.floor(data.length * 0.75);
        if (size > 8_000_000) return err(res, 400, "That image is too large.");
        const id = hexId(8);
        const mime = String(body.mime || "image/jpeg");
        await sql("INSERT INTO pl_photos (id, report_id, user_id, kind, url, storage, key, data, mime, sort, created) VALUES ($1,$2,$3,$4,'','db','',$5,$6,0,$7)", [id, String(body.reportId), user.id, kind, data, mime, Date.now()]);
        return json(res, 200, { id, url: photoUrl({ id }, own[0].token) });
      }

      case "pl-del-photo": {
        await sql("DELETE FROM pl_photos WHERE id=$1 AND user_id=$2", [String(body.id || ""), user.id]);
        return json(res, 200, { ok: true });
      }

      case "pl-save-settings": {
        await sql("UPDATE pl_users SET biz=$2, phone=$3, website=$4 WHERE id=$1", [
          user.id,
          String(body.biz || "").trim().slice(0, 120) || user.biz,
          String(body.phone == null ? (user.phone || "") : body.phone).trim().slice(0, 40),
          String(body.website == null ? (user.website || "") : body.website).trim().slice(0, 120),
        ]);
        return json(res, 200, { ok: true });
      }


      default:
        return err(res, 404, "Unknown action.");
    }
  } catch (e) {
    console.error("pl api error", a, e);
    return err(res, 500, "Something went wrong on our end. Try again.");
  }
};
