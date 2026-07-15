import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const assets = new URL("../docs/assets/", import.meta.url);
const linkedin = new URL("linkedin/", assets);
await mkdir(linkedin, { recursive: true });

const palette = {
  canvas: "#f3f4f6",
  surface: "#ffffff",
  ink: "#182235",
  muted: "#4f5c70",
  faint: "#596679",
  line: "#d4d9e0",
  navy: "#17243b",
  teal: "#267a78",
  tealSoft: "#e8f3f2",
  green: "#28704f",
  greenSoft: "#eaf4ee",
  amber: "#956517",
  amberSoft: "#faf1df",
  red: "#a53d42",
  redSoft: "#f9e9ea"
};

function svgFrame(width, height, body) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
    <rect width="${width}" height="${height}" fill="${palette.canvas}"/>
    ${body}
  </svg>`;
}

function mark(x, y, size = 54, dark = true) {
  const scale = size / 64;
  return `<g transform="translate(${x} ${y}) scale(${scale})">
    <rect width="64" height="64" rx="14" fill="${dark ? palette.navy : palette.teal}"/>
    <path d="M32 10 49 17v13c0 11-6.5 19.4-17 24-10.5-4.6-17-13-17-24V17l17-7Z" fill="none" stroke="#fff" stroke-width="4" stroke-linejoin="round"/>
    <path d="M23 31h10a6 6 0 1 0 0-12h-2M26 26l-5 5 5 5" fill="none" stroke="#75c1bd" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  </g>`;
}

function text(x, y, value, size, weight = 400, color = palette.ink, anchor = "start", tracking = 0) {
  return `<text x="${x}" y="${y}" fill="${color}" font-family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="${size}" font-weight="${weight}" text-anchor="${anchor}" letter-spacing="${tracking}">${value}</text>`;
}

function mono(x, y, value, size = 18, color = palette.muted) {
  return `<text x="${x}" y="${y}" fill="${color}" font-family="SFMono-Regular, Menlo, monospace" font-size="${size}">${value}</text>`;
}

function rounded(x, y, width, height, fill = palette.surface, stroke = palette.line, radius = 14) {
  return `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}" stroke="${stroke}"/>`;
}

async function render(svg, target, width, height) {
  await sharp(Buffer.from(svg)).resize(width, height).png({ quality: 92, compressionLevel: 9 })
    .toFile(fileURLToPath(target));
}

const cover = svgFrame(1280, 640, `
  <rect width="1280" height="640" fill="${palette.navy}"/>
  <rect x="0" y="0" width="10" height="640" fill="${palette.teal}"/>
  ${mark(74, 70, 62, false)}
  ${text(153, 112, "HookShield", 29, 700, "#ffffff")}
  ${text(74, 236, "Trust the event.", 58, 720, "#ffffff", "start", -1.2)}
  ${text(74, 300, "Keep the evidence.", 58, 720, "#ffffff", "start", -1.2)}
  ${text(76, 365, "A local-first webhook security inbox for signatures,", 22, 400, "#b9c5d5")}
  ${text(76, 398, "replay protection, idempotency, and secret rotation.", 22, 400, "#b9c5d5")}
  ${rounded(75, 477, 163, 40, "#213551", "#405371", 7)}
  ${text(156, 503, "GITHUB · STRIPE", 13, 750, "#d9e3ef", "middle", 1.1)}
  ${rounded(250, 477, 152, 40, "#213551", "#405371", 7)}
  ${text(326, 503, "GENERIC HMAC", 13, 750, "#d9e3ef", "middle", 1.1)}
  ${rounded(760, 66, 454, 508, "#f8f9fa", "#53627a", 16)}
  ${text(797, 112, "DELIVERY INSPECTOR", 12, 800, palette.faint, "start", 1.8)}
  ${text(797, 153, "deployment.completed", 24, 720, palette.ink)}
  ${mono(797, 180, "sim_8dbd881846772d51b6", 14)}
  ${rounded(1045, 119, 126, 35, palette.redSoft, "#e2b9bc", 18)}
  ${text(1108, 142, "REJECTED", 12, 800, palette.red, "middle", 1)}
  <line x1="797" y1="214" x2="1176" y2="214" stroke="${palette.line}"/>
  ${text(797, 246, "SECURITY CHECKS", 12, 800, palette.faint, "start", 1.5)}
  ${rounded(797, 267, 379, 64, palette.greenSoft, "#c6decf", 8)}
  <circle cx="827" cy="299" r="11" fill="${palette.green}"/>
  ${text(827, 304, "✓", 14, 800, "#ffffff", "middle")}
  ${text(852, 294, "Payload size", 15, 700, palette.ink)}
  ${text(852, 315, "95 bytes within endpoint policy", 12, 400, palette.muted)}
  ${rounded(797, 343, 379, 64, palette.redSoft, "#e2b9bc", 8)}
  <circle cx="827" cy="375" r="11" fill="${palette.red}"/>
  ${text(827, 380, "×", 16, 700, "#ffffff", "middle")}
  ${text(852, 370, "Cryptographic signature", 15, 700, palette.ink)}
  ${text(852, 391, "Signature mismatch on raw bytes", 12, 400, palette.muted)}
  ${rounded(797, 419, 379, 64, palette.greenSoft, "#c6decf", 8)}
  <circle cx="827" cy="451" r="11" fill="${palette.green}"/>
  ${text(827, 456, "✓", 14, 800, "#ffffff", "middle")}
  ${text(852, 446, "Freshness window", 15, 700, palette.ink)}
  ${text(852, 467, "Timestamp inside 300 seconds", 12, 400, palette.muted)}
  ${text(797, 532, "SIGNATURE_INVALID", 13, 800, palette.red, "start", 1.1)}
`);
await render(cover, new URL("social-cover.png", assets), 1280, 640);

const architecture = svgFrame(1600, 900, `
  ${mark(72, 57, 54)}
  ${text(143, 92, "HookShield architecture", 30, 720)}
  ${text(143, 122, "Local-first boundaries with an explicit scale-out path", 17, 400, palette.muted)}
  ${rounded(80, 210, 270, 166, palette.surface, palette.line, 12)}
  ${text(110, 251, "UNTRUSTED INGRESS", 12, 800, palette.red, "start", 1.4)}
  ${text(110, 294, "Providers + simulator", 22, 700)}
  ${text(110, 329, "Raw bytes", 16, 500, palette.muted)}
  ${text(110, 354, "Provider headers", 16, 500, palette.muted)}
  <path d="M350 293 H438" stroke="${palette.teal}" stroke-width="3"/>
  <path d="m428 283 12 10-12 10" fill="none" stroke="${palette.teal}" stroke-width="3"/>
  ${rounded(440, 174, 490, 240, palette.surface, palette.teal, 12)}
  ${text(475, 217, "FASTIFY SECURITY BOUNDARY", 12, 800, palette.teal, "start", 1.4)}
  ${text(475, 261, "Ingress + decision engine", 25, 720)}
  ${rounded(475, 289, 198, 46, palette.tealSoft, "#bdd8d6", 7)}
  ${text(574, 318, "Size + rate gates", 15, 650, palette.teal, "middle")}
  ${rounded(688, 289, 207, 46, palette.tealSoft, "#bdd8d6", 7)}
  ${text(791, 318, "Provider verifier", 15, 650, palette.teal, "middle")}
  ${rounded(475, 347, 198, 46, palette.tealSoft, "#bdd8d6", 7)}
  ${text(574, 376, "Replay + idempotency", 15, 650, palette.teal, "middle")}
  ${rounded(688, 347, 207, 46, palette.tealSoft, "#bdd8d6", 7)}
  ${text(791, 376, "Internal consumer", 15, 650, palette.teal, "middle")}
  <path d="M930 293 H1018" stroke="${palette.teal}" stroke-width="3"/>
  <path d="m1008 283 12 10-12 10" fill="none" stroke="${palette.teal}" stroke-width="3"/>
  ${rounded(1020, 210, 260, 166, palette.surface, palette.line, 12)}
  ${text(1050, 251, "SQLITE · WAL", 12, 800, palette.green, "start", 1.4)}
  ${text(1050, 294, "Security evidence", 22, 700)}
  ${text(1050, 329, "Encrypted secret versions", 15, 500, palette.muted)}
  ${text(1050, 354, "Deliveries · checks · audit", 15, 500, palette.muted)}
  <path d="M1150 376 V478" stroke="${palette.teal}" stroke-width="3"/>
  <path d="m1140 468 10 12 10-12" fill="none" stroke="${palette.teal}" stroke-width="3"/>
  ${rounded(986, 480, 328, 166, palette.surface, palette.line, 12)}
  ${text(1018, 522, "AUTHENTICATED API", 12, 800, palette.teal, "start", 1.4)}
  ${text(1018, 566, "Owner-scoped operations", 22, 700)}
  ${text(1018, 601, "HttpOnly session · CSRF", 15, 500, palette.muted)}
  ${text(1018, 626, "Audit export · retention · retry", 15, 500, palette.muted)}
  <path d="M986 563 H898" stroke="${palette.teal}" stroke-width="3"/>
  <path d="m908 553-12 10 12 10" fill="none" stroke="${palette.teal}" stroke-width="3"/>
  ${rounded(568, 480, 328, 166, palette.surface, palette.line, 12)}
  ${text(600, 522, "NEXT.JS CONSOLE", 12, 800, palette.navy, "start", 1.4)}
  ${text(600, 566, "Operations workbench", 22, 700)}
  ${text(600, 601, "Inbox · inspector · simulator", 15, 500, palette.muted)}
  ${text(600, 626, "Responsive · keyboard · WCAG", 15, 500, palette.muted)}
  ${rounded(80, 732, 1438, 96, palette.navy, palette.navy, 10)}
  ${text(116, 771, "SCALE-OUT PATH", 12, 800, "#86c3bf", "start", 1.5)}
  ${text(116, 803, "PostgreSQL uniqueness  →  Redis rate windows  →  durable queue  →  KMS envelope encryption", 21, 550, "#e7edf5")}
`);
await render(architecture, new URL("architecture.png", assets), 1600, 900);

const flow = svgFrame(1600, 900, `
  ${mark(72, 57, 54)}
  ${text(143, 92, "Webhook validation flow", 30, 720)}
  ${text(143, 122, "Every decision produces inspectable evidence", 17, 400, palette.muted)}
  <line x1="160" y1="440" x2="1430" y2="440" stroke="${palette.line}" stroke-width="4"/>
  ${[
    [145, "01", "Capture", "Original HTTP bytes", palette.navy],
    [395, "02", "Bound", "Size + rate policy", palette.teal],
    [645, "03", "Authenticate", "Provider signature", palette.teal],
    [895, "04", "Freshness", "Signed timestamp*", palette.amber],
    [1145, "05", "Idempotency", "Delivery identifier", palette.amber],
    [1395, "06", "Decide", "Admit or stop", palette.green]
  ].map(([x, number, title, detail, colour]) => `
    <circle cx="${x}" cy="440" r="42" fill="${colour}" stroke="#fff" stroke-width="8"/>
    ${text(x, 447, number, 15, 800, "#fff", "middle", 1)}
    ${text(x, 528, title, 20, 720, palette.ink, "middle")}
    ${text(x, 558, detail, 14, 450, palette.muted, "middle")}
  `).join("")}
  ${rounded(116, 664, 1368, 108, palette.surface, palette.line, 10)}
  ${text(154, 706, "PROVIDER TRUTH", 12, 800, palette.red, "start", 1.5)}
  ${text(154, 742, "* GitHub does not sign a timestamp in its standard webhook protocol. HookShield marks freshness unavailable; it does not manufacture a guarantee.", 17, 500, palette.ink)}
  ${rounded(1305, 92, 179, 48, palette.greenSoft, "#c4dccd", 24)}
  ${text(1394, 122, "AUDIT RECORDED", 12, 800, palette.green, "middle", 1)}
`);
await render(flow, new URL("webhook-flow.png", assets), 1600, 900);

function slide(index, kicker, titleLines, bodyLines, sideLabel, colour = palette.teal) {
  const titleSvg = titleLines.map((line, offset) => text(76, 300 + offset * 72, line, 58, 720, palette.ink, "start", -1)).join("");
  const bodySvg = bodyLines.map((line, offset) => `${rounded(76, 560 + offset * 100, 928, 74, palette.surface, palette.line, 9)}<circle cx="110" cy="${597 + offset * 100}" r="7" fill="${colour}"/>${text(136, 604 + offset * 100, line, 24, 520, palette.ink)}`).join("");
  return svgFrame(1080, 1350, `
    <rect x="0" y="0" width="18" height="1350" fill="${colour}"/>
    ${mark(76, 72, 54)}
    ${text(143, 108, "HookShield", 26, 720)}
    ${text(1004, 108, `0${index} / 05`, 16, 750, palette.faint, "end", 1.2)}
    ${text(76, 214, kicker.toUpperCase(), 15, 800, colour, "start", 2.2)}
    ${titleSvg}
    ${bodySvg}
    <line x1="76" y1="1226" x2="1004" y2="1226" stroke="${palette.line}"/>
    ${text(76, 1272, sideLabel, 18, 650, palette.muted)}
    ${text(1004, 1272, "github.com/JMDcore/JMD-HookShield", 16, 500, palette.faint, "end")}
  `);
}

const slides = [
  [1, "AppSec portfolio project", ["Confía en el evento.", "Conserva la evidencia."], ["Firmas de GitHub, Stripe y HMAC genérico", "Replay, idempotencia y rotación de secretos", "Demo local con un único comando"], "Bandeja de seguridad para webhooks", palette.teal],
  [2, "El problema", ["Una petición HTTP", "no demuestra confianza."], ["El origen puede falsificarse", "El payload puede modificarse", "Una entrega válida puede reutilizarse"], "Verificar antes de procesar", palette.red],
  [3, "El flujo", ["De bytes originales", "a una decisión auditable."], ["1 · Límite de tamaño y frecuencia", "2 · Firma y timestamp del proveedor", "3 · Idempotencia, decisión y timeline"], "Cada control deja evidencia", palette.teal],
  [4, "Controles", ["Seguridad aplicada,", "sin estética de teatro."], ["HMAC-SHA256 y comparación en tiempo constante", "AES-256-GCM y versiones de secretos", "CSRF, autorización, redacción y retención"], "Modelo de amenazas incluido", palette.amber],
  [5, "Arquitectura", ["Full-stack local-first.", "Preparado para evolucionar."], ["Next.js + React · consola operativa", "Fastify + SQLite · motor de decisiones", "Vitest + Playwright + axe · CI + CodeQL"], "MVP profesional, no promesa de producción", palette.green]
];

for (const [index, kicker, titles, lines, label, colour] of slides) {
  await render(
    slide(index, kicker, titles, lines, label, colour),
    new URL(`0${index}-${["cover", "problem", "flow", "security", "architecture"][index - 1]}.png`, linkedin),
    1080,
    1350
  );
}

const dashboardPath = fileURLToPath(new URL("screenshots/dashboard.png", assets));
await sharp(dashboardPath)
  .extract({ left: 246, top: 162, width: 443, height: 558 })
  .png({ quality: 92, compressionLevel: 9 })
  .toFile(fileURLToPath(new URL("screenshots/delivery-inbox.png", assets)));
await sharp(dashboardPath)
  .extract({ left: 689, top: 215, width: 591, height: 505 })
  .png({ quality: 92, compressionLevel: 9 })
  .toFile(fileURLToPath(new URL("screenshots/delivery-inspector.png", assets)));

process.stdout.write("HookShield social and architecture assets generated.\n");
