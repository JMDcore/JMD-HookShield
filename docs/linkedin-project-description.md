# HookShield — descripción para la sección Proyectos

**HookShield** es una bandeja de entrada y firewall local para webhooks, desarrollada como MVP profesional de AppSec. Permite crear endpoints para GitHub, Stripe y HMAC genérico; recibir eventos reales o sintéticos; verificar firmas sobre el cuerpo HTTP original; detectar payloads manipulados, timestamps caducados, duplicados y ataques de replay; rotar secretos cifrados; y consultar cada decisión en una consola visual.

El backend está construido con Fastify, TypeScript y SQLite. Aplica HMAC-SHA256, comparación en tiempo constante, AES-256-GCM para secretos en reposo, idempotencia por identificador de entrega, rate limiting, límites de payload, sesiones `HttpOnly`, CSRF, autorización por propietario, redacción estructurada, retención y auditoría exportable. Stripe utiliza su SDK oficial y GitHub conserva explícitamente la limitación de no disponer de un timestamp firmado en su protocolo estándar.

La interfaz Next.js presenta una bandeja operativa, inspector JSON, headers censurados, checks de seguridad y timeline. El modo demo arranca con `pnpm demo`, sin Docker ni servicios externos, e incluye escenarios válidos y adversos. El proyecto incorpora pruebas unitarias, integración, E2E, accesibilidad WCAG, GitHub Actions, CodeQL, Dependabot, modelo de amenazas y documentación de arquitectura.

**Stack:** Next.js · React · TypeScript · Fastify · SQLite · Stripe SDK · Zod · Vitest · Playwright · axe · GitHub Actions · CodeQL

**Enfoque:** backend · AppSec · criptografía aplicada · diseño de APIs · observabilidad · producto técnico
