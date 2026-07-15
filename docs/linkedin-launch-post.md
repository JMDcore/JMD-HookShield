# Publicación de lanzamiento para LinkedIn

He terminado la primera versión de **HookShield**, un proyecto de portafolio centrado en seguridad de aplicaciones, backend y diseño de producto técnico.

Un webhook puede parecer solo una petición HTTP, pero antes de procesarlo hay preguntas importantes:

- ¿Procede realmente del proveedor?
- ¿Se ha modificado el payload?
- ¿El timestamp sigue siendo válido?
- ¿Ya procesamos ese identificador?
- ¿Se está reutilizando una entrega anterior?
- ¿Qué control tomó la decisión final?

HookShield convierte esas comprobaciones en una bandeja operativa. Permite crear endpoints para GitHub, Stripe y HMAC genérico, verificar firmas sobre los bytes originales, detectar replay y duplicados, rotar secretos cifrados y revisar headers censurados, payload, checks y timeline.

Quería que fuera fácil de evaluar, así que el modo demo funciona con:

```bash
pnpm install
pnpm demo
```

No necesita Docker, Redis, PostgreSQL, túneles ni cuentas externas. Incluye eventos sintéticos válidos, firmas incorrectas, payloads manipulados, timestamps caducados, duplicados, payloads excesivos y rate limiting.

En la parte de seguridad he trabajado con HMAC-SHA256, comparación en tiempo constante, AES-256-GCM, versiones de secretos, sesiones `HttpOnly`, CSRF, autorización por propietario, retención, redacción y auditoría. Stripe se valida mediante su SDK oficial; en GitHub documento de forma explícita que la firma estándar no aporta un timestamp firmado.

La calidad también forma parte del proyecto: pruebas unitarias, integración y E2E, auditoría de accesibilidad, GitHub Actions, CodeQL, Dependabot, modelo de amenazas, diagramas y documentación de las decisiones descartadas. El resultado es un MVP profesional de AppSec, no una afirmación de producto listo para producción.

Repositorio: https://github.com/JMDcore/JMD-HookShield

#AppSec #CyberSecurity #Backend #TypeScript #Webhooks #SoftwareEngineering #OpenSource #Portfolio

## Texto breve alternativo

Nuevo proyecto: **HookShield**, una bandeja de entrada y firewall local para webhooks.

Verifica firmas de GitHub, Stripe y HMAC genérico sobre el cuerpo original; detecta payloads manipulados, replay, timestamps caducados y duplicados; cifra versiones de secretos; y explica cada decisión en un inspector visual.

El demo arranca con `pnpm demo`, sin Docker ni servicios externos. Incluye Fastify, Next.js, SQLite, Vitest, Playwright, CodeQL, modelo de amenazas y pruebas de accesibilidad.

Repositorio: https://github.com/JMDcore/JMD-HookShield

#AppSec #Backend #TypeScript #CyberSecurity #Webhooks
