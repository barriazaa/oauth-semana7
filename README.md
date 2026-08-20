# API SoundAccess - OAuth 2.0 & JWT

API REST de catálogo musical y listas de reproducción protegida con OAuth 2.0 y JSON Web Tokens (JWT), construida para la gestión de identidades, delegación de permisos mediante *scopes* y control de acceso granular.

---

#Información del Estudiante

* **Nombre: Bryan Ottoniel Arriaza Ascencio
* **Carnet: 1890-18-20
* **Curso: Seguridad y Auditoría de Sistemas
* **Tecnología utilizada:Node.js / JavaScript (Express)
* **Repositorio GitHub:** [https://github.com/barriazaa/oauth-semana7](https://github.com/barriazaa/oauth-semana7)

---

Arquitectura y Flujos OAuth

La solución separa estrictamente la autenticación de usuarios de la autorización de recursos, implementando dos flujos principales:

1. **Authorization Code Grant con PKCE (S256):**
   * Uso:Clientes públicos/aplicaciones de usuario final.

   * Seguridad:Utiliza `code_challenge` (SHA-256) y `code_verifier` para evitar intercepciones de código en la redirección. Previene CSRF mediante el parámetro `state`.

2. **Client Credentials Grant:**
   * Uso:Comunicaciones servidor a servidor (máquina a máquina).

   * Seguridad:Autenticación directa de clientes confidenciales mediante `client_id` y `client_secret`. Restringido a datos públicos del catálogo.

> *Decisión de Seguridad (RFC 9700): Se excluye totalmente el flujo ROPC (*Resource Owner Password Credentials*) para evitar que las aplicaciones procesen credenciales primarias en texto plano.

---

Requisitos e Instalación

### Requisitos previos
* Node.js v18.x o superior
* npm v9.x o superior

Pasos de Instalación
1. Clonar el repositorio:
   ```bash
   git clone [https://github.com/barriazaa/oauth-semana7.git](https://github.com/barriazaa/oauth-semana7.git)
   cd oauth-semana7


