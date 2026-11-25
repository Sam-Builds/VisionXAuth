# Asymmetric JWT Signing Migration Plan (HS256 → RS256/ES256)

## Current State
- `VisionX.Auth` currently signs access tokens with HMAC-SHA256 (`HS256`) using symmetric shared secret `Jwt:Key`.
- `GET /.well-known/jwks.json` is already exposed via `TokenService.GetJwks()`, publishing key metadata for downstream services (`visionx-app`).
- Both `VisionX.Auth` and `VisionXBackend` share the same `Jwt:Issuer`, `Jwt:Audience`, and `Jwt:Key`.

## Zero-Downtime Migration Steps
1. **Generate RSA/ECDSA Key Pair (Outside Git)**:
   - Store private key securely in `/opt/visionx/secrets/auth-jwt-private.pem` (mounted read-only into `VisionX.Auth`).
   - Assign key identifier `kid = "visionx-auth-rs256-v1"`.
2. **Dual-Publishing JWKS in Auth**:
   - Update `TokenService.GetJwks()` to publish the public RSA/ECDSA modulus & exponent (`kty: "RSA"`, `alg: "RS256"`, `kid: "visionx-auth-rs256-v1"`) alongside key rotation support.
3. **Update Resource Servers (`VisionXBackend`) First**:
   - Configure `JwtBearerOptions` in `VisionXBackend/Program.cs` to resolve keys dynamically from `https://authc.visionx.io/.well-known/jwks.json` (via `ConfigurationManager<OpenIdConnectConfiguration>` / `IssuerSigningKeyResolver`) while temporarily retaining `SymmetricSecurityKey` in `IssuerSigningKeys` so active `HS256` tokens remain valid until expiry (max 60 minutes).
4. **Switch Signing Algorithm in Auth**:
   - Change `TokenService.CreateAccessToken` to sign new JWTs with `SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)`.
5. **Retire Shared Symmetric Secret**:
   - Once 60 minutes have elapsed (all previous `HS256` tokens expired), remove `Jwt:Key` from `VisionXBackend`.
