use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const ACCESS_TTL: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub org_id: String,
    pub role: String,
    pub plan: String,
    pub trial_ends_at: Option<i64>,
    pub iat: i64,
    pub exp: i64,
}

#[cfg(target_arch = "wasm32")]
pub fn now() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn sign(claims: &Claims, secret: &str) -> Result<String, String> {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD
        .encode(serde_json::to_string(claims).map_err(|e| e.to_string())?);
    let input = format!("{}.{}", header, body);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
    mac.update(input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{}.{}", input, sig))
}

pub fn verify(token: &str, secret: &str) -> Result<Claims, String> {
    let mut parts = token.splitn(3, '.');
    let header = parts.next().ok_or("Malformed JWT")?;
    let payload = parts.next().ok_or("Malformed JWT")?;
    let sig_b64 = parts.next().ok_or("Malformed JWT")?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "Invalid signature encoding")?;
    let input = format!("{}.{}", header, payload);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
    mac.update(input.as_bytes());
    mac.verify_slice(&sig_bytes)
        .map_err(|_| "Invalid signature".to_string())?;

    let payload_bytes =
        URL_SAFE_NO_PAD.decode(payload).map_err(|e| e.to_string())?;
    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|e| e.to_string())?;

    if claims.exp < now() {
        return Err("Token expired".into());
    }
    Ok(claims)
}

pub fn decode_cf_payload(token: &str) -> Result<serde_json::Value, String> {
    let payload = token.split('.').nth(1).ok_or("Malformed JWT")?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_claims(exp: i64) -> Claims {
        Claims {
            sub: "user-1".into(),
            email: "test@example.com".into(),
            org_id: "org-1".into(),
            role: "admin".into(),
            plan: "enterprise".into(),
            trial_ends_at: None,
            iat: 1_700_000_000,
            exp,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let claims = test_claims(9_999_999_999);
        let token = sign(&claims, "test-secret").unwrap();
        let decoded = verify(&token, "test-secret").unwrap();
        assert_eq!(decoded.sub, "user-1");
        assert_eq!(decoded.email, "test@example.com");
        assert_eq!(decoded.org_id, "org-1");
        assert_eq!(decoded.role, "admin");
        assert_eq!(decoded.plan, "enterprise");
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let token = sign(&test_claims(9_999_999_999), "secret-a").unwrap();
        assert!(verify(&token, "secret-b").is_err());
    }

    #[test]
    fn verify_rejects_expired_token() {
        let token = sign(&test_claims(1_000), "secret").unwrap();
        assert!(verify(&token, "secret").is_err());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let token = sign(&test_claims(9_999_999_999), "secret").unwrap();
        // flip one char in the payload segment
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut payload = parts[1].to_string();
        let tampered = if payload.ends_with('A') { payload.pop(); payload.push('B'); payload } else { payload.push('X'); payload };
        let new_token = format!("{}.{}.{}", parts[0], tampered, parts[2]);
        assert!(verify(&new_token, "secret").is_err());
    }

    #[test]
    fn decode_cf_payload_extracts_fields() {
        let json = r#"{"iss":"https://cf.example.com","sub":"user@test.com","email":"user@test.com"}"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let fake_jwt = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", encoded);
        let decoded = decode_cf_payload(&fake_jwt).unwrap();
        assert_eq!(decoded["sub"], "user@test.com");
        assert_eq!(decoded["email"], "user@test.com");
    }

    #[test]
    fn decode_cf_payload_rejects_malformed() {
        assert!(decode_cf_payload("notajwt").is_err());
    }
}
