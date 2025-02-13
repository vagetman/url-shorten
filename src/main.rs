use anyhow::{anyhow, Result};
use chrono::prelude::*;
use fastly::http::{header, Method, StatusCode};
use fastly::secret_store::Secret;
use fastly::{ConfigStore, KVStore, Request, Response, SecretStore};
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use serde_json::json;

const SECRET_STORE_RES: &str = "secret-auth-store";
const KV_STORE_RES: &str = "short-urls-store";
const CONF_STORE_RES: &str = "auth_vendors_map";
const SHORT_ID_LEN: usize = 15;
const URLSHORT_AUTH: &str = "X-URLShort-Auth";
const RESPONSE_HOST: &str = "X-Response-Host";

/// Generate a random short ID
fn generate_short_id() -> String {
    let mut rng = rng();
    (0..SHORT_ID_LEN)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

// Extract short ID from the URL
fn extract_short_id(req: &Request) -> Result<&str> {
    let short_id = req
        .get_path()
        .get(1..)
        .ok_or_else(|| anyhow!("mal-formatted URL"))?;

    if short_id
        .as_bytes()
        .iter()
        .any(|s| !s.is_ascii_alphanumeric())
    {
        return Err(anyhow!("mal-formatted short id"));
    };

    Ok(short_id)
}

/// Get redirect URL from short ID
fn get_redirect_url(req: &Request) -> Result<Response> {
    let short_id = extract_short_id(req)?;
    // open kv store
    let kv_store =
        KVStore::open(KV_STORE_RES)?.ok_or_else(|| anyhow!("kv store does not exist"))?;

    // lookup the short ID in the KV store
    let redir_entry = kv_store
        .lookup(short_id)
        .map_err(|e| anyhow!("redirect lookup failed: {e}"))?
        .take_body()
        .into_string();

    // separate EPOCH timestamp from the URL
    let (_epoch, redir_location) = redir_entry
        .split_once(' ')
        .ok_or_else(|| anyhow!("redirect entry is mal-formed"))?;

    Ok(Response::from_status(StatusCode::MOVED_PERMANENTLY)
        .with_header(header::LOCATION, redir_location)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
}

// Get vendor prefix from the config store
fn get_vendor_prefix(vendor_hdr: &str) -> Result<String> {
    // open config store
    let config_store = ConfigStore::try_open(CONF_STORE_RES)?;

    let vendor_prefix = config_store
        .get(vendor_hdr)
        .ok_or_else(|| anyhow!("Vendor prefix needs to be setup in service config"))?;

    Ok(vendor_prefix)
}

// Create short ID of a URL
fn create_short_url(req: &Request, vendor_hdr: &str) -> Result<Response> {
    // get vendor prefix from the config store
    let vendor_prefix = get_vendor_prefix(vendor_hdr)?;
    // generate a short ID with the vendor prefix
    let short_id = format!("{vendor_prefix}{}", generate_short_id());

    // The `RESPONSE_HOST` header should be present
    let Some(redir_domain) = req.get_header_str(RESPONSE_HOST) else {
        return Err(anyhow!("No response host found in a header"));
    };
    // Create a JSON of the shorten URL using our domain and the short ID
    let our_domain = req.get_header_str("host").unwrap_or("localhost");
    let short_url = format!("https://{our_domain}/{short_id}");
    let short_url_json = json!({"short": short_url});

    // create a mutable URL object, from received URL
    let mut redir_url = req.get_url().clone();
    // update the domain with the domain we received in a header
    redir_url.set_host(Some(redir_domain))?;

    // open KV store
    let kv_store = KVStore::open(KV_STORE_RES)?.ok_or_else(|| anyhow!("KV store not exists"))?;

    // create a redirect entry from EPOCH timestamp and the `redir_url`
    let redir_entry = format!(
        "{} {}",
        Utc::now().format("%s"),
        redir_url.as_str().replace("%23", "#")
    );

    println!("Redir URL to store: {redir_entry}");

    kv_store.insert(&short_id, redir_entry)?;
    Ok(Response::from_status(StatusCode::CREATED)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_body_text_plain(&serde_json::to_string_pretty(&short_url_json).unwrap()))
}

// Delete short ID of a URL
fn delete_short_url(req: &Request, short_id: &str) -> Result<Response> {
    // open KV store
    let kv_store =
        KVStore::open(KV_STORE_RES)?.ok_or_else(|| anyhow!("KV store does not exist"))?;

    // delete the entry from KV store
    match kv_store.delete(short_id) {
        Ok(()) => (),
        Err(e) => {
            return Ok(
                Response::from_status(StatusCode::NOT_FOUND).with_body_text_plain(&e.to_string())
            )
        }
    };

    // Create a response JSON of the shorten URL using our domain and the short ID
    let our_domain = req.get_header_str("host").unwrap_or("localhost");
    let short_url = format!("https://{our_domain}/{short_id}");
    let short_url_json = json!({"deleted": short_url});

    Ok(Response::from_status(StatusCode::ACCEPTED)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_body_text_plain(&serde_json::to_string_pretty(&short_url_json).unwrap()))
}

fn get_secret(name: &str) -> Result<Secret> {
    let secret_store = SecretStore::open(SECRET_STORE_RES)?;

    let passcode = secret_store
        .get(name)
        .ok_or_else(|| anyhow!("No passcode in secret store"))?;

    Ok(passcode)
}

// check if the request is authorized and vendor is allowed
// return the vendor name if authorized
fn authorized_vendor(req: &Request) -> Result<&str> {
    let auth_header = req
        .get_header_str(URLSHORT_AUTH)
        .ok_or_else(|| anyhow!("No auth header found"))?;

    let Some((hdr_vendor, hdr_secret)) = auth_header.split_once(' ') else {
        return Err(anyhow!("No passcode found in auth header"));
    };

    let auth_secret = get_secret(hdr_vendor)?;

    if auth_secret.plaintext() == hdr_secret.as_bytes() {
        Ok(hdr_vendor)
    } else {
        Err(anyhow!("Vendor passcode mismatch"))
    }
}

// handle DELETE
fn handle_delete(req: &Request) -> Result<Response> {
    let vendor_hdr = match authorized_vendor(req) {
        Ok(hdr_vendor) => hdr_vendor,
        Err(e) => {
            println!("Unauthorized request: {e}");
            return Ok(Response::from_status(StatusCode::UNAUTHORIZED)
                .with_body_text_plain(&format!("Unauthorized request: {e}\n")));
        }
    };
    let vendor_prefix = get_vendor_prefix(vendor_hdr)?;

    // extract short ID from the URL
    let short_id = extract_short_id(req)?;

    if !short_id.starts_with(&vendor_prefix) {
        return Ok(Response::from_status(StatusCode::FORBIDDEN)
            .with_body_text_plain(&format!("The short URL must start with {vendor_prefix}\n")));
    }

    match delete_short_url(req, short_id) {
        Ok(resp) => Ok(resp),
        Err(e) => Err(anyhow!("URL deletion failed: {e}")),
    }
}

// handle GET
fn handle_get(req: &Request) -> Result<Response> {
    // when Auth header received and verified - treat it as a shortening request:
    // * create the short URL and return the response
    if let Ok(has_vendor) = authorized_vendor(req) {
        let hdr_vendor = has_vendor;
        return match create_short_url(req, hdr_vendor) {
            Ok(resp) => Ok(resp),
            Err(e) => Err(anyhow!("URL shortening failed: {e}")),
        };
    }

    // when no Auth header - treat it as a short URL:
    // * lookup the kv store for the URI
    // * if a match found - return a stored redirect

    // always respond with 200 OK to `/` request
    if req.get_path() == "/" {
        // this helps with service deployment
        return Ok(Response::from_status(StatusCode::OK));
    }

    match get_redirect_url(req) {
        Ok(resp) => Ok(resp),
        Err(e) => {
            Ok(Response::from_status(StatusCode::NOT_FOUND).with_body_text_plain(&e.to_string()))
        }
    }
}

fn handle_options() -> Response {
    // handle OPTIONS
    Response::from_status(StatusCode::NO_CONTENT)
        .with_header(header::ALLOW, "GET, POST, OPTIONS")
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_header(header::ACCESS_CONTROL_ALLOW_HEADERS, "*")
        .with_header(header::ACCESS_CONTROL_ALLOW_METHODS, "*")
}

#[fastly::main]
fn main(req: Request) -> Result<Response> {
    match *req.get_method() {
        Method::GET => handle_get(&req),
        Method::DELETE => handle_delete(&req),
        Method::OPTIONS => Ok(handle_options()),
        _ => Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, POST, OPTIONS")
            .with_body_text_plain("This method is not allowed\n")),
    }
}

#[cfg(test)]
mod tests {
    use header::HOST;

    use super::*;

    #[test]
    fn test_generate_short_id() {
        let short_id = generate_short_id();
        assert_eq!(short_id.len(), SHORT_ID_LEN);
        assert!(short_id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_get_redirect_url() {
        let req = Request::get("http://localhost/STZmurkrcgBptG7mz").with_method(Method::GET);
        let response = get_redirect_url(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::MOVED_PERMANENTLY);
    }

    #[test]
    fn test_create_short_url() {
        let req = Request::get("http://localhost/whatever/something")
            .with_header(HOST, "test.com")
            .with_header(RESPONSE_HOST, "example.com")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");
        let response = create_short_url(&req, "vendor");
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::CREATED);
    }

    #[test]
    fn test_delete_short_url() {
        let req = Request::get("http://localhost/STv1jotZvbekUufNj").with_method(Method::DELETE);

        let short_id = req
            .get_path()
            .get(1..)
            .ok_or_else(|| anyhow!("mal-formatted URL"))
            .unwrap();

        let response = delete_short_url(&req, short_id);
        assert!(response.is_ok());
        let response = response.unwrap();
        println!("{:?}", response);
        assert_eq!(response.get_status(), StatusCode::ACCEPTED);
    }

    #[test]
    fn test_handle_get() {
        let req = Request::get("http://localhost/");
        let response = handle_get(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::OK);
    }

    #[test]
    fn test_handle_delete() {
        let req = Request::delete("http://localhost/SThTyfEo5uvCbxtZ3")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");
        let response = handle_delete(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::ACCEPTED);
    }

    #[test]
    fn test_delete_wrong_prefix() {
        let req = Request::delete("http://localhost/QTv1jotZvbekUufNj")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let response = handle_delete(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_handle_options() {
        let response = handle_options();
        assert_eq!(response.get_status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.get_header(header::ALLOW).unwrap(),
            "GET, POST, OPTIONS"
        );
    }
}
