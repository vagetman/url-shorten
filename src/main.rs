use anyhow::{anyhow, Result};
use fastly::http::{header, Method, StatusCode};
use fastly::secret_store::Secret;
use fastly::{ObjectStore, Request, Response, SecretStore};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::json;

const SECRET_STORE_RES: &str = "secret-auth-store";
const OBJ_STORE_RES: &str = "short-urls-store";
const SHORT_ID_LEN: usize = 10;
const URLSHORT_AUTH: &str = "X-URLShort-Auth";
const RESPONSE_HOST: &str = "X-Response-Host";

/// Generate a random short ID
fn generate_short_id() -> String {
    let mut rng = thread_rng();
    (0..SHORT_ID_LEN)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

/// Get redirect URL from short ID
fn get_redirect_url(req: &Request) -> Result<Response> {
    // remove leading "/" in the path
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

    let object_store =
        ObjectStore::open(OBJ_STORE_RES)?.ok_or_else(|| anyhow!("object store not exists"))?;

    let redirect_location = object_store
        .lookup_str(short_id)?
        .ok_or_else(|| anyhow!("redirect location not found"))?;

    Ok(Response::from_status(StatusCode::MOVED_PERMANENTLY)
        .with_header(header::LOCATION, redirect_location)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
}

/// Create short ID of a URL
fn create_short_id(req: &Request) -> Result<Response> {
    // Generate a new short ID
    let short_id = generate_short_id();
    // The `RESPONSE_HOST` header should be present
    let Some(redir_domain) = req.get_header_str(RESPONSE_HOST) else {
        return Err(anyhow!("No response host found in a header"));
    };
    // Create a JSON of the shorten URL using our domain and the short ID
    let our_domain = req.get_header_str("host").unwrap();
    let short_url = format!("https://{our_domain}/{short_id}");
    let short_url_json = json!({"short": short_url});
    // create a mutable URL object, as it was received
    let mut redir_url = req.get_url().clone();
    // update the domain with the domain we received in a header
    redir_url.set_host(Some(redir_domain))?;

    let mut object_store =
        ObjectStore::open(OBJ_STORE_RES)?.ok_or_else(|| anyhow!("object store not exists"))?;

    println!("Redir URL to store: {redir_url}");

    object_store.insert(&short_id, redir_url.as_str())?;
    Ok(Response::from_status(StatusCode::CREATED)
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

// handle GET
fn handle_get(req: &Request) -> Result<Response> {
    // when Auth header received - treat it as a shortening request:
    // * verify the header
    // * create the short URL and return the response
    if let Some(auth_header) = req.get_header_str(URLSHORT_AUTH) {
        let Some((hdr_vendor, hdr_secret)) = auth_header.split_once(' ') else {
            return Err(anyhow!("No passcode found in auth header"));
        };

        let auth_secret = get_secret(hdr_vendor)?;

        if auth_secret.plaintext() != hdr_secret.as_bytes() {
            return Err(anyhow!("Passcode mismatch"));
        }

        return match create_short_id(req) {
            Ok(resp) => Ok(resp),
            Err(e) => Err(anyhow!("No passcode found in secret store: {e}")),
        };
    }

    // when no Auth header - treat it as a short URL:
    // * lookup the kv store for the URI
    // * if a match found - return a stored redirect

    // always respond with 200 OK to `/` request
    if req.get_path() == "/" {
        // this helps with service deployment
        Ok(Response::from_status(StatusCode::OK))
    } else {
        match get_redirect_url(req) {
            Ok(resp) => Ok(resp),
            Err(e) => {
                Ok(Response::from_status(StatusCode::NOT_FOUND)
                    .with_body_text_plain(&e.to_string()))
            }
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
        Method::OPTIONS => Ok(handle_options()),
        _ => Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, POST, OPTIONS")
            .with_body_text_plain("This method is not allowed\n")),
    }
}
