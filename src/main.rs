use anyhow::{anyhow, Result};
use fastly::http::{header, Method, StatusCode};
use fastly::secret_store::Secret;
use fastly::{ObjectStore, Request, Response, SecretStore};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

const SECRETS_RES: &str = "secrets";
const CFG_OBJ_STORE_RES: &str = "short-urls-store-resource";
const CFG_SHORT_ID_LEN: usize = 8;
const URLSHORT_AUTH: &str = "X-URLShort-Auth";

/// Holds ID & URL mapping request: short ID (optional) and URL
#[derive(Serialize, Deserialize, Debug)]
struct MyRedirect {
    short: Option<String>,
    url: String,
}

/// Holds result of short ID creation
#[derive(serde::Serialize)]
struct CreationResult {
    short: String,
}

/// Generate a random short ID
fn generate_short_id() -> String {
    let mut rng = thread_rng();
    (0..CFG_SHORT_ID_LEN)
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
        ObjectStore::open(CFG_OBJ_STORE_RES)?.ok_or_else(|| anyhow!("object store not exists"))?;

    let redirect_location = object_store
        .lookup_str(short_id)?
        .ok_or_else(|| anyhow!("redirect location not found"))?;

    Ok(Response::from_status(StatusCode::MOVED_PERMANENTLY)
        .with_header(header::LOCATION, redirect_location)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
}

/// Create short ID of a URL
fn create_short_id(req: &mut Request) -> Result<Response> {
    let r = match req.get_content_type() {
        Some(mime) if fastly::mime::APPLICATION_WWW_FORM_URLENCODED == mime => {
            req.take_body_form::<MyRedirect>()?
        }
        _ => req.take_body_json::<MyRedirect>()?,
    };

    let short_id = r.short.map_or_else(generate_short_id, |short| {
        if short.is_empty() {
            generate_short_id()
        } else {
            short
        }
    });

    let mut object_store =
        ObjectStore::open(CFG_OBJ_STORE_RES)?.ok_or_else(|| anyhow!("object store not exists"))?;

    object_store.insert(&short_id, r.url)?;

    Ok(Response::from_status(StatusCode::CREATED)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_body_json(&CreationResult { short: short_id })?)
}

fn get_secret(name: &str) -> Result<Secret> {
    let secret_store = SecretStore::open(SECRETS_RES)?;

    let passcode = secret_store
        .get(name)
        .ok_or_else(|| anyhow!("No passcode in secret store"))?;

    Ok(passcode)
}

// handle GET
fn handle_get(req: &mut Request) -> Result<Response> {
    // when Auth header received - treat it as a shortening request:
    // * verify the header
    // * create the short URL and return the response
    if let Some(auth_header) = req.get_header_str(URLSHORT_AUTH) {
        let Some((hdr_vendor, hdr_secret)) = auth_header.split_once(' ') else {
            return Err(anyhow!("No passcode found in secret store"))
        };

        let auth_secret = get_secret(hdr_vendor)?;

        if auth_secret.plaintext() != hdr_secret.as_bytes() {
            return Err(anyhow!("Passcode mismatch"));
        }

        match create_short_id(req) {
            Ok(resp) => return Ok(resp),
            Err(e) => return Err(anyhow!("No passcode found in secret store: {e}")),
        }
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
fn main(mut req: Request) -> Result<Response> {
    match *req.get_method() {
        Method::GET => handle_get(&mut req),
        Method::OPTIONS => Ok(handle_options()),
        _ => Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, POST, OPTIONS")
            .with_body_text_plain("This method is not allowed\n")),
    }
}
