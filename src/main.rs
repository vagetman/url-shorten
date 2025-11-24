use anyhow::{Result, anyhow};
use chrono::prelude::*;
use fastly::http::{Method, StatusCode, header};
use fastly::kv_store::{InsertMode, KVStoreError};
use fastly::secret_store::Secret;
use fastly::{ConfigStore, KVStore, Request, Response, SecretStore};
use rand::distr::Alphanumeric;
use rand::{Rng, rng};
use serde_json::Value::Null;
use serde_json::json;

const SECRET_STORE_RES: &str = "secret-auth-store";
const KV_STORE_RES: &str = "short-urls-store";
const CONF_STORE_RES: &str = "auth_vendors_map";
const SHORT_ID_LEN: usize = 15;
const URLSHORT_AUTH: &str = "X-URLShort-Auth";
const RESPONSE_HOST: &str = "X-Response-Host";
// Time constants are i64 to match Unix timestamp type from chrono::Utc::now().timestamp()
// This avoids type conversions when doing timestamp arithmetic
const DAYS_PER_MONTH: i64 = 30;
const DAYS_PER_YEAR: i64 = 365;
const SECONDS_PER_DAY: i64 = 86400;
const MAX_ID_GENERATION_ATTEMPTS: u32 = 10;

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
    }

    Ok(short_id)
}

/// Get redirect URL from short ID
fn get_redirect_url(req: &Request) -> Result<Response> {
    let short_id = extract_short_id(req)?;
    // open kv store
    let kv_store = open_kv_store()?;

    // lookup the short ID in the KV store
    let mut lookup_result = kv_store
        .build_lookup()
        .execute(short_id)
        .map_err(|e| anyhow!("redirect lookup failed: {e}"))?;

    let redir_entry = lookup_result.take_body().into_string();

    // separate EPOCH timestamp from the URL
    let (_epoch, redir_location) = redir_entry
        .split_once(' ')
        .ok_or_else(|| anyhow!("redirect entry is mal-formed"))?;

    Ok(with_cors(
        Response::from_status(StatusCode::MOVED_PERMANENTLY)
            .with_header(header::LOCATION, redir_location),
    ))
}

// Helper function to open KV store
fn open_kv_store() -> Result<KVStore> {
    KVStore::open(KV_STORE_RES)?.ok_or_else(|| anyhow!("KV store does not exist"))
}

// Helper function to format short URL from request and short ID
fn format_short_url(req: &Request, short_id: &str) -> String {
    let our_domain = req.get_header_str("host").unwrap_or("localhost");
    format!("https://{our_domain}/{short_id}")
}

// Helper function to get vendor prefix from config store
fn get_vendor_prefix(vendor_hdr: &str) -> Result<String> {
    let config_store = ConfigStore::try_open(CONF_STORE_RES)?;

    let vendor_prefix = config_store
        .get(vendor_hdr)
        .ok_or_else(|| anyhow!("Vendor prefix needs to be setup in service config"))?;

    Ok(vendor_prefix)
}

// Helper function to generate short ID with vendor prefix, checking for collisions
// Returns the short_id and the redir_entry that should be inserted
fn insert_unique_short_id(
    vendor_hdr: &str,
    kv_store: &KVStore,
    redir_entry: &str,
) -> Result<String> {
    let vendor_prefix = get_vendor_prefix(vendor_hdr)?;

    // Create RNG once and reuse it for all attempts (optimization for collision retries)
    let mut rng = rng();

    // Try to generate a unique short ID, using InsertMode::Add for collision detection
    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > MAX_ID_GENERATION_ATTEMPTS {
            return Err(anyhow!(
                "Failed to generate unique short ID after {MAX_ID_GENERATION_ATTEMPTS} attempts"
            ));
        }

        // Generate random suffix inline to reuse the RNG instance
        let random_suffix: String = (0..SHORT_ID_LEN)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect();
        let short_id = format!("{vendor_prefix}{random_suffix}");

        // Try to insert with Add mode - fails if key already exists (ItemPreconditionFailed)
        match kv_store
            .build_insert()
            .mode(InsertMode::Add)
            .execute(&short_id, redir_entry)
        {
            Ok(()) => {
                // Success - ID is unique and value is inserted
                return Ok(short_id);
            }
            Err(KVStoreError::ItemPreconditionFailed) => {
                // Collision detected - ID already exists, try again
                println!("Short ID collision detected: {short_id}, retrying...");
            }
            Err(e) => {
                // Other error occurred
                return Err(anyhow!("KV store insert failed: {e}"));
            }
        }
    }
}

// Create short ID of a URL
fn create_short_url(req: &Request, vendor_hdr: &str) -> Result<Response> {
    // The `RESPONSE_HOST` header should be present
    let Some(redir_domain) = req.get_header_str(RESPONSE_HOST) else {
        return Err(anyhow!("No response host found in a header"));
    };

    // create a mutable URL object, from received URL
    let mut redir_url = req.get_url().clone();
    // update the domain with the domain we received in a header
    redir_url.set_host(Some(redir_domain))?;

    // open KV store
    let kv_store = open_kv_store()?;

    // create a redirect entry from EPOCH timestamp and the `redir_url`
    let redir_entry = format!(
        "{} {}",
        Utc::now().format("%s"),
        // `#` is encoded to `%23` on request URLs, but should be stored as is in KV store
        redir_url.as_str().replace("%23", "#")
    );

    println!("Redir URL to store: {redir_entry}");

    // Generate a unique short ID with collision detection and insert atomically
    // The insert happens inside build_short_id_for_vendor using InsertMode::Add
    let short_id = insert_unique_short_id(vendor_hdr, &kv_store, &redir_entry)?;

    // Create a JSON of the shorten URL using our domain and the short ID
    let short_url = format_short_url(req, &short_id);
    let short_url_json = json!({"short": short_url});

    Ok(with_cors(
        Response::from_status(StatusCode::CREATED)
            .with_body_text_plain(&json_to_string(&short_url_json)),
    ))
}

// Delete short ID of a URL
fn delete_short_url(req: &Request, short_id: &str) -> Result<Response> {
    // open KV store
    let kv_store = open_kv_store()?;

    // delete the entry from KV store
    if let Err(e) = kv_store.build_delete().execute(short_id) {
        return Ok(
            Response::from_status(StatusCode::NOT_FOUND).with_body_text_plain(&e.to_string())
        );
    }

    // Create a response JSON of the shorten URL using our domain and the short ID
    let short_url = format_short_url(req, short_id);
    let short_url_json = json!({"deleted": short_url});

    Ok(with_cors(
        Response::from_status(StatusCode::ACCEPTED)
            .with_body_text_plain(&json_to_string(&short_url_json)),
    ))
}

// Helper function to format timestamp as human-readable date
fn format_timestamp(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp, 0).map_or_else(
        || "Invalid date".to_string(),
        |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    )
}

// Helper to create error response with status and message
fn error_response(status: StatusCode, message: &str) -> Response {
    Response::from_status(status).with_body_text_plain(message)
}

// Helper to add CORS headers to response
fn with_cors(response: Response) -> Response {
    response.with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
}

// Helper to serialize JSON with fallback to non-pretty format
fn json_to_string(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

// Parse age threshold from URL path like /age/days/30, /age/months/6, /age/years/1
fn parse_age_threshold(path: &str) -> Result<i64> {
    let mut parts = path.trim_start_matches('/').split('/');

    // Check format without allocating a Vec
    if parts.clone().count() != 3 {
        return Err(anyhow!(
            "Invalid path format. Expected /age/days/N, /age/months/N, or /age/years/N"
        ));
    }

    // Safe to unwrap because we verified count == 3
    let (age_endpoint, unit, value_str) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );

    if age_endpoint != "age" {
        return Err(anyhow!(
            "Invalid path format. Expected /age/days/N, /age/months/N, or /age/years/N"
        ));
    }

    let value = value_str
        .parse::<i64>()
        .map_err(|_| anyhow!("Invalid numeric value: {value_str}"))?;

    let days = match unit {
        "days" => value,
        "months" => value
            .checked_mul(DAYS_PER_MONTH)
            .ok_or_else(|| anyhow!("Age threshold overflow"))?,
        "years" => value
            .checked_mul(DAYS_PER_YEAR)
            .ok_or_else(|| anyhow!("Age threshold overflow"))?,
        _ => {
            return Err(anyhow!(
                "Invalid time unit. Expected 'days', 'months', or 'years'"
            ));
        }
    };

    Ok(days)
}

// Purge old URLs from KV store - iterates through keys with vendor prefix
fn purge_expired_urls(
    vendor_prefix: &str,
    days_old: i64,
    preview_mode: bool,
    verbose_mode: bool,
) -> Result<Response> {
    let kv_store = open_kv_store()?;

    // Get the current timestamp
    let now = Utc::now().timestamp();
    let cutoff_timestamp = now
        .checked_sub(days_old * SECONDS_PER_DAY)
        .ok_or_else(|| anyhow!("Timestamp calculation overflow"))?;

    let mut deleted_count = 0;
    let mut checked_count = 0;
    let mut errors: Vec<String> = Vec::new();
    let mut skipped_count = 0;
    let mut items: Vec<serde_json::Value> = Vec::new();

    // Use the list API with prefix filter to iterate through keys
    let list_response = kv_store.build_list().prefix(vendor_prefix).iter();

    // Iterate through all pages of results
    for page_result in list_response {
        let page = page_result?;

        for key in page.keys() {
            checked_count += 1;

            // Lookup the entry
            match kv_store.build_lookup().execute(key) {
                Ok(mut entry) => {
                    let redir_entry = entry.take_body().into_string();

                    // Parse the EPOCH timestamp from the entry
                    if let Some((epoch_str, url)) = redir_entry.split_once(' ') {
                        if let Ok(epoch) = epoch_str.parse::<i64>() {
                            if epoch < cutoff_timestamp {
                                let age_days = (now - epoch) / SECONDS_PER_DAY;
                                let created_date = format_timestamp(epoch);

                                // Collect item details if verbose mode is enabled
                                if verbose_mode {
                                    items.push(json!({
                                        "short_id": key,
                                        "url": url,
                                        "created_at": epoch,
                                        "created_date": created_date,
                                        "age_days": age_days
                                    }));
                                }

                                if preview_mode {
                                    // In preview mode, just count without deleting
                                    deleted_count += 1;
                                } else {
                                    // Actually delete the entry
                                    match kv_store.build_delete().execute(key) {
                                        Ok(()) => {
                                            deleted_count += 1;
                                            // println!(
                                            //     "Purged old entry: {key} (age: {age_days} days)"
                                            // );
                                        }
                                        Err(e) => {
                                            errors.push(format!("Failed to delete {key}: {e}"));
                                        }
                                    }
                                }
                            } else {
                                skipped_count += 1;
                            }
                        } else {
                            errors.push(format!("Invalid timestamp in entry: {key}"));
                        }
                    } else {
                        errors.push(format!("Malformed entry: {key}"));
                    }
                }
                Err(e) => {
                    errors.push(format!("Failed to lookup {key}: {e}"));
                }
            }
        }
    }

    let cutoff_date = format_timestamp(cutoff_timestamp);

    let mut result = json!({
        "status": if preview_mode { "preview_completed" } else { "purge_completed" },
        "preview_mode": preview_mode,
        "vendor_prefix": vendor_prefix,
        "cutoff_days": days_old,
        "cutoff_timestamp": cutoff_timestamp,
        "cutoff_date": cutoff_date,
        "checked": checked_count,
        "would_delete": if preview_mode { json!(deleted_count) } else { Null },
        "deleted": if preview_mode { Null } else { json!(deleted_count) },
        "skipped": skipped_count,
        "errors": errors
    });

    // Add items array if verbose mode is enabled (works in both preview and actual purge)
    if verbose_mode && !items.is_empty() {
        result["items"] = json!(items);
    }

    Ok(with_cors(
        Response::from_status(StatusCode::OK).with_body_text_plain(&json_to_string(&result)),
    ))
}

// get secret passcode for the vendor from secret store
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
            return Ok(error_response(
                StatusCode::UNAUTHORIZED,
                &format!("Unauthorized request: {e}\n"),
            ));
        }
    };
    let vendor_prefix = get_vendor_prefix(vendor_hdr)?;

    // extract short ID from the URL
    let short_id = extract_short_id(req)?;

    if !short_id.starts_with(&vendor_prefix) {
        return Ok(error_response(
            StatusCode::FORBIDDEN,
            &format!("The short URL must start with {vendor_prefix}\n"),
        ));
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
        Err(e) => Ok(error_response(StatusCode::NOT_FOUND, &e.to_string())),
    }
}

// handle PURGE
fn handle_purge(req: &Request) -> Result<Response> {
    // Check authorization
    let vendor_hdr = match authorized_vendor(req) {
        Ok(hdr_vendor) => hdr_vendor,
        Err(e) => {
            println!("Unauthorized request: {e}");
            return Ok(error_response(
                StatusCode::UNAUTHORIZED,
                &format!("Unauthorized request: {e}\n"),
            ));
        }
    };

    // Get vendor prefix
    let vendor_prefix = get_vendor_prefix(vendor_hdr)?;

    // Parse the age threshold from the URL path
    let days_old = parse_age_threshold(req.get_path())?;

    // Parse query parameters in a single pass
    let (preview_mode, verbose_mode) = req.get_url().query_pairs().fold(
        (false, false),
        |(preview, verbose), (key, value)| match (key.as_ref(), value.as_ref()) {
            ("preview", "true") => (true, verbose),
            ("verbose", "true") => (preview, true),
            _ => (preview, verbose),
        },
    );

    // println!(
    //     "Purging URLs older than {days_old} days for vendor: {vendor_hdr} (prefix: {vendor_prefix})"
    // );

    match purge_expired_urls(&vendor_prefix, days_old, preview_mode, verbose_mode) {
        Ok(resp) => Ok(resp),
        Err(e) => Err(anyhow!("URL purge failed: {e}")),
    }
}

fn handle_options() -> Response {
    // handle OPTIONS
    Response::from_status(StatusCode::NO_CONTENT)
        .with_header(header::ALLOW, "GET, DELETE, PURGE, OPTIONS")
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .with_header(header::ACCESS_CONTROL_ALLOW_HEADERS, "*")
        .with_header(header::ACCESS_CONTROL_ALLOW_METHODS, "*")
}

#[fastly::main]
fn main(req: Request) -> Result<Response> {
    let method_str = req.get_method_str();

    match *req.get_method() {
        Method::GET => handle_get(&req),
        Method::DELETE => handle_delete(&req),
        Method::OPTIONS => Ok(handle_options()),
        _ if method_str == "PURGE" => handle_purge(&req),
        _ => Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(header::ALLOW, "GET, DELETE, PURGE, OPTIONS")
            .with_body_text_plain("This method is not allowed\n")),
    }
}

#[cfg(test)]
mod tests {
    use header::HOST;

    use super::*;

    #[test]
    fn test_generate_short_id() {
        // Test the inline short ID generation logic
        let mut rng = rng();
        let short_id: String = (0..SHORT_ID_LEN)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect();
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

        let short_id = extract_short_id(&req).unwrap();

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
            "GET, DELETE, PURGE, OPTIONS"
        );
    }

    #[test]
    fn test_parse_age_threshold() {
        // Test days
        assert_eq!(parse_age_threshold("/age/days/30").unwrap(), 30);

        // Test months
        assert_eq!(parse_age_threshold("/age/months/6").unwrap(), 180);

        // Test years
        assert_eq!(parse_age_threshold("/age/years/1").unwrap(), 365);

        // Test invalid unit
        assert!(parse_age_threshold("/age/weeks/2").is_err());

        // Test with 0 days
        assert_eq!(parse_age_threshold("/age/days/0").unwrap(), 0);

        // Test with large numbers
        assert_eq!(parse_age_threshold("/age/years/10").unwrap(), 3650);

        // Test with invalid format
        assert!(parse_age_threshold("/age/").is_err());

        // Test with wrong prefix
        assert!(parse_age_threshold("/old/days/30").is_err());

        // Test with non-numeric value
        assert!(parse_age_threshold("/age/days/abc").is_err());
    }

    #[test]
    fn test_purge_old_urls() {
        let req = Request::new("PURGE", "http://localhost/age/days/30")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let response = handle_purge(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::OK);
    }

    #[test]
    fn test_purge_unauthorized() {
        let req = Request::new("PURGE", "http://localhost/age/days/30");

        let response = handle_purge(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_purge_invalid_path() {
        let req = Request::new("PURGE", "http://localhost/invalid/path")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let response = handle_purge(&req);
        assert!(response.is_err());
    }

    #[test]
    fn test_purge_preview_mode() {
        let req = Request::new("PURGE", "http://localhost/age/days/30?preview=true")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let response = handle_purge(&req);
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.get_status(), StatusCode::OK);

        // Parse response body to verify preview mode
        let body = response.into_body_str();
        assert!(body.contains("preview_mode"));
        assert!(body.contains("preview_completed"));
    }

    #[test]
    fn test_purge_preview_mode_query_param() {
        // Test that query parameter is correctly parsed
        let req = Request::new("PURGE", "http://localhost/age/days/30?preview=true")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let has_preview = req
            .get_url()
            .query_pairs()
            .any(|(key, value)| key == "preview" && value == "true");
        assert!(has_preview);
    }

    #[test]
    fn test_purge_no_preview_mode() {
        let req = Request::new("PURGE", "http://localhost/age/days/30")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let has_preview = req
            .get_url()
            .query_pairs()
            .any(|(key, value)| key == "preview" && value == "true");
        assert!(!has_preview);
    }

    #[test]
    fn test_purge_with_different_ages() {
        // Test 7 days
        let req = Request::new("PURGE", "http://localhost/age/days/7")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");
        let response = handle_purge(&req);
        assert!(response.is_ok());
        assert_eq!(response.unwrap().get_status(), StatusCode::OK);

        // Test 3 months
        let req = Request::new("PURGE", "http://localhost/age/months/3")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");
        let response = handle_purge(&req);
        assert!(response.is_ok());
        assert_eq!(response.unwrap().get_status(), StatusCode::OK);

        // Test 2 years
        let req = Request::new("PURGE", "http://localhost/age/years/2")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");
        let response = handle_purge(&req);
        assert!(response.is_ok());
        assert_eq!(response.unwrap().get_status(), StatusCode::OK);
    }

    #[test]
    fn test_purge_response_structure() {
        let req = Request::new("PURGE", "http://localhost/age/days/30?preview=true")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let response = handle_purge(&req);
        assert!(response.is_ok());
        let response = response.unwrap();

        let body = response.into_body_str();

        // Verify required fields are present
        assert!(body.contains("\"status\""));
        assert!(body.contains("\"preview_mode\""));
        assert!(body.contains("\"vendor_prefix\""));
        assert!(body.contains("\"cutoff_days\""));
        assert!(body.contains("\"cutoff_timestamp\""));
        assert!(body.contains("\"checked\""));
        assert!(body.contains("\"skipped\""));
        assert!(body.contains("\"errors\""));

        // In preview mode, should have would_delete, not deleted
        assert!(body.contains("\"would_delete\""));
    }

    #[test]
    fn test_purge_actual_mode_response() {
        let req = Request::new("PURGE", "http://localhost/age/days/365")
            .with_header(URLSHORT_AUTH, "vendor F1B7D119CE3B5CB1084509B79F2B9FBA");

        let response = handle_purge(&req);
        assert!(response.is_ok());
        let response = response.unwrap();

        let body = response.into_body_str();

        // In actual mode, should have deleted, not would_delete
        assert!(body.contains("\"deleted\""));
        assert!(body.contains("purge_completed"));
    }

    #[test]
    fn test_parse_age_threshold_edge_cases() {
        // Test with 0 days (should work)
        let result = parse_age_threshold("/age/days/0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // Test with large numbers
        let result = parse_age_threshold("/age/years/10");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3650);

        // Test with invalid format
        let result = parse_age_threshold("/age/");
        assert!(result.is_err());

        // Test with wrong prefix
        let result = parse_age_threshold("/old/days/30");
        assert!(result.is_err());

        // Test with non-numeric value
        let result = parse_age_threshold("/age/days/abc");
        assert!(result.is_err());
    }
}
