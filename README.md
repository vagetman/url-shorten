# URL Shortening Tool

This tool provides a simple and secure solution for URL shortening on Fastly Compute, offering users faster responses compared to central cloud services or on-premise solutions. The tool includes the following features::

- **Short URL Creation**: A secure API to generate shortened URLs.
- **URL Resolution**: Resolves shortened URLs back to their original destinations.
- **URL Deletion**: Removes the shortened URLs from KV store.
- **URL Purging**: Bulk deletion of expired URLs based on age thresholds.

---

## Installation

The service requires the following Fastly components to be created and linked to the app deployed on the Fastly Compute platform:

1. **KV Store**: Used for storing shortened URLs.
2. **Config Store**: Holds configuration details.
3. **Secret Store**: Used for securely storing authentication credentials.

Update the following constants in the code with the names of the linked stores, if they differ from the defaults:

```rust
const SECRET_STORE_RES: &str = "secret-auth-store";
const KV_STORE_RES: &str = "short-urls-store";
const CONF_STORE_RES: &str = "auth_vendors_map";
```

### Deployment

To deploy the service, use the latest version of the Fastly CLI tool, available for download on the [Fastly Developer Website](https://developer.fastly.com/learning/tools/cli/).

## Usage

### 1. **URL Shortening API Request**

To shorten a URL, the API request must include:

- The **URI** to be shortened (in the request body or path).
- The `X-Response-Host` header specifying the destination host for the shortened URL.

#### Required Headers:

- `X-URLShort-Auth`: An authentication header with a `vendor password` sequence, separated by a space. The `password` is stored in the Secret Store, with the `vendor` being the key to the secret value.
- `X-Response-Host`: The destination host for the shortened URL.

#### Response:

- If authentication is successful and the key is created, a `201 Created` response is returned. A JSON object with shortened URL is returned, eg

```
{
  "short": "https://example.com/STpll0DfpzQMZBInA"
}
```

#### Special Notes:

**URL Fragments (`#`):**  
User agents typically do not transmit fragments (`#<tag>`) in URLs. To include fragments, encode `#` as `%23` in the request. The tool will automatically decode `%23` back to `#` during processing.

**Collision Detection:**  
The service generates random alphanumeric short IDs with a vendor-specific prefix. Before storing a new short URL, it verifies that the generated key doesn't already exist in the KV store. If a collision is detected (extremely rare), the service automatically retries with a new random ID, ensuring every shortened URL is unique.

---

### 2. **URL Expansion**

To expand a shortened URL:

- Send a request without headers.
- The path in the URI is treated as the shortened key.

The service performs a lookup in the KV Store:

- If found, a `301 Moved Permanently` response is returned with the `Location` header pointing to the original URL.
- If not found, a `404 Not Found` response is returned.

---

### 3. **Redirect Deletion API**

To delete a shortened URL key from the KV Store, send a `DELETE` request with the following:

#### Required Header:

- `X-URLShort-Auth`: The same authentication header used for URL shortening.

#### Response:

- If authentication is unsuccessful `401 Unauthorized` response is returned.
- If the URL starts with anything other than a prefix defined for this vendor `403 Forbidden` response is retuned.
- If the key is not found, a `404 Not Found` response is returned.
- If authentication is successful and the key exists, a `202 Accepted` response is returned. A JSON object in the response body will indicate deleted key.

```json
{
  "deleted": "https://example.com/STKot65UQdbESV9kE"
}
```

---

### 3. **Redirect URL Purging API**

To bulk delete expired shortened URLs from the KV Store, send a `PURGE` request with the following:

#### Request Format:

```
PURGE /age/{unit}/{value}[?preview=true][&verbose=true]
```

- **Path Parameters**:

  - `unit`: Time unit - `days`, `months`, or `years`
  - `value`: Numeric value for the age threshold

- **Query Parameters** (optional):
  - `preview=true`: Preview mode - shows what would be deleted without actually deleting
  - `verbose=true`: Include detailed list of URLs in the response

#### Required Header:

- `X-URLShort-Auth`: The same authentication header used for URL shortening.

#### Response:

- If authentication is unsuccessful, a `401 Unauthorized` response is returned.
- If authentication is successful, a `200 OK` response is returned with a JSON object.

#### Examples:

**Example 1: Actual purge (delete URLs older than 30 days)**

```bash
curl -X PURGE "https://example.com/age/days/30" \
  -H "X-URLShort-Auth: vendor SECRET"
```

Response:

```json
{
  "status": "purge_completed",
  "preview_mode": false,
  "vendor_prefix": "ST",
  "cutoff_days": 30,
  "cutoff_timestamp": 1729814400,
  "cutoff_date": "2024-10-25 00:00:00 UTC",
  "checked": 150,
  "would_delete": null,
  "deleted": 2,
  "skipped": 108,
  "errors": []
}
```

---

**Example 2: Preview mode (see what would be deleted without deleting)**

```bash
curl -X PURGE "https://example.com/age/days/30?preview=true" \
  -H "X-URLShort-Auth: vendor SECRET"
```

Response:

```json
{
  "status": "preview_completed",
  "preview_mode": true,
  "vendor_prefix": "ST",
  "cutoff_days": 30,
  "cutoff_timestamp": 1729814400,
  "cutoff_date": "2024-10-25 00:00:00 UTC",
  "checked": 150,
  "would_delete": 2,
  "deleted": null,
  "skipped": 108,
  "errors": []
}
```

---

**Example 3: Preview with verbose (detailed list of URLs to be deleted)**

```bash
curl -X PURGE "https://example.com/age/months/6?preview=true&verbose=true" \
  -H "X-URLShort-Auth: vendor SECRET"
```

Response:

```json
{
  "status": "preview_completed",
  "preview_mode": true,
  "vendor_prefix": "ST",
  "cutoff_days": 180,
  "cutoff_timestamp": 1714000000,
  "cutoff_date": "2024-04-25 00:00:00 UTC",
  "checked": 150,
  "would_delete": 2,
  "deleted": null,
  "skipped": 108,
  "errors": [],
  "items": [
    {
      "short_id": "STpll0DfpzQMZBInA",
      "url": "https://example.com/original",
      "created_at": 1720000000,
      "created_date": "2024-07-03 12:26:40 UTC",
      "age_days": 145
    },
    {
      "short_id": "STabc123xyz456789",
      "url": "https://example.com/another-url",
      "created_at": 1715000000,
      "created_date": "2024-05-06 12:13:20 UTC",
      "age_days": 203
    }
  ]
}
```

---

**Example 4: Actual purge with verbose (detailed list of deleted URLs)**

```bash
curl -X PURGE "https://example.com/age/years/1?verbose=true" \
  -H "X-URLShort-Auth: vendor SECRET"
```

Response:

```json
{
  "status": "purge_completed",
  "preview_mode": false,
  "vendor_prefix": "ST",
  "cutoff_days": 365,
  "cutoff_timestamp": 1700000000,
  "cutoff_date": "2023-11-15 00:00:00 UTC",
  "checked": 500,
  "would_delete": null,
  "deleted": 2,
  "skipped": 108,
  "errors": [],
  "items": [
    {
      "short_id": "STpll0DfpzQMZBInA",
      "url": "https://example.com/original",
      "created_at": 1720000000,
      "created_date": "2024-07-03 12:26:40 UTC",
      "age_days": 145
    },
    {
      "short_id": "STabc123xyz456789",
      "url": "https://example.com/another-url",
      "created_at": 1715000000,
      "created_date": "2024-05-06 12:13:20 UTC",
      "age_days": 203
    }
  ]
}
```

---

#### Response Fields:

- `status`: Operation status - `preview_completed` or `purge_completed`
- `preview_mode`: Boolean indicating if this was a preview
- `vendor_prefix`: The vendor prefix used for filtering URLs
- `cutoff_days`: Age threshold in days
- `cutoff_timestamp`: Unix timestamp for the cutoff date
- `cutoff_date`: Human-readable cutoff date
- `checked`: Total number of URLs examined
- `would_delete`: Number of URLs that would be deleted (number in preview mode, `null` in actual mode)
- `deleted`: Number of URLs that were deleted (number in actual mode, `null` in preview mode)
- `skipped`: Number of URLs skipped (newer than threshold)
- `errors`: Array of error messages, if any
- `items`: Detailed list of URLs with their metadata (only present when `verbose=true`)
