# URL Shortening Tool

This tool provides a simple and secure solution for URL shortening on Fastly Compute, offering users faster responses compared to central cloud services or on-premise solutions. The tool includes the following features::

- **Short URL Creation**: A secure API to generate shortened URLs.
- **URL Resolution**: Resolves shortened URLs back to their original destinations.
- **URL Deletion**: Removes the shortened URLs from KV store.

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

#### Special Note on URL Fragments (`#`):

User agents typically do not transmit fragments (`#<tag>`) in URLs. To include fragments, encode `#` as `%23` in the request. The tool will automatically decode `%23` back to `#` during processing.

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

```
{
  "deleted": "https://example.com/STKot65UQdbESV9kE"
}
```
