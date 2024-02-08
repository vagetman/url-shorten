# URL Shortening tool
The tool provides the following functionality for URL shortenin
* an secured API to create short URL
* it resolves shortened URL into its original destination

# Installation
Fastly kv strore, config store and secret store are required to be created and linked to the service where the app is published on Fastly Compute platform. 
The following constants should be updated with the name of stores linked to the service, if the names are different

```rust
const SECRET_STORE_RES: &str = "secret-auth-store";
const KV_STORE_RES: &str = "short-urls-store";
const CONF_STORE_RES: &str = "auth_vendors_map";
```
To deploy the service use the latest `fastly` tool [available on Fastly web site](https://developer.fastly.com/learning/tools/cli/).

# Usage
## The API shortening request
The API request for URL shortening takes the URI from the request and `X-Response-Host` header (see bellow). The API request should contain the following 2 headers. 
* `X-URLShort-Auth` - Authentication header. It's a space separated `vendor password` sequence. The `password` should be stored in secret store (see above) with `vendor` being a key to the secret value.
* `X-Response-Host` - the destination host for URI.

To encode URLs with a 'fragment' (`#<tag>`) the whole URL needs to be sent. User agents generally are not transmitting anything beyond `#` as the fragment is intended to be used locally only. Even if transmitted, it's not received and parsed correctly on Fastly platform. To transmit and receive the URL in its entirety the `#` should be sent in its URL-encoded form (`%23`). The code is making a reverse translation of `%23` back to `#`. 

The protocol is always `https`. When the API request succeeds `201 Created` response is returned.

## The URL expansion
When no headers is supplied the URI path is assumed a shorten key with a request to expansion. A KV store lookup is performed and an original URL. When found `301` response is returned with `location` header containing the original URL. Otherwise `404` is returned. 
