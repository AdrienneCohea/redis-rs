## AWS IAM Authentication Plan for redis-rs

### How AWS IAM Auth for Redis Works

Unlike Azure Entra ID (which uses JWTs via OAuth2), AWS IAM auth for ElastiCache/MemoryDB uses **SigV4 pre-signed URLs** as the password:

1. You construct an HTTP GET request to `http://{cluster_name}/?Action=connect&User={user_id}`
2. Sign it with AWS SigV4, placing the signature in query params (pre-signed URL style)
3. Strip the `http://` prefix — the resulting URL string **is** the password
4. Send `AUTH <user_id> <token>` to Redis

**Key differences from Entra ID:**
- Token is a pre-signed URL, **not a JWT** — no OID extraction needed
- Username is the ElastiCache/MemoryDB user ID (provided by the caller, not extracted from the token)
- Token lifetime is **15 minutes** (vs. Azure's longer-lived OAuth tokens)
- Connections can live up to **12 hours** before requiring re-auth
- Supports both ElastiCache (service name `elasticache`) and MemoryDB (service name `memorydb`)

### Architecture

You can follow the exact same pattern as `EntraIdCredentialsProvider`, leveraging the existing `StreamingCredentialsProvider` trait and `token-based-authentication` infrastructure.

#### New Files

**`redis/src/aws_iam.rs`** — The AWS IAM credentials provider, mirroring `entra_id.rs`:

```
AwsIamCredentialsProvider
├── Fields:
│   ├── credentials_provider: SharedCredentialsProvider (from aws-config)
│   ├── user_id: String                    (ElastiCache/MemoryDB user ID)
│   ├── host_name: String                   (cluster endpoint hostname)
│   ├── region: String                     (AWS region)
│   ├── service_name: AwsRedisServiceName  (elasticache | memorydb)
│   ├── is_serverless: bool                (adds ResourceType=ServerlessCache param)
│   ├── subscribers: Arc<Mutex<Vec<Sender>>>          (SharedSubscriptions type alias)
│   ├── current_credentials: Arc<RwLock<Option<BasicAuth>>>  (for immediate yield to new subscribers)
│   └── background_handle: Arc<Mutex<Option<JoinHandle>>>    (Arc+Mutex needed for start/stop/Drop)
│
├── Constructors:
│   ├── new(user_id, host_name, region, service_name, credentials_provider)
│   ├── new_from_env(user_id, host_name, region, service_name)
│   │     → Uses aws_config::defaults + DefaultCredentialsChain
│   └── Builder pattern for optional settings (is_serverless, custom refresh config)
│
├── Token Generation:
│   └── generate_auth_token(&self) -> Result<String>
│         → Build URL, SigV4 presign, strip http://
│
├── Background Refresh:
│   └── start(retry_config: RetryConfig) → spawns tokio task
│         → Generates token every ~12 minutes (fixed interval, 80% of 15m lifetime)
│         → Stores BasicAuth in current_credentials for new subscribers
│         → Pushes BasicAuth { username: user_id, password: token } to subscribers
│         → Retry with exponential backoff on failure (backon ExponentialBuilder)
│         → Stops and notifies subscribers with error after max retries exhausted
│
├── impl StreamingCredentialsProvider:
│   └── subscribe() → returns Stream<Item = RedisResult<BasicAuth>>
│         → Creates mpsc channel, adds sender to subscribers list
│         → If current_credentials is Some, yields it immediately via stream::once
│         → Chains with unfold stream for future updates (mirrors EntraId pattern)
│
├── impl Drop:
│   └── drop() → calls stop() to abort the background task (prevents leaked tasks)
│
└── impl Debug:
    └── fmt() → debug_struct with fields, redacting credential_provider
```

#### New Feature Flag

```toml
# redis/Cargo.toml
[dependencies]
aws-sigv4 = { version = "1", optional = true }
aws-credential-types = { version = "1", optional = true }
aws-config = { version = "1", optional = true }
aws-smithy-runtime-api = { version = "1", optional = true }
http = { version = "1", optional = true }  # needed for constructing HTTP request for SigV4 signing

[features]
aws-iam = [
    "dep:aws-sigv4",
    "dep:aws-credential-types",
    "dep:aws-config",
    "dep:aws-smithy-runtime-api",
    "dep:http",
    "token-based-authentication",  # reuse existing infra
    "tokio-comp"
]
```

> **Note:** The `http` crate is required because `aws-sigv4`'s signing API operates on
> `http::Request` types. Verify exact version compatibility with the `aws-sigv4` version chosen.

#### Changes to Existing Files

- **`redis/src/lib.rs`** — Two additions, mirroring the `entra-id` pattern:
  1. Module declaration:
     ```rust
     #[cfg(feature = "aws-iam")]
     #[cfg_attr(docsrs, doc(cfg(feature = "aws-iam")))]
     pub mod aws_iam;
     ```
  2. Re-exports (alongside the existing `entra-id` re-exports):
     ```rust
     #[cfg(feature = "aws-iam")]
     pub use crate::aws_iam::{AwsIamCredentialsProvider, AwsRedisServiceName};
     ```
- **No changes needed** to `auth.rs`, `auth_management.rs`, `client.rs`, `connection.rs`, or `multiplexed_connection.rs` — the existing `StreamingCredentialsProvider` trait + `open_with_credentials_provider` works as-is

#### Token Generation (Core Logic)

```rust
fn generate_auth_token(&self) -> RedisResult<String> {
    let mut url = format!(
        "http://{}/?Action=connect&User={}",
        self.host_name, self.user_id
    );
    if self.is_serverless {
        url.push_str("&ResourceType=ServerlessCache");
    }

    // SigV4 presign with 900s (15 min) expiry
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(Duration::from_secs(900));

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&self.region)
        .name(self.service_name.as_str())  // "elasticache" or "memorydb"
        .time(SystemTime::now())
        .settings(settings)
        .build()?;

    // Sign, apply to request, strip "http://" prefix
    let signed_url = /* ... */;
    Ok(signed_url.strip_prefix("http://").unwrap().to_string())
}
```

#### Refresh Strategy

| Parameter | Recommended Value |
|---|---|
| Token validity | 15 minutes (AWS maximum) |
| Refresh interval | ~12 minutes (fixed, 80% of 15m lifetime) |
| Connection re-auth | Before 12-hour window expires |
| Retry config | Reuse existing `RetryConfig` (exponential backoff via `backon::ExponentialBuilder`) |

**Approach:** Use a fixed refresh interval of ~12 minutes (720 seconds). Unlike EntraId which
subtracts a hardcoded `TOKEN_REFRESH_BUFFER_SECS` (240s) from the actual token expiry returned by
Azure, AWS IAM tokens always have a fixed 15-minute lifetime. The `start()` method takes
`RetryConfig` directly (matching `EntraIdCredentialsProvider::start(&mut self, retry_config: RetryConfig)`).
The `TokenRefreshConfig` type exists in `auth_management.rs` but is currently unused by EntraId —
we follow the same pattern and use `RetryConfig` directly for now.

### Usage Would Look Like

```rust
use redis::{Client, AwsIamCredentialsProvider, AwsRedisServiceName, RetryConfig};

// Using default AWS credential chain (env vars, ~/.aws, IMDS, etc.)
let mut provider = AwsIamCredentialsProvider::new_from_env(
    "my-redis-user",           // ElastiCache/MemoryDB user ID
    "my-cluster.abc.cache.amazonaws.com",  // cluster endpoint
    "us-east-1",
    AwsRedisServiceName::ElastiCache,
).await?;

provider.start(RetryConfig::default());

let client = Client::open_with_credentials_provider(
    "rediss://my-cluster.abc.cache.amazonaws.com:6379",
    provider,
)?;

let mut con = client.get_multiplexed_async_connection().await?;
```

### Testing Strategy

Following the established patterns from `entra_id.rs` and `tests/test_auth.rs`:

#### Unit Tests (in `redis/src/aws_iam.rs`)

- **Mock `CredentialsProvider`**: Create a `MockAwsCredentialsProvider` implementing the AWS
  `ProvideCredentials` trait, similar to EntraId's `MockTokenCredential`. Support scenarios:
  - `success()` — always returns valid `Credentials`
  - `failure()` — always returns a credential error
  - `alternating_fail_success()` — fails then succeeds (tests retry behavior)
  - `multiple_tokens()` — returns different credentials over time
- **Test cases** (mirroring EntraId's test suite):
  - Provider creation without panicking
  - Successful token generation (verify URL format, `http://` prefix stripped)
  - `subscribe()` yields current credentials immediately when available
  - Multiple concurrent subscribers all receive updates
  - Token refresh over time with mock credentials
  - Subscriber cleanup on stream close (channels retained/cleaned correctly)
  - Error propagation after max retries exhausted
  - Provider cleanup on drop (background task aborted)
  - Serverless mode adds `ResourceType=ServerlessCache` to URL

#### Integration Tests (in `redis/tests/test_aws_iam_auth.rs`)

- Gated behind `#[cfg(feature = "aws-iam")]` and `#[ignore]` (require real AWS resources)
- Environment variable driven:
  - `REDIS_URL` — ElastiCache/MemoryDB endpoint
  - `AWS_REGION` — AWS region
  - `AWS_IAM_USER_ID` — ElastiCache/MemoryDB user ID
  - `AWS_IAM_SERVICE_NAME` — `elasticache` or `memorydb`
  - Standard AWS credential env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.)
- Test actual SET/GET operations to verify auth works end-to-end

### Summary of Advantages

- **Zero changes to the core auth infrastructure** — plugs into the existing `StreamingCredentialsProvider` + multiplexed connection re-auth system
- **Feature-gated** — `aws-iam` flag keeps AWS deps optional, just like `entra-id`
- **Supports all AWS credential sources** — env vars, config files, EC2/ECS instance roles, SSO, assume-role chains via `aws-config`'s `DefaultCredentialsChain`
- **Both services** — ElastiCache and MemoryDB via enum
- **Simpler than Entra ID** — no JWT parsing, no OID extraction, straightforward URL signing
