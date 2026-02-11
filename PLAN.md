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
│   ├── subscribers: Arc<Mutex<Vec<Sender>>>
│   └── refresh_task_handle: Option<JoinHandle>
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
│   └── start(token_refresh_config) → spawns tokio task
│         → Generates token every ~12-13 minutes (before 15m expiry)
│         → Pushes BasicAuth { username: user_id, password: token } to subscribers
│         → Retry with exponential backoff on failure
│
└── impl StreamingCredentialsProvider:
    └── subscribe() → returns Stream<Item = RedisResult<BasicAuth>>
```

#### New Feature Flag

```toml
# redis/Cargo.toml
[dependencies]
aws-sigv4 = { version = "1", optional = true }
aws-credential-types = { version = "1", optional = true }
aws-config = { version = "1", optional = true }
aws-smithy-runtime-api = { version = "1", optional = true }

[features]
aws-iam = [
    "dep:aws-sigv4",
    "dep:aws-credential-types",
    "dep:aws-config",
    "dep:aws-smithy-runtime-api",
    "token-based-authentication",  # reuse existing infra
    "tokio-comp"
]
```

#### Changes to Existing Files

- **`redis/src/lib.rs`** — Add `#[cfg(feature = "aws-iam")] pub mod aws_iam;` and re-export public types
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
| Refresh interval | ~12 minutes (refresh at 80% of token lifetime, reusing `TokenRefreshConfig`) |
| Connection re-auth | Before 12-hour window expires |
| Retry config | Reuse existing `RetryConfig` (exponential backoff) |

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

### Summary of Advantages

- **Zero changes to the core auth infrastructure** — plugs into the existing `StreamingCredentialsProvider` + multiplexed connection re-auth system
- **Feature-gated** — `aws-iam` flag keeps AWS deps optional, just like `entra-id`
- **Supports all AWS credential sources** — env vars, config files, EC2/ECS instance roles, SSO, assume-role chains via `aws-config`'s `DefaultCredentialsChain`
- **Both services** — ElastiCache and MemoryDB via enum
- **Simpler than Entra ID** — no JWT parsing, no OID extraction, straightforward URL signing
