use regex::Regex;

pub struct SecretRule {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: Regex,
    /// Fast pre-filter: skip regex if none of these substrings appear.
    pub keywords: Vec<&'static str>,
}

/// Build all default secret detection rules.
///
/// Rules are ordered from most-specific to least-specific.
/// Each regex must contain a named capture group `secret`.
pub fn default_rules() -> Vec<SecretRule> {
    let defs: &[(&str, &str, &str, &[&str])] = &[
        // ── Cloud providers ──────────────────────────────────────────
        (
            "aws_access_key",
            "AWS Access Key ID",
            r"(?P<secret>(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
            &[
                "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA", "A3T",
            ],
        ),
        (
            "aws_secret_key",
            "AWS Secret Access Key",
            r#"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['"]?(?P<secret>[A-Za-z0-9/+=]{40})['"]?"#,
            &["aws_secret", "secret_key", "AWS_SECRET"],
        ),
        (
            "google_api_key",
            "Google API Key",
            r"(?P<secret>AIza[0-9A-Za-z\-_]{35})",
            &["AIza"],
        ),
        (
            "azure_connection_string",
            "Azure Connection String",
            r#"(?P<secret>DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;[^\s'"]*)"#,
            &["DefaultEndpointsProtocol"],
        ),
        // ── AI providers ─────────────────────────────────────────────
        (
            "anthropic_api_key",
            "Anthropic API Key",
            r"(?P<secret>sk-ant-api03-[A-Za-z0-9\-_]{80,})",
            &["sk-ant-"],
        ),
        (
            "openai_api_key",
            "OpenAI API Key",
            // Match sk-proj- and sk-svcacct- (modern OpenAI formats)
            // Old sk-<hash> format excluded to avoid clash with Anthropic sk-ant-
            r"(?P<secret>sk-(?:proj|svcacct)-[A-Za-z0-9\-_]{20,})",
            &["sk-proj-", "sk-svcacct-"],
        ),
        // ── GitHub ───────────────────────────────────────────────────
        (
            "github_pat",
            "GitHub Personal Access Token",
            r"(?P<secret>ghp_[A-Za-z0-9]{36})",
            &["ghp_"],
        ),
        (
            "github_oauth",
            "GitHub OAuth Access Token",
            r"(?P<secret>gho_[A-Za-z0-9]{36})",
            &["gho_"],
        ),
        (
            "github_app",
            "GitHub App Token",
            r"(?P<secret>(?:ghs|ghu)_[A-Za-z0-9]{36})",
            &["ghs_", "ghu_"],
        ),
        (
            "github_fine_grained",
            "GitHub Fine-Grained PAT",
            r"(?P<secret>github_pat_[A-Za-z0-9_]{82})",
            &["github_pat_"],
        ),
        // ── Payments ─────────────────────────────────────────────────
        (
            "stripe_secret",
            "Stripe Secret Key",
            r"(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,})",
            &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        ),
        (
            "stripe_publishable",
            "Stripe Publishable Key",
            r"(?P<secret>pk_(?:live|test)_[A-Za-z0-9]{24,})",
            &["pk_live_", "pk_test_"],
        ),
        // ── Messaging ────────────────────────────────────────────────
        (
            "slack_bot_token",
            "Slack Bot Token",
            r"(?P<secret>xoxb-[A-Za-z0-9\-]{50,})",
            &["xoxb-"],
        ),
        (
            "slack_user_token",
            "Slack User Token",
            r"(?P<secret>xoxp-[A-Za-z0-9\-]{50,})",
            &["xoxp-"],
        ),
        (
            "slack_webhook",
            "Slack Webhook URL",
            r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)",
            &["hooks.slack.com"],
        ),
        (
            "telegram_bot_token",
            "Telegram Bot Token",
            r"(?P<secret>\d{8,10}:[A-Za-z0-9_\-]{35})",
            &[":", "bot", "telegram", "TELEGRAM"],
        ),
        (
            "discord_bot_token",
            "Discord Bot Token",
            r"(?P<secret>[MN][A-Za-z0-9\-_]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})",
            &["discord", "DISCORD", "bot"],
        ),
        // ── Email / SaaS ────────────────────────────────────────────
        (
            "sendgrid_api_key",
            "SendGrid API Key",
            r"(?P<secret>SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})",
            &["SG."],
        ),
        (
            "mailgun_api_key",
            "Mailgun API Key",
            r"(?P<secret>key-[0-9a-zA-Z]{32})",
            &["mailgun", "MAILGUN", "key-"],
        ),
        (
            "twilio_api_key",
            "Twilio API Key",
            r"(?P<secret>SK[0-9a-fA-F]{32})",
            &["twilio", "TWILIO", "SK"],
        ),
        // ── Package registries ───────────────────────────────────────
        (
            "npm_token",
            "npm Access Token",
            r"(?P<secret>npm_[A-Za-z0-9]{36})",
            &["npm_"],
        ),
        (
            "pypi_token",
            "PyPI API Token",
            r"(?P<secret>pypi-[A-Za-z0-9\-_]{100,})",
            &["pypi-"],
        ),
        // ── Crypto / Keys ───────────────────────────────────────────
        (
            "private_key",
            "Private Key Block",
            r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)",
            &["PRIVATE KEY"],
        ),
        (
            "jwt",
            "JSON Web Token",
            r"(?P<secret>eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,})",
            &["eyJ"],
        ),
        // ── Database / infra ─────────────────────────────────────────
        (
            "connection_string",
            "Database Connection String",
            r#"(?P<secret>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'"]{10,})"#,
            &["postgres", "mysql", "mongodb", "redis", "amqp"],
        ),
        (
            "heroku_api_key",
            "Heroku API Key",
            r"(?i)(?:heroku).*?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            &["heroku", "HEROKU"],
        ),
        // ── Generic patterns (least specific, checked last) ──────────
        (
            "generic_secret_assignment",
            "Hardcoded Secret Value",
            r#"(?i)(?:password|passwd|secret|token|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key)['"]?\s*[:=]\s*['"](?P<secret>[^'"]{8,})['"]"#,
            &[
                "password",
                "passwd",
                "secret",
                "token",
                "api_key",
                "apikey",
                "api-key",
                "auth_token",
                "access_token",
                "private_key",
                "PASSWORD",
                "SECRET",
                "TOKEN",
                "API_KEY",
                // The pre-filter is case-sensitive: camelCase JSON keys
                // (accessToken, clientSecret, apiKey) carry capitalised words.
                "Token",
                "Secret",
                "Password",
                "Key",
            ],
        ),
        (
            "bearer_token",
            "Bearer Authorization Token",
            r"(?i)(?:bearer)\s+(?P<secret>[A-Za-z0-9\-_./+=]{20,})",
            &["bearer", "Bearer", "BEARER"],
        ),
        // ── Gitleaks community rules ──────────────────────────────────
        // ── Cloud providers ──
        ("alibaba_access_key_id", "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.", r#"(?P<secret>\b(LTAI(?i)[a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["ltai"]),
        ("alibaba_secret_key", "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:alibaba)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$))"#, &["alibaba"]),
        ("aws_amazon_bedrock_api_key_long_lived", "Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage", r#"(?P<secret>\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\x60'"\s;]|\\[nr]|$))"#, &["absk"]),
        ("aws_amazon_bedrock_api_key_short_lived", "Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage", r"(?P<secret>bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t)", &["bedrock-api-key-"]),
        ("azure_ad_client_secret", "Azure AD Client Secret", r#"(?P<secret>(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),]))"#, &["q~"]),
        ("clickhouse_cloud_api_secret_key", "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.", r"(?P<secret>\b(4b1d[A-Za-z0-9]{38})\b)", &["4b1d"]),
        ("cloudflare_api_key", "Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["cloudflare"]),
        ("cloudflare_global_api_key", "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{37})(?:[\x60'"\s;]|\\[nr]|$))"#, &["cloudflare"]),
        ("cloudflare_origin_ca_key", "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.", r#"(?P<secret>\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60'"\s;]|\\[nr]|$))"#, &["cloudflare", "v1.0-"]),
        ("databricks_api_token", "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.", r#"(?P<secret>\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$))"#, &["dapi"]),
        ("datadog_access_token", "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["datadog"]),
        ("digitalocean_access_token", "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.", r#"(?P<secret>\b(doo_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["doo_v1_"]),
        ("digitalocean_pat", "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.", r#"(?P<secret>\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dop_v1_"]),
        ("digitalocean_refresh_token", "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.", r#"(?P<secret>(?i)\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dor_v1_"]),
        ("doppler_api_token", "Discovered a Doppler API token, posing a risk to environment and secrets management security.", r"(?P<secret>dp\.pt\.(?i)[a-z0-9]{43})", &["dp.pt."]),
        ("dynatrace_api_token", "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.", r"(?P<secret>dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64})", &["dt0c01."]),
        ("fastly_api_token", "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:fastly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["fastly"]),
        ("flyio_access_token", "Uncovered a Fly.io API key", r#"(?P<secret>\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nr]|$))"#, &["fo1_", "fm1", "fm2_"]),
        ("planetscale_api_token", "Identified a PlanetScale API token, potentially compromising database management and operations.", r#"(?P<secret>\b(pscale_tkn_(?i)[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["pscale_tkn_"]),
        ("planetscale_oauth_token", "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.", r#"(?P<secret>\b(pscale_oauth_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["pscale_oauth_"]),
        ("planetscale_password", "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.", r#"(?P<secret>(?i)\b(pscale_pw_(?i)[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["pscale_pw_"]),
        ("yandex_aws_access_token", "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(YC[a-zA-Z0-9_\-]{38})(?:[\x60'"\s;]|\\[nr]|$))"#, &["yandex"]),
        // ── AI providers ──
        ("cohere_api_token", "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.", r#"(?P<secret>[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["cohere", "co_api_key"]),
        ("huggingface_access_token", "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.", r#"(?P<secret>\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$))"#, &["hf_"]),
        ("huggingface_organization_api_token", "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.", r#"(?P<secret>\b(api_org_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$))"#, &["api_org_"]),
        ("openai_api_key", "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.", r#"(?P<secret>\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["t3blbkfj"]),
        ("perplexity_api_key", "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.", r#"(?P<secret>\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b))"#, &["pplx-"]),
        // ── Payments & crypto ──
        ("bittrex_access_key", "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["bittrex"]),
        ("bittrex_secret_key", "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["bittrex"]),
        ("coinbase_access_token", "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:coinbase)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["coinbase"]),
        ("duffel_api_token", "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.", r"(?P<secret>duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43})", &["duffel_"]),
        ("easypost_api_token", "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.", r"(?P<secret>\bEZAK(?i)[a-z0-9]{54}\b)", &["ezak"]),
        ("easypost_test_api_token", "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.", r"(?P<secret>\bEZTK(?i)[a-z0-9]{54}\b)", &["eztk"]),
        ("finicity_api_token", "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["finicity"]),
        ("finicity_client_secret", "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["finicity"]),
        ("flutterwave_encryption_key", "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.", r"(?P<secret>FLWSECK_TEST-(?i)[a-h0-9]{12})", &["flwseck_test"]),
        ("flutterwave_public_key", "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.", r"(?P<secret>FLWPUBK_TEST-(?i)[a-h0-9]{32}-X)", &["flwpubk_test"]),
        ("flutterwave_secret_key", "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.", r"(?P<secret>FLWSECK_TEST-(?i)[a-h0-9]{32}-X)", &["flwseck_test"]),
        ("kraken_access_token", "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9\/=_\+\-]{80,90})(?:[\x60'"\s;]|\\[nr]|$))"#, &["kraken"]),
        ("plaid_api_token", "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["plaid"]),
        ("plaid_client_id", "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$))"#, &["plaid"]),
        ("plaid_secret_key", "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$))"#, &["plaid"]),
        ("shippo_api_token", "Discovered a Shippo API token, potentially compromising shipping services and customer order data.", r#"(?P<secret>\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["shippo_"]),
        ("square_access_token", "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.", r#"(?P<secret>\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sq0atp-", "eaaa"]),
        ("squarespace_access_token", "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:squarespace)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["squarespace"]),
        ("stripe_access_token", "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.", r#"(?P<secret>\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"]),
        // ── Messaging & email ──
        ("beamer_api_token", "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:beamer)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(b_[a-z0-9=_\-]{44})(?:[\x60'"\s;]|\\[nr]|$))"#, &["beamer"]),
        ("discord_api_token", "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["discord"]),
        ("discord_client_id", "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{18})(?:[\x60'"\s;]|\\[nr]|$))"#, &["discord"]),
        ("discord_client_secret", "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["discord"]),
        ("intercom_api_key", "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:intercom)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{60})(?:[\x60'"\s;]|\\[nr]|$))"#, &["intercom"]),
        ("mailchimp_api_key", "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32}-us\d\d)(?:[\x60'"\s;]|\\[nr]|$))"#, &["mailchimp"]),
        ("mailgun_private_api_token", "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["mailgun"]),
        ("mailgun_pub_key", "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["mailgun"]),
        ("mailgun_signing_key", "Identified a Mailgun webhook signing key, potentially compromising email notification integrity and data security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\x60'"\s;]|\\[nr]|$))"#, &["mailgun"]),
        ("messagebird_api_key", "Discovered a MessageBird API key, potentially compromising communication services and messaging data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:messagebird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$))"#, &["messagebird"]),
        ("messagebird_client_id", "Uncovered a MessageBird client ID, posing a risk of unauthorized client account access and messaging data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:messagebird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["messagebird"]),
        ("postman_api_token", "Identified a Postman API Token, potentially compromising API testing and development workflows.", r#"(?P<secret>\b(PMAK-(?i)[a-f0-9]{24}-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$))"#, &["pmak-"]),
        ("pusher_app_secret", "Detected a Pusher App Secret, risking unauthorized access to real-time communication services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:pusher)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["pusher"]),
        ("sendbird_access_id", "Discovered a Sendbird Access ID, which could compromise user communications and data privacy on Sendbird-integrated platforms.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sendbird"]),
        ("sendbird_access_token", "Uncovered a Sendbird Access Token, potentially compromising chat and messaging functionality.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sendbird"]),
        ("sendinblue_api_token", "Found a Sendinblue API token, posing a risk to email marketing and communication services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sendinblue)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sendinblue"]),
        ("telegram_bot_api_token", "Found a Telegram Bot API Token, potentially enabling unauthorized bot operations and message interception.", r#"(?P<secret>(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-]))"#, &["telegram"]),
        ("twillio_api_key", "Discovered a Twilio API Key, which could lead to unauthorized access to communication services and user data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twilio)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(SK[0-9a-fA-F]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twilio"]),
        ("vonage_api_key", "Identified a Vonage API key, potentially compromising communications services and access to sensitive call and messaging data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:vonage|nexmo)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{8})(?:[\x60'"\s;]|\\[nr]|$))"#, &["vonage", "nexmo"]),
        ("zendesk_secret_key", "Detected a Zendesk Secret Key, which could compromise customer support systems and sensitive user interaction data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:zendesk)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["zendesk"]),
        // ── Version control & project mgmt ──
        ("asana_client_id", "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{16})(?:[\x60'"\s;]|\\[nr]|$))"#, &["asana"]),
        ("asana_client_secret", "Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["asana"]),
        ("atlassian_api_token", "Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\x60'"\s;]|\\[nr]|$)|\b(ATATT3[A-Za-z0-9_\-=]{186})(?:[\x60'"\s;]|\\[nr]|$))"#, &["atlassian", "confluence", "jira", "atatt3"]),
        ("bitbucket_client_id", "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["bitbucket"]),
        ("bitbucket_client_secret", "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["bitbucket"]),
        ("github_app_token", "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.", r#"(?P<secret>\b((?:ghu|ghs)_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$))"#, &["ghu_", "ghs_"]),
        ("github_pat_v2", "Uncovered a GitHub Personal Access Token (v2), potentially risking unauthorized repository access and codebase manipulation.", r#"(?P<secret>\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})(?:[\x60'"\s;]|\\[nr]|$))"#, &["github_pat_"]),
        ("github_refresh_token", "Discovered a GitHub Refresh Token, posing a risk of prolonged unauthorized access to GitHub resources.", r#"(?P<secret>\b(ghr_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$))"#, &["ghr_"]),
        ("gitlab_access_token", "Identified a GitLab Access Token, potentially compromising GitLab repository management and CI/CD pipeline configurations.", r#"(?P<secret>(?:glpat|gldt|glrt|glft|glptt|glagent)-[A-Za-z0-9_\-]{20})"#, &["glpat-", "gldt-", "glrt-", "glft-", "glptt-", "glagent-"]),
        ("gitlab_cicd_job_token", "Found a GitLab CI/CD job token, potentially compromising pipeline integrations and build processes.", r#"(?P<secret>glcbt-[0-9]{2}_[A-Za-z0-9_\-]{20})"#, &["glcbt-"]),
        ("gitlab_feature_flags_client_token", "Detected a GitLab feature flags client token, which may risk unauthorized access to feature flag configurations.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:gitlab)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(fls_[a-z0-9]{29})(?:[\x60'"\s;]|\\[nr]|$))"#, &["gitlab"]),
        ("gitlab_oauth_access_token", "Uncovered a GitLab OAuth Access Token, potentially allowing unauthorized access to GitLab resources and data.", r#"(?P<secret>\b(gloas-[A-Za-z0-9_\-]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["gloas-"]),
        ("gitlab_runner_registration_token", "Discovered a GitLab Runner Registration Token, posing a risk of unauthorized CI/CD runner registrations.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:gitlab)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(GR1348941[A-Za-z0-9_\-]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["gr1348941"]),
        ("linear_api_token", "Detected a Linear API Token, potentially compromising project management workflows and sensitive data.", r#"(?P<secret>\b(lin_api_[A-Za-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["lin_api_"]),
        ("linear_client_secret", "Identified a Linear Client Secret, posing a risk to project management tool integrations and data security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:linear)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["linear"]),
        ("lob_api_key", "Uncovered a Lob API Key, potentially risking direct mail service operations and customer data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(((?:test|live)_(?:pub|sec)_[a-f0-9]{40}))(?:[\x60'"\s;]|\\[nr]|$))"#, &["lob"]),
        ("lob_pub_api_key", "Detected a Lob Publishable API Key, posing a risk of unauthorized access to mailing and address verification services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(((?:test|live)_pub_[a-f0-9]{40}))(?:[\x60'"\s;]|\\[nr]|$))"#, &["lob"]),
        // ── Dev tools & CI/CD ──
        ("artifactory_api_key", "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.", r#"(?P<secret>\bAKCp[A-Za-z0-9]{69}\b)"#, &["akcp"]),
        ("artifactory_reference_token", "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.", r#"(?P<secret>\bcmVmd[A-Za-z0-9]{59}\b)"#, &["cmvmd"]),
        ("circleci_access_token", "Uncovered a CircleCI Access Token, potentially compromising continuous integration and deployment pipelines.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:circle)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["circleci"]),
        ("clojars_api_token", "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.", r"(?P<secret>(?i)CLOJARS_[a-z0-9]{60})", &["clojars_"]),
        ("codecov_access_token", "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:codecov)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["codecov"]),
        ("defined_networking_api_token", "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:dnkey)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dnkey"]),
        ("droneci_access_token", "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:droneci)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["droneci"]),
        ("gitter_access_token", "Discovered a Gitter Access Token, potentially compromising developer communication and project collaboration.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:gitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["gitter"]),
        ("netlify_access_token", "Found a Netlify Access Token, risking unauthorized website deployment and potential data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:netlify)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40,46})(?:[\x60'"\s;]|\\[nr]|$))"#, &["netlify"]),
        ("new_relic_browser_api_token", "Detected a New Relic ingest browser API token, risking unauthorized access to browser monitoring data and applications.", r#"(?P<secret>\b(NRJS-[a-f0-9]{19})(?:[\x60'"\s;]|\\[nr]|$))"#, &["nrjs-"]),
        ("new_relic_license_key", "Found a New Relic License Key, which could compromise New Relic monitoring services and data privacy.", r#"(?P<secret>\b([a-zA-Z0-9]{6}FF[ANT][ANT][A-Z0-9]{34}NRAL)(?:[\x60'"\s;]|\\[nr]|$))"#, &["nral"]),
        ("new_relic_user_api_id", "Uncovered a New Relic User API ID, potentially compromising monitoring and analytics services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:new.relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["new-relic", "new_relic", "newrelic"]),
        ("new_relic_user_api_key", "Identified a New Relic User API Key, which could compromise monitoring, analytics, and data management.", r#"(?P<secret>\b(NRAK-[A-Z0-9]{27})(?:[\x60'"\s;]|\\[nr]|$))"#, &["nrak-"]),
        ("npm_access_token", "Uncovered an npm access token, potentially compromising package management and distribution pipelines.", r#"(?P<secret>\b(npm_[A-Za-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$))"#, &["npm_"]),
        ("rubygems_api_token", "Discovered a RubyGems API token, potentially compromising gem management and the Ruby ecosystem.", r#"(?P<secret>\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$))"#, &["rubygems_"]),
        ("snyk_api_token", "Detected a Snyk API token, potentially allowing unauthorized access to vulnerability management services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:snyk)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["snyk"]),
        ("sonarqube_api_token", "Uncovered a SonarQube API token, potentially risking unauthorized access to code quality checks and project configurations.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sonar)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sonar"]),
        ("terraform_api_token", "Discovered a Terraform API token, posing a risk to infrastructure management and cloud resource configurations.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:(?-i:[Tt]erraform)|TERRAFORM)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{14}\.atlasv1\.[a-z0-9\/=_\-]{60,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["terraform"]),
        ("vercel_api_token", "Detected a Vercel API token, potentially compromising website deployments and sensitive project data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:vercel)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_=\-]{24})(?:[\x60'"\s;]|\\[nr]|$))"#, &["vercel"]),
        // ── Storage & media ──
        ("dropbox_api_token", "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{15})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dropbox"]),
        ("dropbox_long_lived_api_token", "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dropbox"]),
        ("dropbox_short_lived_api_token", "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dropbox"]),
        ("frameio_api_token", "Found a Frame.io API token, potentially compromising video collaboration and project management.", r"(?P<secret>fio-u-(?i)[a-z0-9\-_=]{64})", &["fio-u-"]),
        // ── Monitoring & observability ──
        ("datadog_client_token", "Found a Datadog Client Token, which may compromise monitoring services and expose sensitive data about system performance.", r#"(?P<secret>\b(pub[a-f0-9]{27})(?:[\x60'"\s;]|\\[nr]|$))"#, &["datadog"]),
        ("grafana_api_key", "Identified a Grafana API key, potentially compromising monitoring dashboards and data visualization tools.", r#"(?P<secret>\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})(?:[\x60'"\s;]|\\[nr]|$))"#, &["eyJrIjoi"]),
        ("grafana_cloud_api_token", "Uncovered a Grafana cloud API token, which may compromise cloud-based monitoring solutions and data privacy.", r#"(?P<secret>\b(glc_[A-Za-z0-9+/]{32,200}={0,2})(?:[\x60'"\s;]|\\[nr]|$))"#, &["glc_"]),
        ("grafana_service_account_token", "Detected a Grafana service account token, risking unauthorized access to Grafana monitoring services.", r#"(?P<secret>\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$))"#, &["glsa_"]),
        ("sentry_access_token", "Detected a Sentry Access Token, potentially compromising error tracking and application monitoring.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sentry)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sentry"]),
        ("sumologic_access_id", "Uncovered a SumoLogic Access ID, which could compromise log management and data analytics.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sumo)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{14})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sumo"]),
        ("sumologic_access_token", "Detected a SumoLogic Access Token, which may compromise log management services and sensitive operational data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:sumo)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sumo"]),
        // ── Identity & secrets management ──
        ("1password_secret_key", "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.", r"(?P<secret>\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b)", &["a3-"]),
        ("1password_service_account_token", "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.", r"(?P<secret>ops_eyJ[a-zA-Z0-9+/]{250,}={0,3})", &["ops_"]),
        ("adafruit_api_key", "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:adafruit)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["adafruit"]),
        ("age_secret_key", "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.", r"(?P<secret>AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})", &["age-secret-key-1"]),
        ("authress_service_client_access_key", "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.", r#"(?P<secret>\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})(?:[\x60'"\s;]|\\[nr]|$))"#, &["sc_", "ext_", "scauth_", "authress_"]),
        ("doppler_api_token_full", "Discovered a Doppler API token, posing a risk to environment and secrets management security.", r#"(?P<secret>\b(dp\.pt\.[a-zA-Z0-9]{43})(?:[\x60'"\s;]|\\[nr]|$))"#, &["dp.pt."]),
        ("hashicorp_tf_api_token", "Uncovered a HashiCorp Terraform API token, potentially exposing infrastructure automation and management processes.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:(?-i:[Hh]ashicorp)|HASHICORP)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{14}\.atlasv1\.[a-z0-9\/_=\-]{60,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["hashicorp"]),
        ("hashicorp_vault_service_token", "Identified a HashiCorp Vault service token, which could compromise secrets management and access control.", r#"(?P<secret>\b(hvs\.[a-zA-Z0-9_-]{90,120})(?:[\x60'"\s;]|\\[nr]|$))"#, &["hvs."]),
        ("jwt_base64", "Detected a JSON Web Token (JWT) in Base64 encoding, potentially exposing authentication data in encoded form.", r#"(?P<secret>base64\s*\(\s*eyJ[A-Za-z0-9+\-_/]{40,})"#, &["eyj"]),
        ("okta_access_token", "Identified an Okta Access Token, which may compromise identity management and access control systems.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:okta)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-z]{42})(?:[\x60'"\s;]|\\[nr]|$))"#, &["okta"]),
        ("vault_service_token", "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.", r#"(?P<secret>\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))(?:[\x60'"\s;]|\\[nr]|$))"#, &["hvs.", "s."]),
        // ── Social & content platforms ──
        ("etsy_access_token", "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$))"#, &["etsy"]),
        ("facebook_access_token", "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.", r#"(?P<secret>(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["facebook"]),
        ("facebook_page_access_token", "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.", r#"(?P<secret>\b(EAA[MC](?i)[a-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["eaam", "eaac"]),
        ("facebook_secret", "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["facebook"]),
        ("flickr_access_token", "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:flickr)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["flickr"]),
        ("pinterest_access_token", "Uncovered a Pinterest Token, potentially leading to unauthorized Pinterest account access and data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:pinterest)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["pinterest"]),
        ("twitter_api_key", "Identified a Twitter API Key, which could compromise Twitter integrations and expose sensitive user data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twitter"]),
        ("twitter_api_secret", "Detected a Twitter API Secret, potentially compromising Twitter application integrations and user data security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{50})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twitter"]),
        ("twitter_bearer_token", "Found a Twitter Bearer Token, risking unauthorized API access and potential exposure of sensitive data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{11,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twitter"]),
        ("twitter_client_id", "Uncovered a Twitter Client ID, potentially allowing unauthorized access to Twitter applications.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twitter"]),
        ("twitter_oauth", "Detected a Twitter OAuth token, potentially compromising user authentication and data access on Twitter.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]+-[a-z0-9A-Z]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twitter"]),
        ("youtube_api_key", "Found a YouTube API key, potentially compromising video content management and data access.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:youtube)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(AIza[a-z0-9\-_]{35})(?:[\x60'"\s;]|\\[nr]|$))"#, &["youtube"]),
        // ── CRM & marketing ──
        ("adobe_client_id", "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:adobe)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["adobe"]),
        ("adobe_client_secret", "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.", r#"(?P<secret>\b(p8e-(?i)[a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["p8e-"]),
        ("airtable_api_key", "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:airtable)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{17})(?:[\x60'"\s;]|\\[nr]|$))"#, &["airtable"]),
        ("airtable_personnal_access_token", "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.", r"(?P<secret>\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b)", &["airtable"]),
        ("algolia_api_key", "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["algolia"]),
        ("contentful_delivery_api_token", "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:contentful)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{43})(?:[\x60'"\s;]|\\[nr]|$))"#, &["contentful"]),
        ("freshbooks_access_token", "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:freshbooks)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["freshbooks"]),
        ("hubspot_api_key", "Identified a HubSpot API Key, potentially compromising CRM data and business operations.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["hubspot"]),
        ("infracost_api_token", "Detected an Infracost API Token, potentially compromising cloud cost estimation and optimization.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:infracost)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(ico-[a-zA-Z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["infracost"]),
        ("kucoin_access_token", "Discovered a KuCoin Access Token, potentially compromising cryptocurrency exchange security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["kucoin"]),
        ("kucoin_secret_key", "Identified a KuCoin Secret Key, risking unauthorized access to cryptocurrency trading accounts.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["kucoin"]),
        ("launchdarkly_access_token", "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and software deployment.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:launchdarkly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["launchdarkly"]),
        ("lokalise_api_token", "Found a Lokalise API Token, posing a risk to localization and translation management.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:lokalise)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["lokalise"]),
        ("miro_access_token", "Identified a Miro Access Token, potentially compromising collaborative visual workspace data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:miro)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_=\-]{88})(?:[\x60'"\s;]|\\[nr]|$))"#, &["miro"]),
        ("notion_api_token", "Detected a Notion API token, potentially compromising workspace data and collaboration tools.", r#"(?P<secret>\b(secret_[a-zA-Z0-9]{43})(?:[\x60'"\s;]|\\[nr]|$))"#, &["notion", "secret_"]),
        ("typeform_api_token", "Discovered a Typeform API token, potentially compromising form data and survey responses.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:typeform)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})(?:[\x60'"\s;]|\\[nr]|$))"#, &["typeform"]),
        // ── Generic patterns ──
        ("freemius_secret_key", "Detected a Freemius secret key, potentially exposing sensitive information.", r#"(?P<secret>(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["'])"#, &["secret_key"]),
        // ── Other services ──
        ("cisco_meraki_api_key", "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.", r#"(?P<secret>[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["meraki"]),
        ("confluent_access_token", "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$))"#, &["confluent"]),
        ("confluent_secret_key", "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$))"#, &["confluent"]),
        ("curl_auth_header", "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.", r#"(?P<secret>\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))"|'(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))')(?:\B|\s|\z))"#, &["curl"]),
        ("curl_auth_user", "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.", r#"(?P<secret>\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\z))"#, &["curl"]),
        ("etsy_webhook_signature_key", "Identified an Etsy Webhook Signature Key, potentially compromising the integrity of Etsy webhook events.", r#"(?P<secret>\b(ews_[a-zA-Z0-9]{56})(?:[\x60'"\s;]|\\[nr]|$))"#, &["ews_"]),
        ("finnhub_access_token", "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:finnhub)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["finnhub"]),
        ("github_app_secret", "Discovered a GitHub App secret, posing a risk of unauthorized GitHub application access and potential data breaches.", r#"(?P<secret>\b(v0\.[0-9]{10}\.[a-zA-Z0-9]{20}-[a-zA-Z0-9]{22})(?:[\x60'"\s;]|\\[nr]|$))"#, &["v0."]),
        ("github_oauth2", "Identified a GitHub OAuth2 Token, posing a risk of unauthorized access to GitHub resources and data.", r#"(?P<secret>\b(gho_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$))"#, &["gho_"]),
        ("github_pat_classic", "Uncovered a GitHub Personal Access Token (Classic), potentially risking unauthorized repository access and codebase manipulation.", r#"(?P<secret>\b(ghp_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$))"#, &["ghp_"]),
        ("heroku_api_key_fresh", "Found a Heroku API Key, posing a risk to cloud application deployments and operational security.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:(?-i:[Hh]eroku|HEROKU))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\x60'"\s;]|\\[nr]|$))"#, &["heroku"]),
        ("lemon_squeezy_api_key", "Identified a Lemon Squeezy API key, posing a risk of unauthorized access to e-commerce services and financial data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:lemonsqueezy)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9[a-zA-Z0-9_-]{100,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["lemonsqueezy"]),
        ("maptiler_api_key", "Detected a MapTiler API key, potentially compromising mapping services and geospatial data.", r#"(?P<secret>\b([A-Za-z0-9]{5}_[A-Za-z0-9]{18}_[A-Za-z0-9]{8})(?:[\x60'"\s;]|\\[nr]|$))"#, &["maptiler"]),
        ("mapbox_api_token", "Found a Mapbox API token, potentially compromising location services and mapping data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:mapbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pk\.[a-zA-Z0-9._-]{100,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["mapbox", "pk."]),
        ("maxmind_license_key", "Detected a MaxMind License Key, potentially compromising IP geolocation and fraud prevention services.", r#"(?P<secret>\b([0-9A-Za-z]{6}_[0-9A-Za-z]{29}_mmk)(?:[\x60'"\s;]|\\[nr]|$))"#, &["_mmk"]),
        ("microsoft_teams_webhook", "Discovered a Microsoft Teams Webhook, potentially compromising team communication and data privacy.", r#"(?P<secret>https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}@[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})"#, &["office.com/webhookb2"]),
        ("novu_api_key", "Uncovered a Novu API key, which could compromise notification infrastructure and user data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:novu)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["novu"]),
        ("openweathermap_api_token", "Found an OpenWeatherMap API token, which could compromise weather data services and user privacy.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:openweathermap)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{32})(?:[\x60'"\s;]|\\[nr]|$))"#, &["openweathermap"]),
        ("patreon_access_token", "Discovered a Patreon Access Token, posing a risk to creator-supporter relationships and financial data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:patreon)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_\-]{43})(?:[\x60'"\s;]|\\[nr]|$))"#, &["patreon"]),
        ("patreon_client_id", "Identified a Patreon Client ID, potentially allowing unauthorized access to Patreon applications.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:patreon)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_\-]{43})(?:[\x60'"\s;]|\\[nr]|$))"#, &["patreon"]),
        ("paypal_braintree_access_token", "Uncovered a Paypal Braintree Access Token, potentially risking payment processing and financial data exposure.", r#"(?P<secret>(?:access_token)\$production\$[0-9a-z]{16}\$[0-9a-f]{32})"#, &["braintree", "paypal"]),
        ("picatic_api_key", "Found a Picatic API key, potentially exposing event management and ticketing systems.", r"(?P<secret>sk_(?:live|test)_[0-9a-z]{32})", &["picatic"]),
        ("readme_api_token", "Found a ReadMe API token, posing a risk to documentation management and data exposure.", r#"(?P<secret>\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nr]|$))"#, &["rdme_"]),
        ("scalingo_api_token", "Discovered a Scalingo API Token, potentially compromising cloud application deployment and management.", r#"(?P<secret>\b(tk-us-[a-zA-Z0-9\-_]{48})(?:[\x60'"\s;]|\\[nr]|$))"#, &["tk-us-"]),
        ("shopify_access_token", "Identified a Shopify access token, potentially compromising e-commerce platform operations and customer data.", r#"(?P<secret>shpat_[a-fA-F0-9]{32})"#, &["shpat_"]),
        ("shopify_custom_access_token", "Found a Shopify custom access token, posing a risk to e-commerce platform security and data integrity.", r#"(?P<secret>shpca_[a-fA-F0-9]{32})"#, &["shpca_"]),
        ("shopify_private_app_access_token", "Uncovered a Shopify private app access token, potentially allowing unauthorized access to Shopify store operations.", r#"(?P<secret>shppa_[a-fA-F0-9]{32})"#, &["shppa_"]),
        ("shopify_shared_secret", "Detected a Shopify shared secret, potentially compromising inter-application trust and data security.", r#"(?P<secret>shpss_[a-fA-F0-9]{32})"#, &["shpss_"]),
        ("slack_app_token", "Identified a Slack App-level token, potentially compromising workspace automation and data privacy.", r#"(?P<secret>(?:xapp)-\d-[A-Z0-9]+-\d+-[a-z0-9]+)"#, &["xapp-"]),
        ("slack_config_access_token", "Found a Slack configuration access token, posing a risk of unauthorized workspace configuration and data access.", r#"(?P<secret>(?:xoxe\.xoxp|xoxe)-\S+)"#, &["xoxe"]),
        ("slack_config_refresh_token", "Discovered a Slack configuration refresh token, potentially allowing prolonged unauthorized access to Slack configurations.", r#"(?P<secret>(?:xoxe-)\S+)"#, &["xoxe-"]),
        ("slack_legacy_bot_token", "Uncovered a Slack legacy bot token, potentially compromising older Slack bot integrations and operations.", r#"(?P<secret>(?:xoxb)-[0-9]{11}-[a-zA-Z0-9]{24})"#, &["xoxb-"]),
        ("slack_legacy_token", "Identified a Slack legacy token, which could lead to unauthorized access to Slack workspaces and data.", r#"(?P<secret>(?:xox[os])-\d+-\d+-\d+-[a-fA-F\d]+)"#, &["xoxo-", "xoxs-"]),
        ("slack_legacy_workspace_token", "Found a Slack legacy workspace token, potentially exposing workspace data and configurations.", r#"(?P<secret>(?:xox[ar])-(?:\d+-)+[a-z0-9]+)"#, &["xoxa-", "xoxr-"]),
        ("slack_oauth_v2_bot_token", "Detected a Slack OAuth v2 bot token, risking unauthorized bot operations and workspace data exposure.", r#"(?P<secret>xoxb-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32})"#, &["xoxb-"]),
        ("slack_oauth_v2_user_token", "Uncovered a Slack OAuth v2 user token, potentially leading to unauthorized user account access and data exposure.", r#"(?P<secret>xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32})"#, &["xoxp-"]),
        ("slack_webhook_url", "Identified a Slack webhook, which could lead to unauthorized message posting and data leakage in Slack channels.", r#"(?P<secret>https://hooks\.slack\.com/(?:services|workflows)/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"#, &["hooks.slack.com"]),
        ("splitio_api_token", "Found a Split.io API Token, posing a risk to feature flagging and experimentation data.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:split)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9\-_=]{100,})(?:[\x60'"\s;]|\\[nr]|$))"#, &["split"]),
        ("switchboard_client_secret", "Detected a Switchboard client secret, potentially compromising communications and data privacy.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:switchboard)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{20})(?:[\x60'"\s;]|\\[nr]|$))"#, &["switchboard"]),
        ("twitch_api_token", "Found a Twitch API token, potentially compromising streaming services and content creator accounts.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:twitch)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$))"#, &["twitch"]),
        ("typeform_api_key", "Identified a Typeform API Key, potentially compromising survey data and user privacy.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:typeform)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$))"#, &["typeform"]),
        ("yandex_access_token", "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\x60'"\s;]|\\[nr]|$))"#, &["yandex"]),
        ("yandex_api_key", "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.", r#"(?P<secret>(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:[\x60'"\s;]|\\[nr]|$))"#, &["yandex"]),
    ];

    defs.iter()
        .filter_map(|(id, desc, pat, kws)| {
            Regex::new(pat).ok().map(|pattern| SecretRule {
                id,
                description: desc,
                pattern,
                keywords: kws.to_vec(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_compile() {
        let rules = default_rules();
        assert!(
            rules.len() >= 150,
            "Expected 150+ rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn aws_key_matches() {
        let rules = default_rules();
        let aws_rule = rules.iter().find(|r| r.id == "aws_access_key").unwrap();
        assert!(aws_rule.pattern.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!aws_rule.pattern.is_match("not_a_key"));
    }

    #[test]
    fn anthropic_key_matches() {
        let rules = default_rules();
        let rule = rules.iter().find(|r| r.id == "anthropic_api_key").unwrap();
        let fake_key = format!("sk-ant-api03-{}", "a".repeat(80));
        assert!(rule.pattern.is_match(&fake_key));
    }

    #[test]
    fn openai_key_matches_proj_format() {
        let rules = default_rules();
        let rule = rules.iter().find(|r| r.id == "openai_api_key").unwrap();
        let fake_key = format!("sk-proj-{}", "a".repeat(40));
        assert!(rule.pattern.is_match(&fake_key));
    }

    #[test]
    fn openai_key_does_not_match_anthropic() {
        let rules = default_rules();
        let rule = rules.iter().find(|r| r.id == "openai_api_key").unwrap();
        let fake_anthropic = format!("sk-ant-api03-{}", "a".repeat(80));
        assert!(!rule.pattern.is_match(&fake_anthropic));
    }

    #[test]
    fn private_key_matches() {
        let rules = default_rules();
        let rule = rules.iter().find(|r| r.id == "private_key").unwrap();
        assert!(rule.pattern.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(rule.pattern.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(rule.pattern.is_match("-----BEGIN EC PRIVATE KEY-----"));
    }

    #[test]
    fn connection_string_matches() {
        let rules = default_rules();
        let rule = rules.iter().find(|r| r.id == "connection_string").unwrap();
        assert!(rule
            .pattern
            .is_match("postgres://user:pass@localhost:5432/mydb"));
        assert!(rule
            .pattern
            .is_match("mongodb+srv://user:pass@cluster.mongodb.net/db"));
        assert!(rule
            .pattern
            .is_match("redis://default:secret@redis.example.com:6380"));
    }

    #[test]
    fn jwt_matches() {
        let rules = default_rules();
        let rule = rules.iter().find(|r| r.id == "jwt").unwrap();
        // Minimal valid JWT structure
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(rule.pattern.is_match(jwt));
    }
}
