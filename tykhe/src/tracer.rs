use once_cell::sync::Lazy;
use opentelemetry::KeyValue;
use opentelemetry_api::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use opentelemetry_semantic_conventions::resource;
use std::env;
use tonic::codegen::http::HeaderMap;
use tonic::metadata::MetadataMap;
use tracing::metadata::LevelFilter;
use tracing::subscriber::SetGlobalDefaultError;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;

const KEY_VALUE_SEPARATOR: &str = "=";

const DEFAULT_SERVICE_NAME: &str = "tykhe";
const DEFAULT_HEADERS_SEPARATOR: &str = ";";

const ENV_SERVICE_NAME: &str = "SERVICE_NAME";
const ENV_COLLECTOR_URL: &str = "COLLECTOR_URL";
const ENV_COLLECTOR_HEADERS: &str = "COLLECTOR_HEADERS";
const ENV_HEADERS_SEPARATOR: &str = "HEADERS_SEPARATOR";

static SERVICE_NAME: Lazy<String> =
    Lazy::new(|| env::var(ENV_SERVICE_NAME).unwrap_or_else(|_| DEFAULT_SERVICE_NAME.to_string()));

static COLLECTOR_URL: Lazy<Option<String>> = Lazy::new(|| match env::var(ENV_COLLECTOR_URL) {
    Ok(url) => Some(url),
    Err(err) => {
        error!(
            error = err.to_string(),
            "reading collector url from environment variables"
        );

        None
    }
});

static COLLECTOR_HEADERS: Lazy<String> =
    Lazy::new(|| env::var(ENV_COLLECTOR_HEADERS).unwrap_or_default());

static HEADERS_SEPARATOR: Lazy<String> =
    Lazy::new(|| env::var(ENV_HEADERS_SEPARATOR).unwrap_or(DEFAULT_HEADERS_SEPARATOR.to_string()));

fn init_default() -> Result<(), SetGlobalDefaultError> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    let subscriber = Registry::default().with(stdout_log.with_filter(LevelFilter::INFO));

    tracing::subscriber::set_global_default(subscriber)
}

fn init_with_collector(collector_url: &str) -> Result<(), SetGlobalDefaultError> {
    let metadata = COLLECTOR_HEADERS
        .is_empty()
        .then_some(MetadataMap::default())
        .unwrap_or_else(|| {
            MetadataMap::from_headers(HeaderMap::from_iter(
                COLLECTOR_HEADERS.split(&*HEADERS_SEPARATOR).map(|split| {
                    let header: Vec<&str> = split.split(KEY_VALUE_SEPARATOR).collect();
                    (header[0].try_into().unwrap(), header[1].try_into().unwrap())
                }),
            ))
        });

    let tracer =
        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(collector_url)
                    .with_metadata(metadata),
            )
            .with_trace_config(sdktrace::config().with_resource(Resource::new(vec![
                KeyValue::new(resource::SERVICE_NAME, SERVICE_NAME.clone()),
            ])))
            .install_batch(runtime::Tokio)
            .unwrap();

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    let subscriber = Registry::default()
        .with(telemetry)
        .with(stdout_log.with_filter(LevelFilter::INFO));

    tracing::subscriber::set_global_default(subscriber)
}

pub fn init() -> Result<(), SetGlobalDefaultError> {
    if let Some(collector_url) = &*COLLECTOR_URL {
        init_with_collector(collector_url)
    } else {
        init_default()
    }
}

pub fn shutdown() {
    global::shutdown_tracer_provider()
}
