//! Loopback-only, read-only HTTP monitor embedded in the broker process.
//!
//! The HTTP parser is Hyper. Credentials travel only in an Authorization header;
//! neither cookies nor browser URLs carry access secrets. Same-user local code and
//! administrators remain inside the endpoint's existing trust boundary.
use crate::broker::Broker;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{StreamExt, stream};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Frame, Incoming},
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, ORIGIN, TRANSFER_ENCODING},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

type Body = UnsyncBoxBody<Bytes, Infallible>;
const MAX_CONNECTIONS: usize = 32;
const MAX_EVENTS: usize = 8;
const MAX_REQUESTS_PER_SECOND: usize = 100;
const MAX_QUERY: usize = 2048;

/// Each enable generation has a fresh credential and owns its HTTP connections.
/// Deliberately has no Debug implementation: status/logging must not expose keys.
#[derive(Default)]
pub struct Control {
    enabled: bool,
    port: u16,
    generation: u64,
    token: Option<String>,
    url: Option<String>,
    last_error: Option<String>,
}
impl Control {
    pub fn enable(&mut self, port: u16) -> Value {
        if !self.enabled || self.port != port || self.last_error.is_some() {
            self.generation = self.generation.wrapping_add(1);
            self.enabled = true;
            self.port = port;
            self.token = Some(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
            self.url = None;
            self.last_error = None;
        }
        self.credentials()
    }
    pub fn disable(&mut self) -> Value {
        self.generation = self.generation.wrapping_add(1);
        self.enabled = false;
        self.token = None;
        self.url = None;
        self.last_error = None;
        self.status()
    }
    pub fn status(&self) -> Value {
        json!({"enabled":self.enabled,"url":self.url,"requested_port":self.port,"last_error":self.last_error})
    }
    /// Only the private local administration socket may return this value.
    pub fn credentials(&self) -> Value {
        let mut value = self.status();
        value["access_token"] = json!(self.token);
        value
    }
    fn current(&self, generation: u64) -> bool {
        self.enabled && self.generation == generation
    }
}
fn default_limit() -> usize {
    50
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorQuery {
    pub machine: Option<String>,
    pub agent: Option<String>,
    pub state: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub before: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}
impl Default for MonitorQuery {
    fn default() -> Self {
        Self {
            machine: None,
            agent: None,
            state: None,
            since: None,
            until: None,
            before: None,
            limit: default_limit(),
        }
    }
}
struct Rate {
    started: Instant,
    count: usize,
}
impl Rate {
    fn allow(&mut self) -> bool {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.count = 0;
        }
        self.count += 1;
        self.count <= MAX_REQUESTS_PER_SECOND
    }
}
#[derive(Clone)]
struct App {
    broker: Broker,
    generation: u64,
    host: String,
    origin: String,
    token: String,
    events: Arc<Semaphore>,
    rate: Arc<Mutex<Rate>>,
}
impl App {
    fn current(&self) -> bool {
        self.broker
            .monitor_control
            .lock()
            .unwrap()
            .current(self.generation)
    }
}
fn body(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).boxed_unsync()
}
fn response(
    status: StatusCode,
    content_type: &'static str,
    content: impl Into<Bytes>,
) -> Response<Body> {
    let mut response = Response::new(body(content));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("pragma", "no-cache".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "cross-origin-resource-policy",
        "same-origin".parse().unwrap(),
    );
    headers.insert("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'".parse().unwrap());
    response
}
fn error(status: StatusCode, message: &'static str) -> Response<Body> {
    response(
        status,
        "application/json; charset=utf-8",
        json!({"error":message}).to_string(),
    )
}
fn unique_header<'a>(request: &'a Request<Incoming>, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = request.headers().get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first.map(|v| v.to_str().map_err(|_| ())).transpose()
}
fn safe_context(request: &Request<Incoming>, app: &App) -> bool {
    // Absolute-form proxy targets are not an additional origin authority.
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return false;
    }
    if unique_header(request, HOST.as_str()) != Ok(Some(app.host.as_str())) {
        return false;
    }
    match unique_header(request, ORIGIN.as_str()) {
        Ok(None) => {}
        Ok(Some(origin)) if origin == app.origin => {}
        _ => return false,
    }
    matches!(
        unique_header(request, "sec-fetch-site"),
        Ok(None) | Ok(Some("none" | "same-origin"))
    )
}
fn authorized(request: &Request<Incoming>, expected: &str) -> bool {
    let Ok(Some(value)) = unique_header(request, AUTHORIZATION.as_str()) else {
        return false;
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return false;
    };
    // Fixed-size constant work after rejecting an invalid credential length.
    if token.len() != expected.len() {
        return false;
    }
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}
async fn route(request: Request<Incoming>, app: App) -> Result<Response<Body>, Infallible> {
    if !app.current() {
        return Ok(error(StatusCode::UNAUTHORIZED, "Monitor access expired"));
    }
    if !safe_context(&request, &app) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "Untrusted browser origin or host",
        ));
    }
    if !app.rate.lock().unwrap().allow() {
        return Ok(error(
            StatusCode::TOO_MANY_REQUESTS,
            "Monitor request limit reached",
        ));
    }
    if request.method() != hyper::Method::GET {
        return Ok(error(StatusCode::METHOD_NOT_ALLOWED, "Read-only monitor"));
    }
    if request.headers().contains_key(TRANSFER_ENCODING)
        || request
            .headers()
            .get(CONTENT_LENGTH)
            .is_some_and(|v| v.as_bytes() != b"0")
    {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Request bodies are not accepted",
        ));
    }
    let path = request.uri().path();
    let query = request.uri().query();
    if request.uri().to_string().len() > MAX_QUERY || (path != "/api/messages" && query.is_some()) {
        return Ok(error(
            StatusCode::BAD_REQUEST,
            "Unexpected or oversized query",
        ));
    }
    if path.starts_with("/api/") && !authorized(&request, &app.token) {
        return Ok(error(StatusCode::UNAUTHORIZED, "Access token required"));
    }
    let response = match path {
        "/" => response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            include_str!("../assets/monitor/index.html"),
        ),
        "/style.css" => response(
            StatusCode::OK,
            "text/css; charset=utf-8",
            include_str!("../assets/monitor/style.css"),
        ),
        "/app.js" => response(
            StatusCode::OK,
            "text/javascript; charset=utf-8",
            include_str!("../assets/monitor/app.js"),
        ),
        "/api/status" => match app.broker.monitor_metadata() {
            Ok(value) => json_response(value),
            Err(_) => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Monitor data unavailable",
            ),
        },
        "/api/messages" => match serde_urlencoded::from_str::<MonitorQuery>(query.unwrap_or("")) {
            Ok(query) => match app.broker.monitor_messages(query) {
                Ok(value) => json_response(value),
                Err(_) => error(StatusCode::BAD_REQUEST, "Invalid message filters"),
            },
            Err(_) => error(StatusCode::BAD_REQUEST, "Invalid message filters"),
        },
        "/api/events" => events(app),
        _ if path.starts_with("/api/messages/") => {
            let id = path.trim_start_matches("/api/messages/");
            if id.is_empty() || id.len() > 100 || id.contains('/') {
                error(StatusCode::BAD_REQUEST, "Invalid message ID")
            } else {
                match app.broker.monitor_message(id) {
                    Ok(value) => json_response(value),
                    Err(_) => error(StatusCode::NOT_FOUND, "Message unavailable"),
                }
            }
        }
        _ => error(StatusCode::NOT_FOUND, "Not found"),
    };
    Ok(response)
}
fn json_response(value: Value) -> Response<Body> {
    response(
        StatusCode::OK,
        "application/json; charset=utf-8",
        value.to_string(),
    )
}
struct EventState {
    app: App,
    _permit: OwnedSemaphorePermit,
    revision: Option<(u64, u64)>,
    heartbeat: Instant,
}
fn events(app: App) -> Response<Body> {
    let Ok(permit) = app.events.clone().try_acquire_owned() else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Live monitor connection limit reached",
        );
    };
    let state = EventState {
        app,
        _permit: permit,
        revision: None,
        heartbeat: Instant::now(),
    };
    let stream = stream::unfold(state, |mut state| async move {
        loop {
            if !state.app.current() {
                return None;
            }
            let revision = match state.app.broker.monitor_revision() {
                Ok(v) => v,
                Err(_) => return None,
            };
            if state.revision != Some(revision) {
                state.revision = Some(revision);
                state.heartbeat = Instant::now();
                let bytes = Bytes::from(format!(
                    "event: revision\ndata: {}\n\n",
                    json!({"revision":revision})
                ));
                return Some((Ok::<_, Infallible>(Frame::data(bytes)), state));
            }
            if state.heartbeat.elapsed() >= Duration::from_secs(15) {
                state.heartbeat = Instant::now();
                return Some((
                    Ok(Frame::data(Bytes::from_static(b": heartbeat\n\n"))),
                    state,
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .boxed();
    let mut response = response(
        StatusCode::OK,
        "text/event-stream; charset=utf-8",
        Bytes::new(),
    );
    *response.body_mut() = StreamBody::new(stream).boxed_unsync();
    response
}

/// Supervisor is polled alongside the broker; no separate executable is launched.
/// Returning/dropping this future aborts all of its connection tasks.
pub async fn run(broker: Broker) {
    loop {
        let desired = {
            let control = broker.monitor_control.lock().unwrap();
            if control.enabled {
                Some((
                    control.generation,
                    control.port,
                    control.token.clone().unwrap(),
                ))
            } else {
                None
            }
        };
        let Some((generation, port, token)) = desired else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => listener,
            Err(_) => {
                {
                    let mut control = broker.monitor_control.lock().unwrap();
                    if control.current(generation) {
                        control.url = None;
                        control.last_error = Some("Could not bind local monitor port".into());
                    }
                }
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if !broker.monitor_control.lock().unwrap().current(generation) {
                        break;
                    }
                }
                continue;
            }
        };
        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(_) => continue,
        };
        {
            let mut control = broker.monitor_control.lock().unwrap();
            if !control.current(generation) {
                continue;
            }
            control.url = Some(format!("http://{address}"));
        }
        serve_generation(broker.clone(), generation, token, listener, address).await;
    }
}
async fn serve_generation(
    broker: Broker,
    generation: u64,
    token: String,
    listener: TcpListener,
    address: SocketAddr,
) {
    let app = App {
        broker,
        generation,
        host: address.to_string(),
        origin: format!("http://{address}"),
        token,
        events: Arc::new(Semaphore::new(MAX_EVENTS)),
        rate: Arc::new(Mutex::new(Rate {
            started: Instant::now(),
            count: 0,
        })),
    };
    let mut tasks = JoinSet::new();
    let mut check = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            _=check.tick()=>{if !app.current(){break;}},
            accepted=listener.accept()=>{
                let Ok((socket,_))=accepted else{break;};
                if tasks.len()>=MAX_CONNECTIONS{drop(socket);continue;}
                let app=app.clone();
                tasks.spawn(async move {
                    let event_stream=Arc::new(AtomicBool::new(false));
                    let flag=event_stream.clone();
                    let service=service_fn(move|request|{
                        let app=app.clone();let flag=flag.clone();
                        async move {
                            let response=route(request,app).await?;
                            flag.store(response.status()==StatusCode::OK && response.headers().get(CONTENT_TYPE).is_some_and(|v|v.as_bytes()==b"text/event-stream; charset=utf-8"),Ordering::Relaxed);
                            Ok::<_,Infallible>(response)
                        }
                    });
                    let mut builder=http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_headers(32).max_buf_size(16*1024).keep_alive(false);
                    let connection=builder.serve_connection(TokioIo::new(socket),service);
                    tokio::pin!(connection);
                    // Ordinary slow readers cannot occupy slots for an SSE lifetime.
                    if tokio::time::timeout(Duration::from_secs(10), &mut connection).await.is_err() && event_stream.load(Ordering::Relaxed) {
                        let _=tokio::time::timeout(Duration::from_secs(1790),connection).await;
                    }
                });
            },
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
