// The read API is served over a Unix domain socket, and `std` has no Windows
// equivalent, so the whole boot test is Unix-only. The remaining modules stay
// platform-neutral: `node_api` drives the real `ergo-api` router over loopback
// TCP, so it still covers the daemon on Windows.
#[cfg(unix)]
mod daemon_boot;
mod http_client;
mod node_api;
mod routes;
mod scan_registry_rewind;
mod store_reopen;
mod support;
mod sync;
