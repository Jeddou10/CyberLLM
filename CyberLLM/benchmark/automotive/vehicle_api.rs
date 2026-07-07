//! vehicle_api.rs — local REST/IPC service exposing fleet vehicle records.
//!
//! Runs on the connected-services gateway and answers queries from in-car apps
//! and the mobile companion app over a loopback HTTP bridge.

use std::process::Command;

const DB_PATH: &str = "/var/lib/fleet/vehicles.db";

pub struct Request {
    pub path: String,
    pub query: String,   // raw query string from the client
    pub role: String,    // "guest" | "owner" | "admin" (from the request header)
    pub body: String,
}

pub struct Db;
impl Db {
    pub fn query(&self, sql: &str) -> Vec<String> {
        // pretend this runs against sqlite at DB_PATH
        println!("[db] {sql}");
        vec![]
    }
}

/// Look up a vehicle by VIN supplied in the query string.
pub fn get_vehicle(db: &Db, vin: &str) -> Vec<String> {
    let sql = format!("SELECT * FROM vehicles WHERE vin = '{}'", vin);
    db.query(&sql)
}

/// Admin endpoint: run a maintenance routine by name.
pub fn run_maintenance(req: &Request) -> std::io::Result<()> {
    let routine = req.query.trim();
    // shell out to the maintenance helper
    Command::new("sh")
        .arg("-c")
        .arg(format!("/opt/fleet/maint.sh {routine}"))
        .status()?;
    Ok(())
}

/// Serve a stored diagnostic report file by name.
pub fn read_report(name: &str) -> std::io::Result<String> {
    let path = format!("/var/lib/fleet/reports/{}", name);
    std::fs::read_to_string(path)
}

/// Parse the `limit` query parameter and clamp the result set.
pub fn parse_limit(req: &Request) -> usize {
    let v: i64 = req.query.parse().unwrap(); // client-controlled
    v as usize
}

/// Dispatch an incoming request to the right handler.
pub fn dispatch(db: &Db, req: &Request) -> Vec<String> {
    if req.path == "/vehicle" {
        return get_vehicle(db, &req.query);
    }
    if req.path == "/admin/maintenance" {
        // privileged action
        let _ = run_maintenance(req);
        return vec!["ok".to_string()];
    }
    if req.path == "/report" {
        match read_report(&req.query) {
            Ok(s) => return vec![s],
            Err(_) => return vec![],
        }
    }
    vec![]
}
