//! JDBC URL templates and tunnel redirection.
use std::collections::HashMap;

/// Placeholders that name the catalogue rather than the server.
///
/// `{database}`, `{service}`, `{sid}` and `{file}` all stand for the same thing
/// on screen — what a product calls the thing you connect *to* — but each driver
/// family spells it its own way, so one field on screen fills whichever of these
/// the template happens to use.
pub const CATALOGUE_PLACEHOLDERS: [&str; 4] = ["database", "service", "sid", "file"];

/// Fills `{placeholder}` holes in a driver's URL template.
///
/// An unknown placeholder is left as it stands rather than blanked: a template
/// from a hand-written `drivers.json` may well use a hole the editor has no
/// field for, and leaving `{warehouse}` visible in the preview says so, whereas
/// silently dropping it produces a URL that fails at the driver with no clue
/// where the gap came from.
pub fn substitute(template: &str, values: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}').map(|index| open + index) else {
            // An unbalanced brace is part of the URL, not a hole.
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &rest[open + 1..close];
        match values.get(name) {
            Some(value) => out.push_str(value),
            None => out.push_str(&rest[open..=close]),
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The placeholders a template actually uses, in the order they appear.
pub fn placeholders_of(template: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}').map(|index| open + index) else {
            break;
        };
        let name = rest[open + 1..close].to_string();
        if !name.is_empty() && !found.contains(&name) {
            found.push(name);
        }
        rest = &rest[close + 1..];
    }
    found
}

/// Rewrites the host and port of an already-assembled JDBC URL.
///
/// What the tunnel needs: the profile's URL names the database as it is called
/// *inside* the remote network, and the driver has to be pointed at the local
/// port instead. Only the authority — the `host:port` between `//` and the next
/// `/`, `;`, `?` or end — is touched, so a URL's grammar survives whatever shape
/// it has. A URL with no `//` (SQLite's `jdbc:sqlite:/path`, H2's
/// `jdbc:h2:mem:x`) is left alone: there is no server in it to redirect.
pub fn redirect_authority(url: &str, host: &str, port: u16) -> String {
    let Some(slashes) = url.find("//") else {
        return url.to_string();
    };
    let start = slashes + 2;
    let end = url[start..]
        .find(['/', ';', '?'])
        .map_or(url.len(), |index| start + index);
    format!("{}{host}:{port}{}", &url[..start], &url[end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn a_template_is_filled_hole_by_hole() {
        let filled = substitute(
            "jdbc:postgresql://{host}:{port}/{database}",
            &values(&[
                ("host", "db.example.com"),
                ("port", "5432"),
                ("database", "app"),
            ]),
        );
        assert_eq!(filled, "jdbc:postgresql://db.example.com:5432/app");

        // SQL Server's semicolon grammar and Oracle's `@//` both go through the
        // same substitution untouched.
        assert_eq!(
            substitute(
                "jdbc:sqlserver://{host}:{port};databaseName={database}",
                &values(&[("host", "sql"), ("port", "1433"), ("database", "app")]),
            ),
            "jdbc:sqlserver://sql:1433;databaseName=app"
        );
        assert_eq!(
            substitute(
                "jdbc:oracle:thin:@//{host}:{port}/{service}",
                &values(&[("host", "ora"), ("port", "1521"), ("service", "ORCLPDB")]),
            ),
            "jdbc:oracle:thin:@//ora:1521/ORCLPDB"
        );
    }

    #[test]
    fn a_hole_nothing_fills_stays_visible() {
        // A hand-written `drivers.json` may use a placeholder the editor has no
        // field for. Leaving it in the preview says so; blanking it would
        // produce a URL that fails at the driver with nothing to point at.
        assert_eq!(
            substitute("jdbc:x://{host}/{warehouse}", &values(&[("host", "h")])),
            "jdbc:x://h/{warehouse}"
        );
        // An unbalanced brace is part of the URL.
        assert_eq!(substitute("jdbc:x:{oops", &values(&[])), "jdbc:x:{oops");
    }

    #[test]
    fn the_holes_a_template_uses_are_listed_in_order_and_once_each() {
        assert_eq!(
            placeholders_of("jdbc:postgresql://{host}:{port}/{database}"),
            vec!["host", "port", "database"]
        );
        assert_eq!(placeholders_of("jdbc:sqlite:{file}"), vec!["file"]);
        assert_eq!(
            placeholders_of("jdbc:x://{host}:{port}/?failover={host}"),
            vec!["host", "port"]
        );
        assert!(placeholders_of("jdbc:h2:mem:test").is_empty());
    }

    #[test]
    fn a_tunnel_moves_only_the_authority_of_a_url() {
        assert_eq!(
            redirect_authority("jdbc:postgresql://db.internal:5432/app", "127.0.0.1", 41234),
            "jdbc:postgresql://127.0.0.1:41234/app"
        );
        // The semicolon grammar: the authority ends at the first `;`.
        assert_eq!(
            redirect_authority(
                "jdbc:sqlserver://db.internal:1433;databaseName=app",
                "127.0.0.1",
                41234
            ),
            "jdbc:sqlserver://127.0.0.1:41234;databaseName=app"
        );
        // A query string.
        assert_eq!(
            redirect_authority(
                "jdbc:mysql://db.internal:3306/app?useSSL=false",
                "127.0.0.1",
                1
            ),
            "jdbc:mysql://127.0.0.1:1/app?useSSL=false"
        );
        // A URL with no authority at all has no server to redirect.
        assert_eq!(
            redirect_authority("jdbc:h2:mem:test", "127.0.0.1", 41234),
            "jdbc:h2:mem:test"
        );
        assert_eq!(
            redirect_authority("jdbc:sqlite:/var/db/app.sqlite", "127.0.0.1", 1),
            "jdbc:sqlite:/var/db/app.sqlite"
        );
    }
}
