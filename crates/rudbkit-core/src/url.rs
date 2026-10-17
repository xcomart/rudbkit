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

/// Reads a URL back into the values its template's holes were filled with.
///
/// The template is split on its `{holes}` and the URL matched against the
/// literal pieces between them; a URL that does not fit — because it was
/// overridden, or written for another driver — yields `None`. A hole the
/// template uses twice appears twice, in order. Each value runs up to the first
/// occurrence of the literal that follows its hole, so a value that itself
/// contains that literal (an IPv6 host before a `:`) is split in the wrong
/// place; callers that need a value to *mean* something check it.
pub fn decompose(template: &str, url: &str) -> Option<Vec<(String, String)>> {
    if placeholders_of(template).is_empty() {
        return None;
    }

    let mut values = Vec::new();
    let mut rest_template = template;
    let mut rest_url = url;

    while let Some(open) = rest_template.find('{') {
        let close = rest_template[open..].find('}').map(|index| open + index)?;
        let literal = &rest_template[..open];
        rest_url = rest_url.strip_prefix(literal)?;
        let name = rest_template[open + 1..close].to_string();
        rest_template = &rest_template[close + 1..];

        // The value runs up to the next literal, or to the end of the URL when
        // the hole is the last thing in the template.
        let next_literal_end = rest_template.find('{').unwrap_or(rest_template.len());
        let next_literal = &rest_template[..next_literal_end];
        let value_end = if next_literal.is_empty() {
            rest_url.len()
        } else {
            rest_url.find(next_literal)?
        };
        values.push((name, rest_url[..value_end].to_string()));
        rest_url = &rest_url[value_end..];
    }

    (rest_url == rest_template).then_some(values)
}

/// A tunnelled URL that names no server the tunnel could stand in for.
///
/// Returned by [`redirect_url`] instead of the URL itself: a profile that asked
/// for an SSH tunnel and then connected straight to the database would reach
/// it — or fail to — by a route the user explicitly ruled out, and would do so
/// without a word. The URL is deliberately not part of the message, because a
/// JDBC URL may carry a password in its properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedirectError;

impl std::fmt::Display for RedirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the connection URL has no host and port the SSH tunnel can replace; \
             use the driver's URL template (with `{host}` and `{port}`) or a \
             `//host:port` URL, or turn the tunnel off",
        )
    }
}

impl std::error::Error for RedirectError {}

/// Points an already-assembled JDBC URL at the local end of a tunnel.
///
/// What the tunnel needs: the profile's URL names the database as it is called
/// *inside* the remote network, and the driver has to be pointed at the local
/// port instead. Two ways are tried, most precise first:
///
/// 1. **The template.** When `template` — the driver's URL template, the one
///    the URL was rendered from — has both a `{host}` and a `{port}` hole and
///    the URL still fits it, the URL is rendered again with the tunnel's host
///    and port in those holes and every other value as it was. This is the
///    only way to redirect a grammar with no `//`: CUBRID's
///    `jdbc:cubrid:{host}:{port}:{database}:::`, Oracle's SID form
///    `jdbc:oracle:thin:@{host}:{port}:{sid}`. A decomposed port that is not a
///    number means the URL was split in the wrong place (see [`decompose`]),
///    and the template is not trusted.
/// 2. **The authority.** Otherwise the `host:port` between `//` and the next
///    `/`, `;`, `?` or end is replaced, so a hand-edited URL's grammar survives
///    whatever shape it has.
///
/// A URL that neither fits — SQLite's `jdbc:sqlite:/path`, H2's `jdbc:h2:mem:x`,
/// an overridden Oracle descriptor — is a [`RedirectError`], never the URL
/// unchanged: a tunnelled profile must not connect around its tunnel.
pub fn redirect_url(
    url: &str,
    template: &str,
    host: &str,
    port: u16,
) -> Result<String, RedirectError> {
    if let Some(redirected) = redirect_template(url, template, host, port) {
        return Ok(redirected);
    }
    rewrite_authority(url, host, port).ok_or(RedirectError)
}

/// Step 1 of [`redirect_url`]: the URL rendered again through its template.
fn redirect_template(url: &str, template: &str, host: &str, port: u16) -> Option<String> {
    let names = placeholders_of(template);
    if !names.iter().any(|name| name == "host") || !names.iter().any(|name| name == "port") {
        return None;
    }
    let mut values: HashMap<String, String> = decompose(template, url)?.into_iter().collect();
    values.get("port")?.parse::<u16>().ok()?;
    values.insert("host".to_string(), host.to_string());
    values.insert("port".to_string(), port.to_string());
    Some(substitute(template, &values))
}

/// Step 2 of [`redirect_url`]: the `//` authority replaced, if there is one.
fn rewrite_authority(url: &str, host: &str, port: u16) -> Option<String> {
    let start = url.find("//")? + 2;
    let end = url[start..]
        .find(['/', ';', '?'])
        .map_or(url.len(), |index| start + index);
    Some(format!("{}{host}:{port}{}", &url[..start], &url[end..]))
}

/// Rewrites the host and port of an already-assembled JDBC URL.
///
/// Only the authority — the `host:port` between `//` and the next `/`, `;`, `?`
/// or end — is touched. A URL with no `//` comes back **unchanged**, which for a
/// tunnelled profile means connecting straight to the database, around the
/// tunnel; [`redirect_url`] refuses such a URL instead and also handles
/// templates with no `//`.
#[deprecated(
    since = "0.1.3",
    note = "use `redirect_url`, which never returns a URL that bypasses the tunnel"
)]
pub fn redirect_authority(url: &str, host: &str, port: u16) -> String {
    rewrite_authority(url, host, port).unwrap_or_else(|| url.to_string())
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
    #[allow(deprecated)]
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

    #[test]
    fn a_url_reads_back_into_its_template_values() {
        assert_eq!(
            decompose(
                "jdbc:postgresql://{host}:{port}/{database}",
                "jdbc:postgresql://db.internal:5432/app"
            ),
            Some(vec![
                ("host".to_string(), "db.internal".to_string()),
                ("port".to_string(), "5432".to_string()),
                ("database".to_string(), "app".to_string()),
            ])
        );
        // Another driver's URL, or an overridden one, does not fit.
        assert_eq!(
            decompose(
                "jdbc:postgresql://{host}:{port}/{database}",
                "jdbc:mysql://db.internal:3306/app"
            ),
            None
        );
        assert_eq!(decompose("jdbc:h2:mem:test", "jdbc:h2:mem:test"), None);
    }

    #[test]
    fn a_tunnel_fills_the_host_and_port_holes_of_a_template_without_slashes() {
        // CUBRID: no `//` anywhere, so the authority rewrite has nothing to
        // hold on to and used to hand the URL back untouched — connecting
        // straight to the database while a tunnel stood open beside it.
        assert_eq!(
            redirect_url(
                "jdbc:cubrid:db.internal:33000:demodb:::",
                "jdbc:cubrid:{host}:{port}:{database}:::",
                "127.0.0.1",
                41234
            ),
            Ok("jdbc:cubrid:127.0.0.1:41234:demodb:::".to_string())
        );
        // Oracle's SID form.
        assert_eq!(
            redirect_url(
                "jdbc:oracle:thin:@ora.internal:1521:ORCL",
                "jdbc:oracle:thin:@{host}:{port}:{sid}",
                "127.0.0.1",
                41234
            ),
            Ok("jdbc:oracle:thin:@127.0.0.1:41234:ORCL".to_string())
        );
        // A template with `//` goes the same way, properties and all.
        assert_eq!(
            redirect_url(
                "jdbc:sqlserver://sql.internal:1433;databaseName=app",
                "jdbc:sqlserver://{host}:{port};databaseName={database}",
                "127.0.0.1",
                1
            ),
            Ok("jdbc:sqlserver://127.0.0.1:1;databaseName=app".to_string())
        );
    }

    #[test]
    fn a_url_that_left_its_template_falls_back_to_the_authority() {
        // Hand-edited: a query string the template does not have.
        assert_eq!(
            redirect_url(
                "jdbc:mysql://db.internal:3306/app?useSSL=false",
                "jdbc:mysql://{host}:{port}/{database}",
                "127.0.0.1",
                1
            ),
            Ok("jdbc:mysql://127.0.0.1:1/app?useSSL=false".to_string())
        );
        // A template with no `{port}` hole cannot place the tunnel's port.
        assert_eq!(
            redirect_url(
                "jdbc:x://db.internal/app",
                "jdbc:x://{host}/{database}",
                "127.0.0.1",
                1
            ),
            Ok("jdbc:x://127.0.0.1:1/app".to_string())
        );
        // A port that is not a number means the URL was split in the wrong
        // place (an IPv6 host before a `:`), so the template is not trusted —
        // and with no `//` either, nothing is.
        assert_eq!(
            redirect_url(
                "jdbc:cubrid:[::1]:33000:demodb:::",
                "jdbc:cubrid:{host}:{port}:{database}:::",
                "127.0.0.1",
                1
            ),
            Err(RedirectError)
        );
    }

    #[test]
    fn a_tunnelled_url_with_no_server_in_it_is_refused_not_passed_through() {
        for (url, template) in [
            ("jdbc:h2:mem:test", "jdbc:h2:mem:{database}"),
            ("jdbc:sqlite:/var/db/app.sqlite", "jdbc:sqlite:{file}"),
            // CUBRID overridden by hand into a shape its template no longer
            // matches: still no `//`, so still no way to redirect it.
            (
                "jdbc:cubrid:db.internal:33000:demodb:dba::?charset=utf8",
                "jdbc:cubrid:{host}:{port}:{database}:::",
            ),
            (
                "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(HOST=ora)(PORT=1521)))",
                "jdbc:oracle:thin:@{host}:{port}:{sid}",
            ),
            // No template at all: only the authority could save it.
            ("jdbc:cubrid:db.internal:33000:demodb:::", ""),
        ] {
            assert_eq!(
                redirect_url(url, template, "127.0.0.1", 41234),
                Err(RedirectError),
                "{url}"
            );
        }
        // The message never repeats the URL, which may hold a password.
        assert!(!RedirectError.to_string().contains("jdbc:"));
    }
}
