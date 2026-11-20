//! The database products the applications ship a driver definition for, as
//! facts about each product and its usual JDBC driver.
//!
//! What belongs to the product is written here once for rudbman and rudbgen
//! both: its name, its driver's class and Maven artifact, the shape of its
//! URL, its port, and the dialect id that `rudbman-sql` and the bridges know it
//! by. What each application chooses for itself stays with it: the id its
//! `drivers.json` keys the definition by, the icon it draws, the driver
//! version it downloads, and anything else its definitions carry, such as
//! rudbgen's connection properties and custom queries.
//!
//! A product added here reaches an application only when that application
//! lists it among its built-ins.

/// One database product and its usual JDBC driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product {
    /// The name a driver definition for it is shown by.
    pub name: &'static str,
    /// The driver's `java.sql.Driver` class.
    pub class: &'static str,
    /// The driver's Maven group and artifact, `group:artifact`, without a
    /// version: each application pins the version it downloads.
    pub artifact: &'static str,
    /// The connection URL, with `{host}`, `{port}` and one of
    /// [`CATALOG_PLACEHOLDERS`](crate::url::CATALOG_PLACEHOLDERS) as holes.
    pub url_template: &'static str,
    /// The port the server listens on unless told otherwise; `None` for a
    /// product that is a file rather than a service.
    pub default_port: Option<u16>,
    /// The dialect id, as `drivers.json` spells it.
    pub dialect: &'static str,
}

impl Product {
    /// The Maven coordinate of `version` of this product's driver.
    pub fn maven(&self, version: &str) -> String {
        format!("{}:{version}", self.artifact)
    }
}

/// The dialect id of a product the SQL layer has no rules of its own for.
pub const GENERIC_DIALECT: &str = "generic";

/// H2 as a server, reached over TCP.
pub const H2_SERVER: Product = Product {
    name: "H2 Server",
    class: "org.h2.Driver",
    artifact: "com.h2database:h2",
    url_template: "jdbc:h2:tcp://{host}:{port}/{database}",
    default_port: Some(9092),
    dialect: "h2",
};

/// H2 as a file opened in this process. It takes an exclusive lock, so the
/// same database cannot be open in a running H2 server at the time.
pub const H2_EMBEDDED: Product = Product {
    name: "H2 Embedded",
    class: "org.h2.Driver",
    artifact: "com.h2database:h2",
    url_template: "jdbc:h2:{file}",
    default_port: None,
    dialect: "h2",
};

/// PostgreSQL.
pub const POSTGRESQL: Product = Product {
    name: "PostgreSQL",
    class: "org.postgresql.Driver",
    artifact: "org.postgresql:postgresql",
    url_template: "jdbc:postgresql://{host}:{port}/{database}",
    default_port: Some(5432),
    dialect: "postgres",
};

/// MySQL, through Connector/J.
pub const MYSQL: Product = Product {
    name: "MySQL",
    class: "com.mysql.cj.jdbc.Driver",
    artifact: "com.mysql:mysql-connector-j",
    url_template: "jdbc:mysql://{host}:{port}/{database}",
    default_port: Some(3306),
    dialect: "mysql",
};

/// MariaDB, through MariaDB Connector/J.
///
/// Its dialect read as `mysql` until a server disagreed: the fork spells a
/// check-constraint drop `DROP CONSTRAINT` where MySQL spells it
/// `DROP CHECK`, and answers a syntax error for MySQL's. It has a dialect of
/// its own now, which is MySQL's in every other spelling.
pub const MARIADB: Product = Product {
    name: "MariaDB",
    class: "org.mariadb.jdbc.Driver",
    artifact: "org.mariadb.jdbc:mariadb-java-client",
    url_template: "jdbc:mariadb://{host}:{port}/{database}",
    default_port: Some(3306),
    dialect: "mariadb",
};

/// SQLite, which is a file, not a service: no host, no port.
pub const SQLITE: Product = Product {
    name: "SQLite",
    class: "org.sqlite.JDBC",
    artifact: "org.xerial:sqlite-jdbc",
    url_template: "jdbc:sqlite:{file}",
    default_port: None,
    dialect: "sqlite",
};

/// Oracle Database, through the thin driver, by service name; the older SID
/// form is `@//{host}:{port}:{sid}`.
pub const ORACLE_THIN: Product = Product {
    name: "Oracle Thin",
    class: "oracle.jdbc.OracleDriver",
    artifact: "com.oracle.database.jdbc:ojdbc11",
    url_template: "jdbc:oracle:thin:@//{host}:{port}/{service}",
    default_port: Some(1521),
    dialect: "oracle",
};

/// Microsoft SQL Server. Its URL carries semicolon-separated properties, not
/// a path: that is this driver's grammar, not a typo.
pub const MSSQL: Product = Product {
    name: "Microsoft SQL Server",
    class: "com.microsoft.sqlserver.jdbc.SQLServerDriver",
    artifact: "com.microsoft.sqlserver:mssql-jdbc",
    url_template: "jdbc:sqlserver://{host}:{port};databaseName={database}",
    default_port: Some(1433),
    dialect: "mssql",
};

/// IBM Db2, through IBM's JCC, the type 4 driver: the one Maven Central
/// carries, and the same JAR for Db2 on Linux, UNIX and Windows, z/OS and
/// IBM i. The database in its URL is the one the server catalogs, not a
/// schema: a schema is picked after connecting, like everywhere else.
pub const DB2: Product = Product {
    name: "IBM Db2",
    class: "com.ibm.db2.jcc.DB2Driver",
    artifact: "com.ibm.db2:jcc",
    url_template: "jdbc:db2://{host}:{port}/{database}",
    default_port: Some(50000),
    dialect: "db2",
};

/// MongoDB, through its JDBC driver, on 27017, the port mongod listens on.
pub const MONGODB: Product = Product {
    name: "MongoDB",
    class: "com.mongodb.jdbc.MongoDriver",
    artifact: "org.mongodb:mongodb-jdbc",
    url_template: "jdbc:mongodb://{host}:{port}/{database}",
    default_port: Some(27017),
    dialect: GENERIC_DIALECT,
};

/// CUBRID. Its URL is colon-separated, and the trailing empty user and
/// password fields are part of the grammar: `host:port:database:user:password:`.
pub const CUBRID: Product = Product {
    name: "CUBRID",
    class: "cubrid.jdbc.driver.CUBRIDDriver",
    artifact: "org.cubrid:cubrid-jdbc",
    url_template: "jdbc:cubrid:{host}:{port}:{database}:::",
    default_port: Some(33000),
    dialect: GENERIC_DIALECT,
};

/// Every product here.
pub const ALL: &[Product] = &[
    H2_SERVER,
    H2_EMBEDDED,
    POSTGRESQL,
    MYSQL,
    MARIADB,
    SQLITE,
    ORACLE_THIN,
    MSSQL,
    DB2,
    MONGODB,
    CUBRID,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::{CATALOG_PLACEHOLDERS, placeholders_of};

    /// Every template's holes are ones a connection editor fills, a port is
    /// known exactly where the template has one, and one catalog field names
    /// what is connected to.
    #[test]
    fn templates_use_the_editors_holes() {
        for product in ALL {
            let holes = placeholders_of(product.url_template);
            for hole in &holes {
                assert!(
                    hole == "host"
                        || hole == "port"
                        || CATALOG_PLACEHOLDERS.contains(&hole.as_str()),
                    "{}: unknown hole {hole}",
                    product.name
                );
            }
            assert_eq!(
                holes.iter().any(|hole| hole == "port"),
                product.default_port.is_some(),
                "{}",
                product.name
            );
            assert_eq!(
                holes
                    .iter()
                    .filter(|hole| CATALOG_PLACEHOLDERS.contains(&hole.as_str()))
                    .count(),
                1,
                "{}",
                product.name
            );
            assert!(
                product.url_template.starts_with("jdbc:"),
                "{}",
                product.name
            );
        }
    }

    /// An artifact is a group and a name, and a version makes it a coordinate.
    #[test]
    fn artifacts_take_a_version() {
        for product in ALL {
            assert_eq!(product.artifact.matches(':').count(), 1, "{}", product.name);
        }
        assert_eq!(DB2.maven("12.1.5.0"), "com.ibm.db2:jcc:12.1.5.0");
    }

    /// No two products share a name.
    #[test]
    fn names_are_unique() {
        let mut names: Vec<_> = ALL.iter().map(|product| product.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL.len());
    }
}
