// Firebird's hooks: what firebird.yml cannot say as data.

/**
 * RDB$TRIGGER_TYPE, which the profile's trigger query puts in the timing
 * column, read as the timing and the events: an odd code before a table
 * change, an even one after, and up to three events two bits each in
 * (code + 1) >> 1 - insert 1, update 2, delete 3. A database trigger's
 * code is 8192 and above.
 */
void triggerRow(String[] r) {
    if (r[4] == null || !(r[4] ==~ /\d+/)) {
        return
    }
    int type = r[4] as int
    if (type >= 8192) {
        r[4] = null
        r[5] = ['CONNECT', 'DISCONNECT', 'TRANSACTION START', 'TRANSACTION COMMIT',
                'TRANSACTION ROLLBACK'][type - 8192]
        r[6] = 'DATABASE'
        return
    }
    r[4] = ((type - 1) & 1) == 0 ? 'BEFORE' : 'AFTER'
    int code = (type + 1) >> 1
    List<String> events = []
    for (int shift = 0; shift < 6; shift += 2) {
        int action = (code >> shift) & 3
        if (action != 0) {
            events << ['INSERT', 'UPDATE', 'DELETE'][action - 1]
        }
    }
    r[5] = events.join(' OR ')
}

/** A sequence's current value, which no catalog column holds: GEN_ID by zero. */
String sequenceValue(Connection conn, Ident id, String catalog, String schema, String name,
        String listed) {
    conn.createStatement().withCloseable { st ->
        st.executeQuery('SELECT GEN_ID(' + id.q(name) + ', 0) FROM RDB$DATABASE').withCloseable { rs ->
            rs.next() ? rs.getString(1) : listed
        }
    }
}

/**
 * The sequences put back where the source's are, after the rows. Since
 * Firebird 4 a sequence restarted with n hands out n next, so the restart is
 * one increment past the value the source last handed out.
 */
List<String> counters(DatabaseMetaData dbm, Ident id, List<Sequence> sequences,
        List<Table> tables, boolean data) {
    sequences.findAll { it.value() ==~ /-?\d+/ }.collect {
        long increment = (it.increment() ?: '1') ==~ /-?\d+/ ? it.increment() as long : 1L
        'ALTER SEQUENCE ' + id.q(it.name()) + ' RESTART WITH ' + ((it.value() as long) + increment) + ';'
    }
}

/**
 * The constraint behind each index, from RDB$RELATION_CONSTRAINTS. A unique
 * index made by CREATE UNIQUE INDEX enforces none, so it is not offered as a
 * constraint that DROP CONSTRAINT could drop.
 */
Map<String, String> indexConstraints(Connection conn, Ident id, String catalog, String schema,
        String table) {
    Map<String, String> out = [:]
    each(conn, 'SELECT TRIM(RDB$INDEX_NAME), TRIM(RDB$CONSTRAINT_NAME) FROM RDB$RELATION_CONSTRAINTS' +
            " WHERE RDB\$CONSTRAINT_TYPE IN ('PRIMARY KEY', 'UNIQUE') AND RDB\$RELATION_NAME = ?",
            table) { ResultSet rs ->
        if (rs.getString(1) != null) {
            out[Vendor.indexKey(null, rs.getString(1))] = rs.getString(2)
        }
    }
    out
}

/**
 * A routine's own text, which Firebird keeps only as its body: the header -
 * the arguments, what it returns - is put back together from RDB$FIELDS,
 * by the types the database holds them as.
 */
String routineText(Connection conn, Ident id, String catalog, String schema, String name,
        boolean function) {
    function ? functionText(conn, id, name) : procedureText(conn, id, name)
}

private static String procedureText(Connection conn, Ident id, String name) {
    String body = single(conn, 'SELECT RDB$PROCEDURE_SOURCE FROM RDB$PROCEDURES' +
            ' WHERE RDB$PROCEDURE_NAME = ? AND RDB$PACKAGE_NAME IS NULL', name)
    if (body == null) {
        return null
    }
    List<String> inputs = []
    List<String> outputs = []
    each(conn, 'SELECT TRIM(p.RDB$PARAMETER_NAME), p.RDB$PARAMETER_TYPE, ' + FIELD +
            ' FROM RDB$PROCEDURE_PARAMETERS p JOIN RDB$FIELDS f ON f.RDB$FIELD_NAME = p.RDB$FIELD_SOURCE' +
            ' WHERE p.RDB$PROCEDURE_NAME = ? AND p.RDB$PACKAGE_NAME IS NULL' +
            ' ORDER BY p.RDB$PARAMETER_TYPE, p.RDB$PARAMETER_NUMBER', name) { ResultSet rs ->
        String parameter = id.q(rs.getString(1)) + ' ' + typeOf(rs, 3)
        (rs.getInt(2) == 0 ? inputs : outputs) << parameter
    }
    'CREATE PROCEDURE ' + id.q(name) +
            (inputs ? ' (' + inputs.join(', ') + ')' : '') +
            (outputs ? '\nRETURNS (' + outputs.join(', ') + ')' : '') +
            '\nAS\n' + body
}

private static String functionText(Connection conn, Ident id, String name) {
    String body = single(conn, 'SELECT RDB$FUNCTION_SOURCE FROM RDB$FUNCTIONS' +
            ' WHERE RDB$FUNCTION_NAME = ? AND RDB$PACKAGE_NAME IS NULL', name)
    if (body == null) {
        return null
    }
    List<String> arguments = []
    String returns = null
    each(conn, 'SELECT TRIM(a.RDB$ARGUMENT_NAME), a.RDB$ARGUMENT_POSITION, ' + FIELD +
            ' FROM RDB$FUNCTION_ARGUMENTS a JOIN RDB$FIELDS f ON f.RDB$FIELD_NAME = a.RDB$FIELD_SOURCE' +
            ' JOIN RDB$FUNCTIONS fn ON fn.RDB$FUNCTION_NAME = a.RDB$FUNCTION_NAME' +
            ' AND fn.RDB$PACKAGE_NAME IS NULL' +
            ' WHERE a.RDB$FUNCTION_NAME = ? AND a.RDB$PACKAGE_NAME IS NULL' +
            ' ORDER BY a.RDB$ARGUMENT_POSITION', name) { ResultSet rs ->
        // The return value is the argument with no name, at RDB$RETURN_ARGUMENT.
        if (rs.getString(1) == null) {
            returns = typeOf(rs, 3)
        } else {
            arguments << id.q(rs.getString(1)) + ' ' + typeOf(rs, 3)
        }
    }
    'CREATE FUNCTION ' + id.q(name) + ' (' + arguments.join(', ') + ')' +
            '\nRETURNS ' + returns + '\nAS\n' + body
}

/** The RDB$FIELDS columns typeOf reads, in its order. */
@groovy.transform.Field
static final String FIELD = 'TRIM(f.RDB$FIELD_NAME), f.RDB$FIELD_TYPE, f.RDB$FIELD_SUB_TYPE,' +
        ' f.RDB$CHARACTER_LENGTH, f.RDB$FIELD_PRECISION, f.RDB$FIELD_SCALE'

/**
 * A field's type as a declaration writes it, from the RDB$FIELDS columns of
 * FIELD at column `at`: a domain of the user's by its name, an implicit one
 * by what it holds.
 */
private static String typeOf(ResultSet rs, int at) {
    String domain = rs.getString(at)
    if (domain != null && !domain.startsWith('RDB$')) {
        return domain
    }
    int type = rs.getInt(at + 1)
    int sub = rs.getInt(at + 2)
    int length = rs.getInt(at + 3)
    int precision = rs.getInt(at + 4)
    int scale = -rs.getInt(at + 5)
    if ((type in [7, 8, 16, 26]) && (sub == 1 || sub == 2)) {
        return (sub == 1 ? 'NUMERIC' : 'DECIMAL') + "(${precision}, ${scale})"
    }
    switch (type) {
        case 7: return 'SMALLINT'
        case 8: return 'INTEGER'
        case 16: return 'BIGINT'
        case 26: return 'INT128'
        case 10: return 'FLOAT'
        case 27: return 'DOUBLE PRECISION'
        case 24: return 'DECFLOAT(16)'
        case 25: return 'DECFLOAT(34)'
        case 12: return 'DATE'
        case 13: return 'TIME'
        case 28: return 'TIME WITH TIME ZONE'
        case 35: return 'TIMESTAMP'
        case 29: return 'TIMESTAMP WITH TIME ZONE'
        case 23: return 'BOOLEAN'
        case 14: return "CHAR(${length})"
        case 37: return "VARCHAR(${length})"
        case 261: return sub == 1 ? 'BLOB SUB_TYPE TEXT' : 'BLOB'
        default: return "/* type ${type} */ BLOB"
    }
}

private static String single(Connection conn, String sql, String name) {
    conn.prepareStatement(sql).withCloseable { ps ->
        ps.setString(1, name)
        ps.executeQuery().withCloseable { rs -> rs.next() ? rs.getString(1) : null }
    }
}

private static void each(Connection conn, String sql, String name, Closure row) {
    conn.prepareStatement(sql).withCloseable { ps ->
        ps.setString(1, name)
        ps.executeQuery().withCloseable { rs ->
            while (rs.next()) {
                row(rs)
            }
        }
    }
}
