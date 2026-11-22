// TiDB's hooks: where its sequences stand, which no catalog column says.

/**
 * The next value no TiDB node has cached yet, from SHOW TABLE ... NEXT_ROW_ID:
 * a restored sequence resumes there, past every value a cache may have
 * handed out, rather than at its start.
 */
String sequenceValue(Connection conn, Ident id, String catalog, String schema, String name,
        String listed) {
    conn.createStatement().withCloseable { st ->
        st.executeQuery('SHOW TABLE ' + id.qualify(catalog, name) + ' NEXT_ROW_ID').withCloseable { rs ->
            while (rs.next()) {
                if (rs.getString('ID_TYPE') == 'SEQUENCE') {
                    return rs.getString('NEXT_GLOBAL_ROW_ID')
                }
            }
            listed
        }
    }
}

/**
 * MySQL's counters for the tables, and each sequence set so that its next
 * value is the one sequenceValue read.
 */
List<String> counters(DatabaseMetaData dbm, Ident id, List<Sequence> sequences,
        List<Table> tables, boolean data) {
    List<String> out = new ArrayList<>(base.counters(dbm, id, sequences, tables, data))
    for (Sequence s : sequences) {
        if (s.value() ==~ /-?\d+/ && (s.increment() ?: '1') ==~ /-?\d+/) {
            long current = (s.value() as long) - ((s.increment() ?: '1') as long)
            out << 'SELECT SETVAL(' + id.qualify(s.catalog(), s.name()) + ', ' + current + ');'
        }
    }
    out
}
