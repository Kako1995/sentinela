def buscar(conn, nome):
    return conn.execute("SELECT * FROM usuarios WHERE nome = '" + nome + "'")
