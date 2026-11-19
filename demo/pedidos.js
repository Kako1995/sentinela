app.get('/pedidos', async (req, res) => {
  const { cliente } = req.query;
  const sql = `
    SELECT id, total FROM pedidos
    WHERE cliente = '${cliente}'
  `;
  const resultado = await db.query(sql);
  res.json(resultado.rows);
});
