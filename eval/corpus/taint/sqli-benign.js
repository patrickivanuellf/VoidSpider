app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id=?', [parseInt(req.query.id, 10)], (e, rows) => res.json(rows));
});
