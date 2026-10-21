app.post('/calc', (req, res) => {
  res.send(String(eval(req.body.expr)));
});
