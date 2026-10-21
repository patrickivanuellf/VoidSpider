app.get('/hello', (req, res) => {
  res.send('<h1>Hi ' + req.query.name + '</h1>');
});
