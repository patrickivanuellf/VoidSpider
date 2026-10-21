app.get('/hello', (req, res) => {
  const el = document.createElement('h1');
  el.textContent = 'Hi ' + req.query.name;
  res.send(el.outerHTML);
});
