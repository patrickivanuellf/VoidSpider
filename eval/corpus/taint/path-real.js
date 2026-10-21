app.get('/file', (req, res) => {
  fs.readFile(path.join('/data', req.query.name), (e, buf) => res.send(buf));
});
