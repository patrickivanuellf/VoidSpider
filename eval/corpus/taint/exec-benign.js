const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
  execFile('ping', ['-c', '1', req.query.host.replace(/[^0-9a-zA-Z.]/g, '')], (e, out) => res.send(out));
});
