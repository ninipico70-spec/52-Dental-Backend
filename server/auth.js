const jwt = require('jsonwebtoken');
const secret = () => process.env.JWT_SECRET || 'dev-secret';
exports.sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, secret(), { expiresIn: '12h' });
exports.required = (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(t, secret()); next(); }
  catch { res.status(401).json({ error: 'Please sign in again.' }); }
};
exports.adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Only admins can do this.' });
