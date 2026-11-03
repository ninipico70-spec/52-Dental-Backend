const jwt = require('jsonwebtoken');
const pool = require('./db');
const { DEFAULT_ROLE_PERMISSIONS, allPermissions, normalizePermissions } = require('./permissions');
const secret = () => process.env.JWT_SECRET || 'dev-secret';
exports.sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, secret(), { expiresIn: '12h' });
exports.required = (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  let token;
  try { token = jwt.verify(t, secret()); }
  catch { return res.status(401).json({ error: 'Please sign in again.' }); }
  pool.query(
    `SELECT u.id,u.name,u.role,u.active,r.permissions AS role_permissions
     FROM users u LEFT JOIN role_permissions r ON r.role=u.role
     WHERE u.id=$1`,
    [token.id]
  ).then(({ rows }) => {
    const user = rows[0];
    if (!user || !user.active)
      return res.status(401).json({ error: 'Please sign in again.' });
    const defaults = normalizePermissions(user.role_permissions || DEFAULT_ROLE_PERMISSIONS[user.role]);
    req.user = {
      id: user.id,
      name: user.name,
      role: user.role,
      permissions: user.role === 'admin'
        ? allPermissions()
        : defaults
    };
    next();
  }).catch(next);
};
exports.adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Only admins can do this.' });
exports.requirePermission = (feature, action) => (req, res, next) => {
  if (req.user.role === 'admin' || req.user.permissions?.[feature]?.[action] === true) return next();
  res.status(403).json({ error: `You do not have permission to ${action} ${feature}.` });
};
exports.requireAllPermissions = (...permissions) => (req, res, next) => {
  if (req.user.role === 'admin' ||
      permissions.every(([feature, action]) => req.user.permissions?.[feature]?.[action] === true))
    return next();
  res.status(403).json({ error: 'You do not have all required permissions for this action.' });
};
exports.requireAnyPermission = (...permissions) => (req, res, next) => {
  if (req.user.role === 'admin' ||
      permissions.some(([feature, action]) => req.user.permissions?.[feature]?.[action] === true))
    return next();
  res.status(403).json({ error: 'You do not have permission to view this feature.' });
};
