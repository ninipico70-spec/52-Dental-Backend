const FEATURES = [
  'patients', 'appointments', 'sessions', 'invoices', 'payments',
  'expenses', 'services', 'reports', 'users', 'settings'
];
const ACTIONS = ['view', 'create', 'edit', 'delete'];
const FEATURE_ACTIONS = {
  patients: ['view', 'create', 'edit', 'delete'],
  appointments: ['view', 'create', 'edit', 'delete'],
  sessions: ['view', 'create', 'edit', 'delete'],
  invoices: ['view', 'create', 'edit'],
  payments: ['view', 'create', 'edit', 'delete'],
  expenses: ['view', 'create', 'delete'],
  services: ['view', 'create', 'edit'],
  reports: ['view'],
  users: ['view'],
  settings: ['view', 'edit']
};

function grid(view = false, create = false, edit = false, remove = false) {
  return { view, create, edit, delete: remove };
}

const DEFAULT_ROLE_PERMISSIONS = {
  doctor: {
    patients: grid(true, true, true, true),
    appointments: grid(true, true, true, true),
    sessions: grid(true, true, true, true),
    invoices: grid(true, true, true),
    payments: grid(true, true, true, true),
    expenses: grid(true, true, false, true),
    services: grid(),
    reports: grid(true),
    users: grid(),
    settings: grid(true)
  },
  assistant: {
    patients: grid(true, true, true, true),
    appointments: grid(true, true, true, true),
    sessions: grid(true, true, true, true),
    invoices: grid(true, true, true),
    payments: grid(true, true, true, true),
    expenses: grid(true, true, false, true),
    services: grid(),
    reports: grid(true),
    users: grid(),
    settings: grid(true)
  },
  receptionist: {
    patients: grid(true, true, true),
    appointments: grid(true, true, true),
    sessions: grid(true),
    invoices: grid(true, true),
    payments: grid(true, true),
    expenses: grid(),
    services: grid(),
    reports: grid(true),
    users: grid(),
    settings: grid(true)
  }
};

function allPermissions() {
  return Object.fromEntries(FEATURES.map(feature => [feature, grid(true, true, true, true)]));
}

function normalizePermissions(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new Error('Permissions must be an object.');
  if (Object.keys(input).some(feature => !FEATURES.includes(feature)))
    throw new Error('Permissions contain an unknown feature.');

  const result = {};
  for (const feature of FEATURES) {
    const source = input[feature];
    if (source === undefined) {
      throw new Error(`Permissions are missing ${feature}.`);
    }
    if (!source || typeof source !== 'object' || Array.isArray(source) ||
        Object.keys(source).some(action => !ACTIONS.includes(action)))
      throw new Error(`Permissions for ${feature} are invalid.`);
    const actions = {};
    for (const action of ACTIONS) {
      const value = source[action];
      if (value === undefined) {
        throw new Error(`Permissions are missing ${feature}.${action}.`);
      }
      if (typeof value !== 'boolean')
        throw new Error(`Permission ${feature}.${action} must be true or false.`);
      if (value && !FEATURE_ACTIONS[feature].includes(action))
        throw new Error(`Permission ${feature}.${action} is not supported.`);
      actions[action] = value;
    }
    result[feature] = actions;
  }
  return result;
}

function constrainRolePermissions(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new Error('Stored role permissions must be an object.');
  const permissions = {};
  for (const feature of FEATURES) {
    const stored = input[feature];
    if (!stored || typeof stored !== 'object' || Array.isArray(stored))
      throw new Error(`Stored permissions for ${feature} are invalid.`);
    permissions[feature] = Object.fromEntries(ACTIONS.map(action => {
      const value = stored[action];
      if (FEATURE_ACTIONS[feature].includes(action) && typeof value !== 'boolean')
        throw new Error(`Stored permission ${feature}.${action} is invalid.`);
      return [action, FEATURE_ACTIONS[feature].includes(action) && value === true];
    }));
  }
  return normalizePermissions(permissions);
}

module.exports = {
  FEATURES,
  ACTIONS,
  FEATURE_ACTIONS,
  DEFAULT_ROLE_PERMISSIONS,
  allPermissions,
  normalizePermissions,
  constrainRolePermissions
};
