let masterKey = null;

module.exports = {
  get: () => masterKey,
  set: (key) => { masterKey = key; },
  clear: () => { masterKey = null; },
};
