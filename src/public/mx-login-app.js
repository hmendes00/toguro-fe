var __defProp = Object.defineProperty;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
const ConfigService = {
  mxDeviceKey: "mx_device_id",
  mxUserId: "mx_user_id",
  mxTokenKey: "mx_access_token",
  mxPickleKey: "mx_pickle_key",
  mxHasPickleKey: "mx_has_pickle_key",
  mxHasMxToken: "mx_has_access_token",
  mxAccountData: "mx-account-data",
  loginRedirectPath: "/",
  defaultAvatar: "/default-avatar.jpeg",
  MatrixUrl: "https://matrix.org"
};
let indexedDB;
try {
  indexedDB = window.indexedDB;
} catch (e) {
}
let idb = null;
async function IdbInit() {
  if (!indexedDB) {
    throw new Error("IndexedDB not available");
  }
  idb = await new Promise((resolve, reject) => {
    const request = indexedDB.open("mx-acc-cached-items", 1);
    request.onerror = reject;
    request.onsuccess = (event) => {
      resolve(request.result);
    };
    request.onupgradeneeded = (event) => {
      const db = request.result;
      db.createObjectStore(ConfigService.mxPickleKey);
      db.createObjectStore(ConfigService.mxAccountData);
    };
  });
}
const IdbLoad = async (table, key) => {
  if (!idb) {
    await IdbInit();
  }
  return new Promise((resolve, reject) => {
    const txn = idb.transaction([table], "readonly");
    txn.onerror = reject;
    const objectStore = txn.objectStore(table);
    const request = objectStore.get(key);
    request.onerror = reject;
    request.onsuccess = (event) => {
      resolve(request.result);
    };
  });
};
const IdbSave = async (table, key, data2) => {
  if (!idb) {
    await IdbInit();
  }
  return new Promise((resolve, reject) => {
    const txn = idb.transaction([table], "readwrite");
    txn.onerror = reject;
    const objectStore = txn.objectStore(table);
    const request = objectStore.put(data2, key);
    request.onerror = reject;
    request.onsuccess = (event) => {
      resolve();
    };
  });
};
const IdbDelete = async (table, key) => {
  if (!idb) {
    await IdbInit();
  }
  return new Promise((resolve, reject) => {
    const txn = idb.transaction([table], "readwrite");
    txn.onerror = reject;
    const objectStore = txn.objectStore(table);
    const request = objectStore.delete(key);
    request.onerror = reject;
    request.onsuccess = (event) => {
      resolve();
    };
  });
};
var commonjsGlobal = typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : {};
var olmlib = {};
var interopRequireDefault = { exports: {} };
(function(module) {
  function _interopRequireDefault2(obj) {
    return obj && obj.__esModule ? obj : {
      "default": obj
    };
  }
  module.exports = _interopRequireDefault2, module.exports.__esModule = true, module.exports["default"] = module.exports;
})(interopRequireDefault);
var escaped = /[\\\"\x00-\x1F]/g;
var escapes = {};
for (var i = 0; i < 32; ++i) {
  escapes[String.fromCharCode(i)] = "\\U" + ("0000" + i.toString(16)).slice(-4).toUpperCase();
}
escapes["\b"] = "\\b";
escapes["	"] = "\\t";
escapes["\n"] = "\\n";
escapes["\f"] = "\\f";
escapes["\r"] = "\\r";
escapes['"'] = '\\"';
escapes["\\"] = "\\\\";
function escapeString(value) {
  escaped.lastIndex = 0;
  return value.replace(escaped, function(c) {
    return escapes[c];
  });
}
function stringify(value) {
  switch (typeof value) {
    case "string":
      return '"' + escapeString(value) + '"';
    case "number":
      return isFinite(value) ? value : "null";
    case "boolean":
      return value;
    case "object":
      if (value === null) {
        return "null";
      }
      if (Array.isArray(value)) {
        return stringifyArray(value);
      }
      return stringifyObject(value);
    default:
      throw new Error("Cannot stringify: " + typeof value);
  }
}
function stringifyArray(array) {
  var sep = "[";
  var result = "";
  for (var i2 = 0; i2 < array.length; ++i2) {
    result += sep;
    sep = ",";
    result += stringify(array[i2]);
  }
  if (sep != ",") {
    return "[]";
  } else {
    return result + "]";
  }
}
function stringifyObject(object) {
  var sep = "{";
  var result = "";
  var keys = Object.keys(object);
  keys.sort();
  for (var i2 = 0; i2 < keys.length; ++i2) {
    var key = keys[i2];
    result += sep + '"' + escapeString(key) + '":';
    sep = ",";
    result += stringify(object[key]);
  }
  if (sep != ",") {
    return "{}";
  } else {
    return result + "}";
  }
}
var anotherJson = { stringify };
var logger$1 = {};
var loglevel = { exports: {} };
(function(module) {
  (function(root, definition) {
    if (module.exports) {
      module.exports = definition();
    } else {
      root.log = definition();
    }
  })(commonjsGlobal, function() {
    var noop = function() {
    };
    var undefinedType = "undefined";
    var isIE = typeof window !== undefinedType && typeof window.navigator !== undefinedType && /Trident\/|MSIE /.test(window.navigator.userAgent);
    var logMethods = [
      "trace",
      "debug",
      "info",
      "warn",
      "error"
    ];
    function bindMethod(obj, methodName) {
      var method = obj[methodName];
      if (typeof method.bind === "function") {
        return method.bind(obj);
      } else {
        try {
          return Function.prototype.bind.call(method, obj);
        } catch (e) {
          return function() {
            return Function.prototype.apply.apply(method, [obj, arguments]);
          };
        }
      }
    }
    function traceForIE() {
      if (console.log) {
        if (console.log.apply) {
          console.log.apply(console, arguments);
        } else {
          Function.prototype.apply.apply(console.log, [console, arguments]);
        }
      }
      if (console.trace)
        console.trace();
    }
    function realMethod(methodName) {
      if (methodName === "debug") {
        methodName = "log";
      }
      if (typeof console === undefinedType) {
        return false;
      } else if (methodName === "trace" && isIE) {
        return traceForIE;
      } else if (console[methodName] !== void 0) {
        return bindMethod(console, methodName);
      } else if (console.log !== void 0) {
        return bindMethod(console, "log");
      } else {
        return noop;
      }
    }
    function replaceLoggingMethods(level, loggerName) {
      for (var i2 = 0; i2 < logMethods.length; i2++) {
        var methodName = logMethods[i2];
        this[methodName] = i2 < level ? noop : this.methodFactory(methodName, level, loggerName);
      }
      this.log = this.debug;
    }
    function enableLoggingWhenConsoleArrives(methodName, level, loggerName) {
      return function() {
        if (typeof console !== undefinedType) {
          replaceLoggingMethods.call(this, level, loggerName);
          this[methodName].apply(this, arguments);
        }
      };
    }
    function defaultMethodFactory(methodName, level, loggerName) {
      return realMethod(methodName) || enableLoggingWhenConsoleArrives.apply(this, arguments);
    }
    function Logger(name, defaultLevel, factory) {
      var self2 = this;
      var currentLevel;
      defaultLevel = defaultLevel == null ? "WARN" : defaultLevel;
      var storageKey = "loglevel";
      if (typeof name === "string") {
        storageKey += ":" + name;
      } else if (typeof name === "symbol") {
        storageKey = void 0;
      }
      function persistLevelIfPossible(levelNum) {
        var levelName = (logMethods[levelNum] || "silent").toUpperCase();
        if (typeof window === undefinedType || !storageKey)
          return;
        try {
          window.localStorage[storageKey] = levelName;
          return;
        } catch (ignore) {
        }
        try {
          window.document.cookie = encodeURIComponent(storageKey) + "=" + levelName + ";";
        } catch (ignore) {
        }
      }
      function getPersistedLevel() {
        var storedLevel;
        if (typeof window === undefinedType || !storageKey)
          return;
        try {
          storedLevel = window.localStorage[storageKey];
        } catch (ignore) {
        }
        if (typeof storedLevel === undefinedType) {
          try {
            var cookie = window.document.cookie;
            var location2 = cookie.indexOf(encodeURIComponent(storageKey) + "=");
            if (location2 !== -1) {
              storedLevel = /^([^;]+)/.exec(cookie.slice(location2))[1];
            }
          } catch (ignore) {
          }
        }
        if (self2.levels[storedLevel] === void 0) {
          storedLevel = void 0;
        }
        return storedLevel;
      }
      function clearPersistedLevel() {
        if (typeof window === undefinedType || !storageKey)
          return;
        try {
          window.localStorage.removeItem(storageKey);
          return;
        } catch (ignore) {
        }
        try {
          window.document.cookie = encodeURIComponent(storageKey) + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC";
        } catch (ignore) {
        }
      }
      self2.name = name;
      self2.levels = {
        "TRACE": 0,
        "DEBUG": 1,
        "INFO": 2,
        "WARN": 3,
        "ERROR": 4,
        "SILENT": 5
      };
      self2.methodFactory = factory || defaultMethodFactory;
      self2.getLevel = function() {
        return currentLevel;
      };
      self2.setLevel = function(level, persist) {
        if (typeof level === "string" && self2.levels[level.toUpperCase()] !== void 0) {
          level = self2.levels[level.toUpperCase()];
        }
        if (typeof level === "number" && level >= 0 && level <= self2.levels.SILENT) {
          currentLevel = level;
          if (persist !== false) {
            persistLevelIfPossible(level);
          }
          replaceLoggingMethods.call(self2, level, name);
          if (typeof console === undefinedType && level < self2.levels.SILENT) {
            return "No console available for logging";
          }
        } else {
          throw "log.setLevel() called with invalid level: " + level;
        }
      };
      self2.setDefaultLevel = function(level) {
        defaultLevel = level;
        if (!getPersistedLevel()) {
          self2.setLevel(level, false);
        }
      };
      self2.resetLevel = function() {
        self2.setLevel(defaultLevel, false);
        clearPersistedLevel();
      };
      self2.enableAll = function(persist) {
        self2.setLevel(self2.levels.TRACE, persist);
      };
      self2.disableAll = function(persist) {
        self2.setLevel(self2.levels.SILENT, persist);
      };
      var initialLevel = getPersistedLevel();
      if (initialLevel == null) {
        initialLevel = defaultLevel;
      }
      self2.setLevel(initialLevel, false);
    }
    var defaultLogger = new Logger();
    var _loggersByName = {};
    defaultLogger.getLogger = function getLogger(name) {
      if (typeof name !== "symbol" && typeof name !== "string" || name === "") {
        throw new TypeError("You must supply a name when creating a logger.");
      }
      var logger2 = _loggersByName[name];
      if (!logger2) {
        logger2 = _loggersByName[name] = new Logger(name, defaultLogger.getLevel(), defaultLogger.methodFactory);
      }
      return logger2;
    };
    var _log = typeof window !== undefinedType ? window.log : void 0;
    defaultLogger.noConflict = function() {
      if (typeof window !== undefinedType && window.log === defaultLogger) {
        window.log = _log;
      }
      return defaultLogger;
    };
    defaultLogger.getLoggers = function getLoggers() {
      return _loggersByName;
    };
    defaultLogger["default"] = defaultLogger;
    return defaultLogger;
  });
})(loglevel);
var _interopRequireDefault$2 = interopRequireDefault.exports;
Object.defineProperty(logger$1, "__esModule", {
  value: true
});
logger$1.logger = void 0;
var _loglevel = _interopRequireDefault$2(loglevel.exports);
const DEFAULT_NAMESPACE = "matrix";
_loglevel.default.methodFactory = function(methodName, logLevel, loggerName) {
  return function(...args) {
    if (this.prefix) {
      args.unshift(this.prefix);
    }
    const supportedByConsole = methodName === "error" || methodName === "warn" || methodName === "trace" || methodName === "info";
    if (supportedByConsole) {
      return console[methodName](...args);
    } else {
      return console.log(...args);
    }
  };
};
const logger = _loglevel.default.getLogger(DEFAULT_NAMESPACE);
logger$1.logger = logger;
logger.setLevel(_loglevel.default.levels.DEBUG, false);
function extendLogger(logger2) {
  logger2.withPrefix = function(prefix) {
    const existingPrefix = this.prefix || "";
    return getPrefixedLogger(existingPrefix + prefix);
  };
}
extendLogger(logger);
function getPrefixedLogger(prefix) {
  const prefixLogger = _loglevel.default.getLogger(`${DEFAULT_NAMESPACE}-${prefix}`);
  if (prefixLogger.prefix !== prefix) {
    extendLogger(prefixLogger);
    prefixLogger.prefix = prefix;
    prefixLogger.setLevel(_loglevel.default.levels.DEBUG, false);
  }
  return prefixLogger;
}
var _interopRequireDefault$1 = interopRequireDefault.exports;
Object.defineProperty(olmlib, "__esModule", {
  value: true
});
olmlib.OLM_ALGORITHM = olmlib.MEGOLM_BACKUP_ALGORITHM = olmlib.MEGOLM_ALGORITHM = void 0;
olmlib.decodeBase64 = decodeBase64;
olmlib.encodeBase64 = encodeBase64;
var encodeUnpaddedBase64_1 = olmlib.encodeUnpaddedBase64 = encodeUnpaddedBase64;
olmlib.encryptMessageForDevice = encryptMessageForDevice;
olmlib.ensureOlmSessionsForDevices = ensureOlmSessionsForDevices;
olmlib.getExistingOlmSessions = getExistingOlmSessions;
olmlib.pkSign = pkSign;
olmlib.pkVerify = pkVerify;
olmlib.verifySignature = verifySignature;
var _anotherJson = _interopRequireDefault$1(anotherJson);
var _logger = logger$1;
var Algorithm;
(function(Algorithm2) {
  Algorithm2["Olm"] = "m.olm.v1.curve25519-aes-sha2";
  Algorithm2["Megolm"] = "m.megolm.v1.aes-sha2";
  Algorithm2["MegolmBackup"] = "m.megolm_backup.v1.curve25519-aes-sha2";
})(Algorithm || (Algorithm = {}));
const OLM_ALGORITHM = Algorithm.Olm;
olmlib.OLM_ALGORITHM = OLM_ALGORITHM;
const MEGOLM_ALGORITHM = Algorithm.Megolm;
olmlib.MEGOLM_ALGORITHM = MEGOLM_ALGORITHM;
const MEGOLM_BACKUP_ALGORITHM = Algorithm.MegolmBackup;
olmlib.MEGOLM_BACKUP_ALGORITHM = MEGOLM_BACKUP_ALGORITHM;
async function encryptMessageForDevice(resultsObject, ourUserId, ourDeviceId, olmDevice, recipientUserId, recipientDevice, payloadFields) {
  const deviceKey = recipientDevice.getIdentityKey();
  const sessionId = await olmDevice.getSessionIdForDevice(deviceKey);
  if (sessionId === null) {
    return;
  }
  _logger.logger.log("Using sessionid " + sessionId + " for device " + recipientUserId + ":" + recipientDevice.deviceId);
  const payload = {
    sender: ourUserId,
    sender_device: ourDeviceId,
    keys: {
      "ed25519": olmDevice.deviceEd25519Key
    },
    recipient: recipientUserId,
    recipient_keys: {
      "ed25519": recipientDevice.getFingerprint()
    }
  };
  Object.assign(payload, payloadFields);
  resultsObject[deviceKey] = await olmDevice.encryptMessage(deviceKey, sessionId, JSON.stringify(payload));
}
async function getExistingOlmSessions(olmDevice, baseApis, devicesByUser) {
  const devicesWithoutSession = {};
  const sessions = {};
  const promises = [];
  for (const [userId, devices] of Object.entries(devicesByUser)) {
    for (const deviceInfo of devices) {
      const deviceId = deviceInfo.deviceId;
      const key = deviceInfo.getIdentityKey();
      promises.push((async () => {
        const sessionId = await olmDevice.getSessionIdForDevice(key, true);
        if (sessionId === null) {
          devicesWithoutSession[userId] = devicesWithoutSession[userId] || [];
          devicesWithoutSession[userId].push(deviceInfo);
        } else {
          sessions[userId] = sessions[userId] || {};
          sessions[userId][deviceId] = {
            device: deviceInfo,
            sessionId
          };
        }
      })());
    }
  }
  await Promise.all(promises);
  return [devicesWithoutSession, sessions];
}
async function ensureOlmSessionsForDevices(olmDevice, baseApis, devicesByUser, force = false, otkTimeout, failedServers, log = _logger.logger) {
  if (typeof force === "number") {
    log = failedServers;
    failedServers = otkTimeout;
    otkTimeout = force;
    force = false;
  }
  const devicesWithoutSession = [];
  const result = {};
  const resolveSession = {};
  for (const [, devices] of Object.entries(devicesByUser)) {
    for (const deviceInfo of devices) {
      const key = deviceInfo.getIdentityKey();
      if (key === olmDevice.deviceCurve25519Key) {
        continue;
      }
      if (!olmDevice.sessionsInProgress[key]) {
        olmDevice.sessionsInProgress[key] = new Promise((resolve) => {
          resolveSession[key] = (v) => {
            delete olmDevice.sessionsInProgress[key];
            resolve(v);
          };
        });
      }
    }
  }
  for (const [userId, devices] of Object.entries(devicesByUser)) {
    result[userId] = {};
    for (const deviceInfo of devices) {
      const deviceId = deviceInfo.deviceId;
      const key = deviceInfo.getIdentityKey();
      if (key === olmDevice.deviceCurve25519Key) {
        log.info("Attempted to start session with ourself! Ignoring");
        result[userId][deviceId] = {
          device: deviceInfo,
          sessionId: null
        };
        continue;
      }
      const forWhom = `for ${key} (${userId}:${deviceId})`;
      const sessionId = await olmDevice.getSessionIdForDevice(key, !!resolveSession[key], log);
      if (sessionId !== null && resolveSession[key]) {
        resolveSession[key]();
      }
      if (sessionId === null || force) {
        if (force) {
          log.info(`Forcing new Olm session ${forWhom}`);
        } else {
          log.info(`Making new Olm session ${forWhom}`);
        }
        devicesWithoutSession.push([userId, deviceId]);
      }
      result[userId][deviceId] = {
        device: deviceInfo,
        sessionId
      };
    }
  }
  if (devicesWithoutSession.length === 0) {
    return result;
  }
  const oneTimeKeyAlgorithm = "signed_curve25519";
  let res;
  let taskDetail = `one-time keys for ${devicesWithoutSession.length} devices`;
  try {
    log.debug(`Claiming ${taskDetail}`);
    res = await baseApis.claimOneTimeKeys(devicesWithoutSession, oneTimeKeyAlgorithm, otkTimeout);
    log.debug(`Claimed ${taskDetail}`);
  } catch (e) {
    for (const resolver of Object.values(resolveSession)) {
      resolver();
    }
    log.log(`Failed to claim ${taskDetail}`, e, devicesWithoutSession);
    throw e;
  }
  if (failedServers && "failures" in res) {
    failedServers.push(...Object.keys(res.failures));
  }
  const otkResult = res.one_time_keys || {};
  const promises = [];
  for (const [userId, devices] of Object.entries(devicesByUser)) {
    const userRes = otkResult[userId] || {};
    for (let j = 0; j < devices.length; j++) {
      const deviceInfo = devices[j];
      const deviceId = deviceInfo.deviceId;
      const key = deviceInfo.getIdentityKey();
      if (key === olmDevice.deviceCurve25519Key) {
        continue;
      }
      if (result[userId][deviceId].sessionId && !force) {
        continue;
      }
      const deviceRes = userRes[deviceId] || {};
      let oneTimeKey = null;
      for (const keyId in deviceRes) {
        if (keyId.indexOf(oneTimeKeyAlgorithm + ":") === 0) {
          oneTimeKey = deviceRes[keyId];
        }
      }
      if (!oneTimeKey) {
        log.warn(`No one-time keys (alg=${oneTimeKeyAlgorithm}) for device ${userId}:${deviceId}`);
        if (resolveSession[key]) {
          resolveSession[key]();
        }
        continue;
      }
      promises.push(_verifyKeyAndStartSession(olmDevice, oneTimeKey, userId, deviceInfo).then((sid) => {
        if (resolveSession[key]) {
          resolveSession[key](sid);
        }
        result[userId][deviceId].sessionId = sid;
      }, (e) => {
        if (resolveSession[key]) {
          resolveSession[key]();
        }
        throw e;
      }));
    }
  }
  taskDetail = `Olm sessions for ${promises.length} devices`;
  log.debug(`Starting ${taskDetail}`);
  await Promise.all(promises);
  log.debug(`Started ${taskDetail}`);
  return result;
}
async function _verifyKeyAndStartSession(olmDevice, oneTimeKey, userId, deviceInfo) {
  const deviceId = deviceInfo.deviceId;
  try {
    await verifySignature(olmDevice, oneTimeKey, userId, deviceId, deviceInfo.getFingerprint());
  } catch (e) {
    _logger.logger.error("Unable to verify signature on one-time key for device " + userId + ":" + deviceId + ":", e);
    return null;
  }
  let sid;
  try {
    sid = await olmDevice.createOutboundSession(deviceInfo.getIdentityKey(), oneTimeKey.key);
  } catch (e) {
    _logger.logger.error("Error starting olm session with device " + userId + ":" + deviceId + ": " + e);
    return null;
  }
  _logger.logger.log("Started new olm sessionid " + sid + " for device " + userId + ":" + deviceId);
  return sid;
}
async function verifySignature(olmDevice, obj, signingUserId, signingDeviceId, signingKey) {
  const signKeyId = "ed25519:" + signingDeviceId;
  const signatures = obj.signatures || {};
  const userSigs = signatures[signingUserId] || {};
  const signature = userSigs[signKeyId];
  if (!signature) {
    throw Error("No signature");
  }
  const mangledObj = Object.assign({}, obj);
  if ("unsigned" in mangledObj) {
    delete mangledObj.unsigned;
  }
  delete mangledObj.signatures;
  const json = _anotherJson.default.stringify(mangledObj);
  olmDevice.verifySignature(signingKey, json, signature);
}
function pkSign(obj, key, userId, pubKey) {
  let createdKey = false;
  if (key instanceof Uint8Array) {
    const keyObj = new commonjsGlobal.Olm.PkSigning();
    pubKey = keyObj.init_with_seed(key);
    key = keyObj;
    createdKey = true;
  }
  const sigs = obj.signatures || {};
  delete obj.signatures;
  const unsigned = obj.unsigned;
  if (obj.unsigned)
    delete obj.unsigned;
  try {
    const mysigs = sigs[userId] || {};
    sigs[userId] = mysigs;
    return mysigs["ed25519:" + pubKey] = key.sign(_anotherJson.default.stringify(obj));
  } finally {
    obj.signatures = sigs;
    if (unsigned)
      obj.unsigned = unsigned;
    if (createdKey) {
      key.free();
    }
  }
}
function pkVerify(obj, pubKey, userId) {
  const keyId = "ed25519:" + pubKey;
  if (!(obj.signatures && obj.signatures[userId] && obj.signatures[userId][keyId])) {
    throw new Error("No signature");
  }
  const signature = obj.signatures[userId][keyId];
  const util = new commonjsGlobal.Olm.Utility();
  const sigs = obj.signatures;
  delete obj.signatures;
  const unsigned = obj.unsigned;
  if (obj.unsigned)
    delete obj.unsigned;
  try {
    util.ed25519_verify(pubKey, _anotherJson.default.stringify(obj), signature);
  } finally {
    obj.signatures = sigs;
    if (unsigned)
      obj.unsigned = unsigned;
    util.free();
  }
}
function encodeBase64(uint8Array) {
  return Buffer.from(uint8Array).toString("base64");
}
function encodeUnpaddedBase64(uint8Array) {
  return encodeBase64(uint8Array).replace(/=+$/g, "");
}
function decodeBase64(base64) {
  return Buffer.from(base64, "base64");
}
var aes = {};
var utils = {};
const I = "l";
const m = "rn";
var require$$0 = {
  "0": "O",
  "1": "l",
  "\u05AD": "\u0596",
  "\u05AE": "\u0598",
  "\u05A8": "\u0599",
  "\u05A4": "\u059A",
  "\u1AB4": "\u06DB",
  "\u20DB": "\u06DB",
  "\u0619": "\u0313",
  "\u08F3": "\u0313",
  "\u0343": "\u0313",
  "\u0315": "\u0313",
  "\u064F": "\u0313",
  "\u065D": "\u0314",
  "\u059C": "\u0301",
  "\u059D": "\u0301",
  "\u0618": "\u0301",
  "\u0747": "\u0301",
  "\u0341": "\u0301",
  "\u0954": "\u0301",
  "\u064E": "\u0301",
  "\u0340": "\u0300",
  "\u0953": "\u0300",
  "\u030C": "\u0306",
  "\uA67C": "\u0306",
  "\u0658": "\u0306",
  "\u065A": "\u0306",
  "\u036E": "\u0306",
  "\u06E8": "\u0306\u0307",
  "\u0310": "\u0306\u0307",
  "\u0901": "\u0306\u0307",
  "\u0981": "\u0306\u0307",
  "\u0A81": "\u0306\u0307",
  "\u0B01": "\u0306\u0307",
  "\u0C00": "\u0306\u0307",
  "\u0C81": "\u0306\u0307",
  "\u0D01": "\u0306\u0307",
  "\u{114BF}": "\u0306\u0307",
  "\u1CD0": "\u0302",
  "\u0311": "\u0302",
  "\u065B": "\u0302",
  "\u07EE": "\u0302",
  "\uA6F0": "\u0302",
  "\u05AF": "\u030A",
  "\u06DF": "\u030A",
  "\u17D3": "\u030A",
  "\u309A": "\u030A",
  "\u0652": "\u030A",
  "\u0B82": "\u030A",
  "\u1036": "\u030A",
  "\u17C6": "\u030A",
  "\u{11300}": "\u030A",
  "\u0E4D": "\u030A",
  "\u0ECD": "\u030A",
  "\u0366": "\u030A",
  "\u2DEA": "\u030A",
  "\u08EB": "\u0308",
  "\u07F3": "\u0308",
  "\u064B": "\u030B",
  "\u08F0": "\u030B",
  "\u0342": "\u0303",
  "\u0653": "\u0303",
  "\u05C4": "\u0307",
  "\u06EC": "\u0307",
  "\u0740": "\u0307",
  "\u08EA": "\u0307",
  "\u0741": "\u0307",
  "\u0358": "\u0307",
  "\u05B9": "\u0307",
  "\u05BA": "\u0307",
  "\u05C2": "\u0307",
  "\u05C1": "\u0307",
  "\u07ED": "\u0307",
  "\u0902": "\u0307",
  "\u0A02": "\u0307",
  "\u0A82": "\u0307",
  "\u0BCD": "\u0307",
  "\u0337": "\u0338",
  "\u1AB7": "\u0328",
  "\u0322": "\u0328",
  "\u0345": "\u0328",
  "\u1CD2": "\u0304",
  "\u0305": "\u0304",
  "\u0659": "\u0304",
  "\u07EB": "\u0304",
  "\uA6F1": "\u0304",
  "\u1CDA": "\u030E",
  "\u0657": "\u0312",
  "\u0357": "\u0350",
  "\u08FF": "\u0350",
  "\u08F8": "\u0350",
  "\u0900": "\u0352",
  "\u1CED": "\u0316",
  "\u1CDC": "\u0329",
  "\u0656": "\u0329",
  "\u1CD5": "\u032B",
  "\u0347": "\u0333",
  "\u08F9": "\u0354",
  "\u08FA": "\u0355",
  "\u309B": "\uFF9E",
  "\u309C": "\uFF9F",
  "\u0336": "\u0335",
  "\u302C": "\u0309",
  "\u05C5": "\u0323",
  "\u08ED": "\u0323",
  "\u1CDD": "\u0323",
  "\u05B4": "\u0323",
  "\u065C": "\u0323",
  "\u093C": "\u0323",
  "\u09BC": "\u0323",
  "\u0A3C": "\u0323",
  "\u0ABC": "\u0323",
  "\u0B3C": "\u0323",
  "\u{111CA}": "\u0323",
  "\u{114C3}": "\u0323",
  "\u{10A3A}": "\u0323",
  "\u08EE": "\u0324",
  "\u1CDE": "\u0324",
  "\u0F37": "\u0325",
  "\u302D": "\u0325",
  "\u0327": "\u0326",
  "\u0321": "\u0326",
  "\u0339": "\u0326",
  "\u1CD9": "\u032D",
  "\u1CD8": "\u032E",
  "\u0952": "\u0331",
  "\u0320": "\u0331",
  "\u08F1": "\u064C",
  "\u08E8": "\u064C",
  "\u08E5": "\u064C",
  "\uFC5E": "\uFE72\u0651",
  "\u08F2": "\u064D",
  "\uFC5F": "\uFE74\u0651",
  "\uFCF2": "\uFE77\u0651",
  "\uFC60": "\uFE76\u0651",
  "\uFCF3": "\uFE79\u0651",
  "\uFC61": "\uFE78\u0651",
  "\u061A": "\u0650",
  "\u0317": "\u0650",
  "\uFCF4": "\uFE7B\u0651",
  "\uFC62": "\uFE7A\u0651",
  "\uFC63": "\uFE7C\u0670",
  "\u065F": "\u0655",
  "\u030D": "\u0670",
  "\u0742": "\u073C",
  "\u0A03": "\u0983",
  "\u0C03": "\u0983",
  "\u0C83": "\u0983",
  "\u0D03": "\u0983",
  "\u0D83": "\u0983",
  "\u1038": "\u0983",
  "\u{114C1}": "\u0983",
  "\u17CB": "\u0E48",
  "\u0EC8": "\u0E48",
  "\u0EC9": "\u0E49",
  "\u0ECA": "\u0E4A",
  "\u0ECB": "\u0E4B",
  "\uA66F": "\u20E9",
  "\u2028": " ",
  "\u2029": " ",
  "\u1680": " ",
  "\u2000": " ",
  "\u2001": " ",
  "\u2002": " ",
  "\u2003": " ",
  "\u2004": " ",
  "\u2005": " ",
  "\u2006": " ",
  "\u2008": " ",
  "\u2009": " ",
  "\u200A": " ",
  "\u205F": " ",
  "\xA0": " ",
  "\u2007": " ",
  "\u202F": " ",
  "\u07FA": "_",
  "\uFE4D": "_",
  "\uFE4E": "_",
  "\uFE4F": "_",
  "\u2010": "-",
  "\u2011": "-",
  "\u2012": "-",
  "\u2013": "-",
  "\uFE58": "-",
  "\u06D4": "-",
  "\u2043": "-",
  "\u02D7": "-",
  "\u2212": "-",
  "\u2796": "-",
  "\u2CBA": "-",
  "\u2A29": "-\u0313",
  "\u2E1A": "-\u0308",
  "\uFB29": "-\u0307",
  "\u2238": "-\u0307",
  "\u2A2A": "-\u0323",
  "\uA4FE": "-.",
  "\uFF5E": "\u301C",
  "\u060D": ",",
  "\u066B": ",",
  "\u201A": ",",
  "\xB8": ",",
  "\uA4F9": ",",
  "\u2E32": "\u060C",
  "\u066C": "\u060C",
  "\u037E": ";",
  "\u2E35": "\u061B",
  "\u0903": ":",
  "\u0A83": ":",
  "\uFF1A": ":",
  "\u0589": ":",
  "\u0703": ":",
  "\u0704": ":",
  "\u16EC": ":",
  "\uFE30": ":",
  "\u1803": ":",
  "\u1809": ":",
  "\u205A": ":",
  "\u05C3": ":",
  "\u02F8": ":",
  "\uA789": ":",
  "\u2236": ":",
  "\u02D0": ":",
  "\uA4FD": ":",
  "\u2A74": "::=",
  "\u29F4": ":\u2192",
  "\uFF01": "!",
  "\u01C3": "!",
  "\u2D51": "!",
  "\u203C": "!!",
  "\u2049": "!?",
  "\u0294": "?",
  "\u0241": "?",
  "\u097D": "?",
  "\u13AE": "?",
  "\uA6EB": "?",
  "\u2048": "?!",
  "\u2047": "??",
  "\u2E2E": "\u061F",
  "\u{1D16D}": ".",
  "\u2024": ".",
  "\u0701": ".",
  "\u0702": ".",
  "\uA60E": ".",
  "\u{10A50}": ".",
  "\u0660": ".",
  "\u06F0": ".",
  "\uA4F8": ".",
  "\uA4FB": ".,",
  "\u2025": "..",
  "\uA4FA": "..",
  "\u2026": "...",
  "\uA6F4": "\uA6F3\uA6F3",
  "\u30FB": "\xB7",
  "\uFF65": "\xB7",
  "\u16EB": "\xB7",
  "\u0387": "\xB7",
  "\u2E31": "\xB7",
  "\u{10101}": "\xB7",
  "\u2022": "\xB7",
  "\u2027": "\xB7",
  "\u2219": "\xB7",
  "\u22C5": "\xB7",
  "\uA78F": "\xB7",
  "\u1427": "\xB7",
  "\u22EF": "\xB7\xB7\xB7",
  "\u2D48": "\xB7\xB7\xB7",
  "\u1444": "\xB7<",
  "\u22D7": "\xB7>",
  "\u1437": "\xB7>",
  "\u1440": "\xB7>",
  "\u152F": "\xB74",
  "\u147E": "\xB7b",
  "\u1480": "\xB7b\u0307",
  "\u147A": "\xB7d",
  "\u1498": "\xB7J",
  "\u14B6": "\xB7L",
  "\u1476": "\xB7P",
  "\u1457": "\xB7U",
  "\u143A": "\xB7V",
  "\u143C": "\xB7\u0245",
  "\u14AE": "\xB7\u0393",
  "\u140E": "\xB7\u0394",
  "\u1459": "\xB7\u0548",
  "\u140C": "\xB7\u1401",
  "\u1410": "\xB7\u1404",
  "\u1412": "\xB7\u1405",
  "\u1414": "\xB7\u1406",
  "\u1417": "\xB7\u140A",
  "\u1419": "\xB7\u140B",
  "\u143E": "\xB7\u1432",
  "\u1442": "\xB7\u1434",
  "\u1446": "\xB7\u1439",
  "\u145B": "\xB7\u144F",
  "\u1454": "\xB7\u1450",
  "\u145D": "\xB7\u1450",
  "\u145F": "\xB7\u1451",
  "\u1461": "\xB7\u1455",
  "\u1463": "\xB7\u1456",
  "\u1474": "\xB7\u146B",
  "\u1478": "\xB7\u146E",
  "\u147C": "\xB7\u1470",
  "\u1492": "\xB7\u1489",
  "\u1494": "\xB7\u148B",
  "\u1496": "\xB7\u148C",
  "\u149A": "\xB7\u148E",
  "\u149C": "\xB7\u1490",
  "\u149E": "\xB7\u1491",
  "\u14AC": "\xB7\u14A3",
  "\u14B0": "\xB7\u14A6",
  "\u14B2": "\xB7\u14A7",
  "\u14B4": "\xB7\u14A8",
  "\u14B8": "\xB7\u14AB",
  "\u14C9": "\xB7\u14C0",
  "\u18C6": "\xB7\u14C2",
  "\u18C8": "\xB7\u14C3",
  "\u18CA": "\xB7\u14C4",
  "\u18CC": "\xB7\u14C5",
  "\u14CB": "\xB7\u14C7",
  "\u14CD": "\xB7\u14C8",
  "\u14DC": "\xB7\u14D3",
  "\u14DE": "\xB7\u14D5",
  "\u14E0": "\xB7\u14D6",
  "\u14E2": "\xB7\u14D7",
  "\u14E4": "\xB7\u14D8",
  "\u14E6": "\xB7\u14DA",
  "\u14E8": "\xB7\u14DB",
  "\u14F6": "\xB7\u14ED",
  "\u14F8": "\xB7\u14EF",
  "\u14FA": "\xB7\u14F0",
  "\u14FC": "\xB7\u14F1",
  "\u14FE": "\xB7\u14F2",
  "\u1500": "\xB7\u14F4",
  "\u1502": "\xB7\u14F5",
  "\u1517": "\xB7\u1510",
  "\u1519": "\xB7\u1511",
  "\u151B": "\xB7\u1512",
  "\u151D": "\xB7\u1513",
  "\u151F": "\xB7\u1514",
  "\u1521": "\xB7\u1515",
  "\u1523": "\xB7\u1516",
  "\u1531": "\xB7\u1528",
  "\u1533": "\xB7\u1529",
  "\u1535": "\xB7\u152A",
  "\u1537": "\xB7\u152B",
  "\u1539": "\xB7\u152D",
  "\u153B": "\xB7\u152E",
  "\u18CE": "\xB7\u1543",
  "\u18CF": "\xB7\u1546",
  "\u18D0": "\xB7\u1547",
  "\u18D1": "\xB7\u1548",
  "\u18D2": "\xB7\u1549",
  "\u18D3": "\xB7\u154B",
  "\u154E": "\xB7\u154C",
  "\u155B": "\xB7\u155A",
  "\u1568": "\xB7\u1567",
  "\u18B3": "\xB7\u18B1",
  "\u18B6": "\xB7\u18B4",
  "\u18B9": "\xB7\u18B8",
  "\u18C2": "\xB7\u18C0",
  "\uA830": "\u0964",
  "\u0965": "\u0964\u0964",
  "\u1C3C": "\u1C3B\u1C3B",
  "\u104B": "\u104A\u104A",
  "\u1AA9": "\u1AA8\u1AA8",
  "\u1AAB": "\u1AAA\u1AA8",
  "\u1B5F": "\u1B5E\u1B5E",
  "\u{10A57}": "\u{10A56}\u{10A56}",
  "\u{1144C}": "\u{1144B}\u{1144B}",
  "\u{11642}": "\u{11641}\u{11641}",
  "\u{11C42}": "\u{11C41}\u{11C41}",
  "\u1C7F": "\u1C7E\u1C7E",
  "\u055D": "'",
  "\uFF07": "'",
  "\u2018": "'",
  "\u2019": "'",
  "\u201B": "'",
  "\u2032": "'",
  "\u2035": "'",
  "\u055A": "'",
  "\u05F3": "'",
  "`": "'",
  "\u1FEF": "'",
  "\uFF40": "'",
  "\xB4": "'",
  "\u0384": "'",
  "\u1FFD": "'",
  "\u1FBD": "'",
  "\u1FBF": "'",
  "\u1FFE": "'",
  "\u02B9": "'",
  "\u0374": "'",
  "\u02C8": "'",
  "\u02CA": "'",
  "\u02CB": "'",
  "\u02F4": "'",
  "\u02BB": "'",
  "\u02BD": "'",
  "\u02BC": "'",
  "\u02BE": "'",
  "\uA78C": "'",
  "\u05D9": "'",
  "\u07F4": "'",
  "\u07F5": "'",
  "\u144A": "'",
  "\u16CC": "'",
  "\u{16F51}": "'",
  "\u{16F52}": "'",
  "\u1CD3": "''",
  '"': "''",
  "\uFF02": "''",
  "\u201C": "''",
  "\u201D": "''",
  "\u201F": "''",
  "\u2033": "''",
  "\u2036": "''",
  "\u3003": "''",
  "\u05F4": "''",
  "\u02DD": "''",
  "\u02BA": "''",
  "\u02F6": "''",
  "\u02EE": "''",
  "\u05F2": "''",
  "\u2034": "'''",
  "\u2037": "'''",
  "\u2057": "''''",
  "\u0181": "'B",
  "\u018A": "'D",
  "\u0149": "'n",
  "\u01A4": "'P",
  "\u01AC": "'T",
  "\u01B3": "'Y",
  "\uFF3B": "(",
  "\u2768": "(",
  "\u2772": "(",
  "\u3014": "(",
  "\uFD3E": "(",
  "\u2E28": "((",
  "\u3220": "(\u30FC)",
  "\u2475": "(2)",
  "\u2487": "(2O)",
  "\u2476": "(3)",
  "\u2477": "(4)",
  "\u2478": "(5)",
  "\u2479": "(6)",
  "\u247A": "(7)",
  "\u247B": "(8)",
  "\u247C": "(9)",
  "\u249C": "(a)",
  "\u{1F110}": "(A)",
  "\u249D": "(b)",
  "\u{1F111}": "(B)",
  "\u249E": "(c)",
  "\u{1F112}": "(C)",
  "\u249F": "(d)",
  "\u{1F113}": "(D)",
  "\u24A0": "(e)",
  "\u{1F114}": "(E)",
  "\u24A1": "(f)",
  "\u{1F115}": "(F)",
  "\u24A2": "(g)",
  "\u{1F116}": "(G)",
  "\u24A3": "(h)",
  "\u{1F117}": "(H)",
  "\u24A4": "(i)",
  "\u24A5": "(j)",
  "\u{1F119}": "(J)",
  "\u24A6": "(k)",
  "\u{1F11A}": "(K)",
  "\u2474": "(l)",
  "\u{1F118}": "(l)",
  "\u24A7": "(l)",
  "\u{1F11B}": "(L)",
  "\u247F": "(l2)",
  "\u2480": "(l3)",
  "\u2481": "(l4)",
  "\u2482": "(l5)",
  "\u2483": "(l6)",
  "\u2484": "(l7)",
  "\u2485": "(l8)",
  "\u2486": "(l9)",
  "\u247E": "(ll)",
  "\u247D": "(lO)",
  "\u{1F11C}": "(M)",
  "\u24A9": "(n)",
  "\u{1F11D}": "(N)",
  "\u24AA": "(o)",
  "\u{1F11E}": "(O)",
  "\u24AB": "(p)",
  "\u{1F11F}": "(P)",
  "\u24AC": "(q)",
  "\u{1F120}": "(Q)",
  "\u24AD": "(r)",
  "\u{1F121}": "(R)",
  "\u24A8": "(rn)",
  "\u24AE": "(s)",
  "\u{1F122}": "(S)",
  "\u{1F12A}": "(S)",
  "\u24AF": "(t)",
  "\u{1F123}": "(T)",
  "\u24B0": "(u)",
  "\u{1F124}": "(U)",
  "\u24B1": "(v)",
  "\u{1F125}": "(V)",
  "\u24B2": "(w)",
  "\u{1F126}": "(W)",
  "\u24B3": "(x)",
  "\u{1F127}": "(X)",
  "\u24B4": "(y)",
  "\u{1F128}": "(Y)",
  "\u24B5": "(z)",
  "\u{1F129}": "(Z)",
  "\u3200": "(\u1100)",
  "\u320E": "(\uAC00)",
  "\u3201": "(\u1102)",
  "\u320F": "(\uB098)",
  "\u3202": "(\u1103)",
  "\u3210": "(\uB2E4)",
  "\u3203": "(\u1105)",
  "\u3211": "(\uB77C)",
  "\u3204": "(\u1106)",
  "\u3212": "(\uB9C8)",
  "\u3205": "(\u1107)",
  "\u3213": "(\uBC14)",
  "\u3206": "(\u1109)",
  "\u3214": "(\uC0AC)",
  "\u3207": "(\u110B)",
  "\u3215": "(\uC544)",
  "\u321D": "(\uC624\uC804)",
  "\u321E": "(\uC624\uD6C4)",
  "\u3208": "(\u110C)",
  "\u3216": "(\uC790)",
  "\u321C": "(\uC8FC)",
  "\u3209": "(\u110E)",
  "\u3217": "(\uCC28)",
  "\u320A": "(\u110F)",
  "\u3218": "(\uCE74)",
  "\u320B": "(\u1110)",
  "\u3219": "(\uD0C0)",
  "\u320C": "(\u1111)",
  "\u321A": "(\uD30C)",
  "\u320D": "(\u1112)",
  "\u321B": "(\uD558)",
  "\u3226": "(\u4E03)",
  "\u3222": "(\u4E09)",
  "\u{1F241}": "(\u4E09)",
  "\u3228": "(\u4E5D)",
  "\u3221": "(\u4E8C)",
  "\u{1F242}": "(\u4E8C)",
  "\u3224": "(\u4E94)",
  "\u3239": "(\u4EE3)",
  "\u323D": "(\u4F01)",
  "\u3241": "(\u4F11)",
  "\u3227": "(\u516B)",
  "\u3225": "(\u516D)",
  "\u3238": "(\u52B4)",
  "\u{1F247}": "(\u52DD)",
  "\u3229": "(\u5341)",
  "\u323F": "(\u5354)",
  "\u3234": "(\u540D)",
  "\u323A": "(\u547C)",
  "\u3223": "(\u56DB)",
  "\u322F": "(\u571F)",
  "\u323B": "(\u5B66)",
  "\u{1F243}": "(\u5B89)",
  "\u{1F245}": "(\u6253)",
  "\u{1F248}": "(\u6557)",
  "\u3230": "(\u65E5)",
  "\u322A": "(\u6708)",
  "\u3232": "(\u6709)",
  "\u322D": "(\u6728)",
  "\u{1F240}": "(\u672C)",
  "\u3231": "(\u682A)",
  "\u322C": "(\u6C34)",
  "\u322B": "(\u706B)",
  "\u{1F244}": "(\u70B9)",
  "\u3235": "(\u7279)",
  "\u{1F246}": "(\u76D7)",
  "\u323C": "(\u76E3)",
  "\u3233": "(\u793E)",
  "\u3237": "(\u795D)",
  "\u3240": "(\u796D)",
  "\u3242": "(\u81EA)",
  "\u3243": "(\u81F3)",
  "\u3236": "(\u8CA1)",
  "\u323E": "(\u8CC7)",
  "\u322E": "(\u91D1)",
  "\uFF3D": ")",
  "\u2769": ")",
  "\u2773": ")",
  "\u3015": ")",
  "\uFD3F": ")",
  "\u2E29": "))",
  "\u2774": "{",
  "\u{1D114}": "{",
  "\u2775": "}",
  "\u301A": "\u27E6",
  "\u301B": "\u27E7",
  "\u27E8": "\u276C",
  "\u2329": "\u276C",
  "\u3008": "\u276C",
  "\u31DB": "\u276C",
  "\u304F": "\u276C",
  "\u{21FE8}": "\u276C",
  "\u27E9": "\u276D",
  "\u232A": "\u276D",
  "\u3009": "\u276D",
  "\uFF3E": "\uFE3F",
  "\u2E3F": "\xB6",
  "\u204E": "*",
  "\u066D": "*",
  "\u2217": "*",
  "\u{1031F}": "*",
  "\u1735": "/",
  "\u2041": "/",
  "\u2215": "/",
  "\u2044": "/",
  "\u2571": "/",
  "\u27CB": "/",
  "\u29F8": "/",
  "\u{1D23A}": "/",
  "\u31D3": "/",
  "\u3033": "/",
  "\u2CC6": "/",
  "\u30CE": "/",
  "\u4E3F": "/",
  "\u2F03": "/",
  "\u29F6": "/\u0304",
  "\u2AFD": "//",
  "\u2AFB": "///",
  "\uFF3C": "\\",
  "\uFE68": "\\",
  "\u2216": "\\",
  "\u27CD": "\\",
  "\u29F5": "\\",
  "\u29F9": "\\",
  "\u{1D20F}": "\\",
  "\u{1D23B}": "\\",
  "\u31D4": "\\",
  "\u4E36": "\\",
  "\u2F02": "\\",
  "\u2CF9": "\\\\",
  "\u244A": "\\\\",
  "\u27C8": "\\\u1455",
  "\uA778": "&",
  "\u0AF0": "\u0970",
  "\u{110BB}": "\u0970",
  "\u{111C7}": "\u0970",
  "\u26AC": "\u0970",
  "\u{111DB}": "\uA8FC",
  "\u17D9": "\u0E4F",
  "\u17D5": "\u0E5A",
  "\u17DA": "\u0E5B",
  "\u0F0C": "\u0F0B",
  "\u0F0E": "\u0F0D\u0F0D",
  "\u02C4": "^",
  "\u02C6": "^",
  "\uA67E": "\u02C7",
  "\u02D8": "\u02C7",
  "\u203E": "\u02C9",
  "\uFE49": "\u02C9",
  "\uFE4A": "\u02C9",
  "\uFE4B": "\u02C9",
  "\uFE4C": "\u02C9",
  "\xAF": "\u02C9",
  "\uFFE3": "\u02C9",
  "\u2594": "\u02C9",
  "\u044A": "\u02C9b",
  "\uA651": "\u02C9bi",
  "\u0375": "\u02CF",
  "\u02FB": "\u02EA",
  "\uA716": "\u02EA",
  "\uA714": "\u02EB",
  "\u3002": "\u02F3",
  "\u2E30": "\xB0",
  "\u02DA": "\xB0",
  "\u2218": "\xB0",
  "\u25CB": "\xB0",
  "\u25E6": "\xB0",
  "\u235C": "\xB0\u0332",
  "\u2364": "\xB0\u0308",
  "\u2103": "\xB0C",
  "\u2109": "\xB0F",
  "\u0BF5": "\u0BF3",
  "\u0F1B": "\u0F1A\u0F1A",
  "\u0F1F": "\u0F1A\u0F1D",
  "\u0FCE": "\u0F1D\u0F1A",
  "\u0F1E": "\u0F1D\u0F1D",
  "\u24B8": "\xA9",
  "\u24C7": "\xAE",
  "\u24C5": "\u2117",
  "\u{1D21B}": "\u2144",
  "\u2BEC": "\u219E",
  "\u2BED": "\u219F",
  "\u2BEE": "\u21A0",
  "\u2BEF": "\u21A1",
  "\u21B5": "\u21B2",
  "\u2965": "\u21C3\u21C2",
  "\u296F": "\u21C3\u16DA",
  "\u{1D6DB}": "\u2202",
  "\u{1D715}": "\u2202",
  "\u{1D74F}": "\u2202",
  "\u{1D789}": "\u2202",
  "\u{1D7C3}": "\u2202",
  "\u{1E8CC}": "\u2202",
  "\u{1E8CD}": "\u2202\u0335",
  "\xF0": "\u2202\u0335",
  "\u2300": "\u2205",
  "\u{1D6C1}": "\u2207",
  "\u{1D6FB}": "\u2207",
  "\u{1D735}": "\u2207",
  "\u{1D76F}": "\u2207",
  "\u{1D7A9}": "\u2207",
  "\u{118A8}": "\u2207",
  "\u2362": "\u2207\u0308",
  "\u236B": "\u2207\u0334",
  "\u2588": "\u220E",
  "\u25A0": "\u220E",
  "\u2A3F": "\u2210",
  "\u16ED": "+",
  "\u2795": "+",
  "\u{1029B}": "+",
  "\u2A23": "+\u0302",
  "\u2A22": "+\u030A",
  "\u2A24": "+\u0303",
  "\u2214": "+\u0307",
  "\u2A25": "+\u0323",
  "\u2A26": "+\u0330",
  "\u2A27": "+\u2082",
  "\u2797": "\xF7",
  "\u2039": "<",
  "\u276E": "<",
  "\u02C2": "<",
  "\u{1D236}": "<",
  "\u1438": "<",
  "\u16B2": "<",
  "\u22D6": "<\xB7",
  "\u2CB4": "<\xB7",
  "\u1445": "<\xB7",
  "\u226A": "<<",
  "\u22D8": "<<<",
  "\u1400": "=",
  "\u2E40": "=",
  "\u30A0": "=",
  "\uA4FF": "=",
  "\u225A": "=\u0306",
  "\u2259": "=\u0302",
  "\u2257": "=\u030A",
  "\u2250": "=\u0307",
  "\u2251": "=\u0307\u0323",
  "\u2A6E": "=\u20F0",
  "\u2A75": "==",
  "\u2A76": "===",
  "\u225E": "=\u036B",
  "\u203A": ">",
  "\u276F": ">",
  "\u02C3": ">",
  "\u{1D237}": ">",
  "\u1433": ">",
  "\u{16F3F}": ">",
  "\u1441": ">\xB7",
  "\u2AA5": "><",
  "\u226B": ">>",
  "\u2A20": ">>",
  "\u22D9": ">>>",
  "\u2053": "~",
  "\u02DC": "~",
  "\u1FC0": "~",
  "\u223C": "~",
  "\u2368": "~\u0308",
  "\u2E1E": "~\u0307",
  "\u2A6A": "~\u0307",
  "\u2E1F": "~\u0323",
  "\u{1E8C8}": "\u2220",
  "\u22C0": "\u2227",
  "\u222F": "\u222E\u222E",
  "\u2230": "\u222E\u222E\u222E",
  "\u2E2B": "\u2234",
  "\u2E2A": "\u2235",
  "\u2E2C": "\u2237",
  "\u{111DE}": "\u2248",
  "\u264E": "\u224F",
  "\u{1F75E}": "\u224F",
  "\u2263": "\u2261",
  "\u2A03": "\u228D",
  "\u2A04": "\u228E",
  "\u{1D238}": "\u228F",
  "\u{1D239}": "\u2290",
  "\u2A05": "\u2293",
  "\u2A06": "\u2294",
  "\u2A02": "\u2297",
  "\u235F": "\u229B",
  "\u{1F771}": "\u22A0",
  "\u{1F755}": "\u22A1",
  "\u25C1": "\u22B2",
  "\u25B7": "\u22B3",
  "\u2363": "\u22C6\u0308",
  "\uFE34": "\u2307",
  "\u25E0": "\u2312",
  "\u2A3D": "\u2319",
  "\u2325": "\u2324",
  "\u29C7": "\u233B",
  "\u25CE": "\u233E",
  "\u29BE": "\u233E",
  "\u29C5": "\u2342",
  "\u29B0": "\u2349",
  "\u23C3": "\u234B",
  "\u23C2": "\u234E",
  "\u23C1": "\u2355",
  "\u23C6": "\u236D",
  "\u2638": "\u2388",
  "\uFE35": "\u23DC",
  "\uFE36": "\u23DD",
  "\uFE37": "\u23DE",
  "\uFE38": "\u23DF",
  "\uFE39": "\u23E0",
  "\uFE3A": "\u23E1",
  "\u25B1": "\u23E5",
  "\u23FC": "\u23FB",
  "\uFE31": "\u2502",
  "\uFF5C": "\u2502",
  "\u2503": "\u2502",
  "\u250F": "\u250C",
  "\u2523": "\u251C",
  "\u2590": "\u258C",
  "\u2597": "\u2596",
  "\u259D": "\u2598",
  "\u2610": "\u25A1",
  "\uFFED": "\u25AA",
  "\u25B8": "\u25B6",
  "\u25BA": "\u25B6",
  "\u2CE9": "\u2627",
  "\u{1F70A}": "\u2629",
  "\u{1F312}": "\u263D",
  "\u{1F319}": "\u263D",
  "\u23FE": "\u263E",
  "\u{1F318}": "\u263E",
  "\u29D9": "\u299A",
  "\u{1F73A}": "\u29DF",
  "\u2A3E": "\u2A1F",
  "\u{101A0}": "\u2CE8",
  "\u2669": "\u{1D158}\u{1D165}",
  "\u266A": "\u{1D158}\u{1D165}\u{1D16E}",
  "\u24EA": "\u{1F10D}",
  "\u21BA": "\u{1F10E}",
  "\u02D9": "\u0971",
  "\u0D4E": "\u0971",
  "\uFF0D": "\u30FC",
  "\u2014": "\u30FC",
  "\u2015": "\u30FC",
  "\u2500": "\u30FC",
  "\u2501": "\u30FC",
  "\u31D0": "\u30FC",
  "\uA7F7": "\u30FC",
  "\u1173": "\u30FC",
  "\u3161": "\u30FC",
  "\u4E00": "\u30FC",
  "\u2F00": "\u30FC",
  "\u1196": "\u30FC\u30FC",
  "\uD7B9": "\u30FC\u1161",
  "\uD7BA": "\u30FC\u1165",
  "\uD7BB": "\u30FC\u1165\u4E28",
  "\uD7BC": "\u30FC\u1169",
  "\u1195": "\u30FC\u116E",
  "\u1174": "\u30FC\u4E28",
  "\u3162": "\u30FC\u4E28",
  "\u1197": "\u30FC\u4E28\u116E",
  "\u{1F10F}": "$\u20E0",
  "\u20A4": "\xA3",
  "\u3012": "\u20B8",
  "\u3036": "\u20B8",
  "\u1B5C": "\u1B50",
  "\uA9C6": "\uA9D0",
  "\u{114D1}": "\u09E7",
  "\u0CE7": "\u0C67",
  "\u1065": "\u1041",
  "\u2460": "\u2780",
  "\u2469": "\u2789",
  "\u23E8": "\u2081\u2080",
  "\u{1D7D0}": "2",
  "\u{1D7DA}": "2",
  "\u{1D7E4}": "2",
  "\u{1D7EE}": "2",
  "\u{1D7F8}": "2",
  "\u{1FBF2}": "2",
  "\uA75A": "2",
  "\u01A7": "2",
  "\u03E8": "2",
  "\uA644": "2",
  "\u14BF": "2",
  "\uA6EF": "2",
  "\uA9CF": "\u0662",
  "\u06F2": "\u0662",
  "\u0AE8": "\u0968",
  "\u{114D2}": "\u09E8",
  "\u0CE8": "\u0C68",
  "\u2461": "\u2781",
  "\u01BB": "2\u0335",
  "\u{1F103}": "2,",
  "\u2489": "2.",
  "\u33F5": "22\u65E5",
  "\u336E": "22\u70B9",
  "\u33F6": "23\u65E5",
  "\u336F": "23\u70B9",
  "\u33F7": "24\u65E5",
  "\u3370": "24\u70B9",
  "\u33F8": "25\u65E5",
  "\u33F9": "26\u65E5",
  "\u33FA": "27\u65E5",
  "\u33FB": "28\u65E5",
  "\u33FC": "29\u65E5",
  "\u33F4": "2l\u65E5",
  "\u336D": "2l\u70B9",
  "\u249B": "2O.",
  "\u33F3": "2O\u65E5",
  "\u336C": "2O\u70B9",
  "\u0DE9": "\u0DE8\u0DCF",
  "\u0DEF": "\u0DE8\u0DD3",
  "\u33E1": "2\u65E5",
  "\u32C1": "2\u6708",
  "\u335A": "2\u70B9",
  "\u{1D206}": "3",
  "\u{1D7D1}": "3",
  "\u{1D7DB}": "3",
  "\u{1D7E5}": "3",
  "\u{1D7EF}": "3",
  "\u{1D7F9}": "3",
  "\u{1FBF3}": "3",
  "\uA7AB": "3",
  "\u021C": "3",
  "\u01B7": "3",
  "\uA76A": "3",
  "\u2CCC": "3",
  "\u0417": "3",
  "\u04E0": "3",
  "\u{16F3B}": "3",
  "\u{118CA}": "3",
  "\u06F3": "\u0663",
  "\u{1E8C9}": "\u0663",
  "\u0AE9": "\u0969",
  "\u2462": "\u2782",
  "\u0498": "3\u0326",
  "\u{1F104}": "3,",
  "\u248A": "3.",
  "\u33FE": "3l\u65E5",
  "\u33FD": "3O\u65E5",
  "\u33E2": "3\u65E5",
  "\u32C2": "3\u6708",
  "\u335B": "3\u70B9",
  "\u{1D7D2}": "4",
  "\u{1D7DC}": "4",
  "\u{1D7E6}": "4",
  "\u{1D7F0}": "4",
  "\u{1D7FA}": "4",
  "\u{1FBF4}": "4",
  "\u13CE": "4",
  "\u{118AF}": "4",
  "\u06F4": "\u0664",
  "\u0AEA": "\u096A",
  "\u2463": "\u2783",
  "\u{1F105}": "4,",
  "\u248B": "4.",
  "\u1530": "4\xB7",
  "\u33E3": "4\u65E5",
  "\u32C3": "4\u6708",
  "\u335C": "4\u70B9",
  "\u{1D7D3}": "5",
  "\u{1D7DD}": "5",
  "\u{1D7E7}": "5",
  "\u{1D7F1}": "5",
  "\u{1D7FB}": "5",
  "\u{1FBF5}": "5",
  "\u01BC": "5",
  "\u{118BB}": "5",
  "\u2464": "\u2784",
  "\u{1F106}": "5,",
  "\u248C": "5.",
  "\u33E4": "5\u65E5",
  "\u32C4": "5\u6708",
  "\u335D": "5\u70B9",
  "\u{1D7D4}": "6",
  "\u{1D7DE}": "6",
  "\u{1D7E8}": "6",
  "\u{1D7F2}": "6",
  "\u{1D7FC}": "6",
  "\u{1FBF6}": "6",
  "\u2CD2": "6",
  "\u0431": "6",
  "\u13EE": "6",
  "\u{118D5}": "6",
  "\u06F6": "\u0666",
  "\u{114D6}": "\u09EC",
  "\u2465": "\u2785",
  "\u{1F107}": "6,",
  "\u248D": "6.",
  "\u33E5": "6\u65E5",
  "\u32C5": "6\u6708",
  "\u335E": "6\u70B9",
  "\u{1D212}": "7",
  "\u{1D7D5}": "7",
  "\u{1D7DF}": "7",
  "\u{1D7E9}": "7",
  "\u{1D7F3}": "7",
  "\u{1D7FD}": "7",
  "\u{1FBF7}": "7",
  "\u{104D2}": "7",
  "\u{118C6}": "7",
  "\u2466": "\u2786",
  "\u{1F108}": "7,",
  "\u248E": "7.",
  "\u33E6": "7\u65E5",
  "\u32C6": "7\u6708",
  "\u335F": "7\u70B9",
  "\u0B03": "8",
  "\u09EA": "8",
  "\u0A6A": "8",
  "\u{1E8CB}": "8",
  "\u{1D7D6}": "8",
  "\u{1D7E0}": "8",
  "\u{1D7EA}": "8",
  "\u{1D7F4}": "8",
  "\u{1D7FE}": "8",
  "\u{1FBF8}": "8",
  "\u0223": "8",
  "\u0222": "8",
  "\u{1031A}": "8",
  "\u0AEE": "\u096E",
  "\u2467": "\u2787",
  "\u{1F109}": "8,",
  "\u248F": "8.",
  "\u33E7": "8\u65E5",
  "\u32C7": "8\u6708",
  "\u3360": "8\u70B9",
  "\u0A67": "9",
  "\u0B68": "9",
  "\u09ED": "9",
  "\u0D6D": "9",
  "\u{1D7D7}": "9",
  "\u{1D7E1}": "9",
  "\u{1D7EB}": "9",
  "\u{1D7F5}": "9",
  "\u{1D7FF}": "9",
  "\u{1FBF9}": "9",
  "\uA76E": "9",
  "\u2CCA": "9",
  "\u{118CC}": "9",
  "\u{118AC}": "9",
  "\u{118D6}": "9",
  "\u0967": "\u0669",
  "\u{118E4}": "\u0669",
  "\u06F9": "\u0669",
  "\u0CEF": "\u0C6F",
  "\u2468": "\u2788",
  "\u{1F10A}": "9,",
  "\u2490": "9.",
  "\u33E8": "9\u65E5",
  "\u32C8": "9\u6708",
  "\u3361": "9\u70B9",
  "\u237A": "a",
  "\uFF41": "a",
  "\u{1D41A}": "a",
  "\u{1D44E}": "a",
  "\u{1D482}": "a",
  "\u{1D4B6}": "a",
  "\u{1D4EA}": "a",
  "\u{1D51E}": "a",
  "\u{1D552}": "a",
  "\u{1D586}": "a",
  "\u{1D5BA}": "a",
  "\u{1D5EE}": "a",
  "\u{1D622}": "a",
  "\u{1D656}": "a",
  "\u{1D68A}": "a",
  "\u0251": "a",
  "\u03B1": "a",
  "\u{1D6C2}": "a",
  "\u{1D6FC}": "a",
  "\u{1D736}": "a",
  "\u{1D770}": "a",
  "\u{1D7AA}": "a",
  "\u0430": "a",
  "\u2DF6": "\u0363",
  "\uFF21": "A",
  "\u{1D400}": "A",
  "\u{1D434}": "A",
  "\u{1D468}": "A",
  "\u{1D49C}": "A",
  "\u{1D4D0}": "A",
  "\u{1D504}": "A",
  "\u{1D538}": "A",
  "\u{1D56C}": "A",
  "\u{1D5A0}": "A",
  "\u{1D5D4}": "A",
  "\u{1D608}": "A",
  "\u{1D63C}": "A",
  "\u{1D670}": "A",
  "\u0391": "A",
  "\u{1D6A8}": "A",
  "\u{1D6E2}": "A",
  "\u{1D71C}": "A",
  "\u{1D756}": "A",
  "\u{1D790}": "A",
  "\u0410": "A",
  "\u13AA": "A",
  "\u15C5": "A",
  "\uA4EE": "A",
  "\u{16F40}": "A",
  "\u{102A0}": "A",
  "\u2376": "a\u0332",
  "\u01CE": "\u0103",
  "\u01CD": "\u0102",
  "\u0227": "\xE5",
  "\u0226": "\xC5",
  "\u1E9A": "\u1EA3",
  "\u2100": "a/c",
  "\u2101": "a/s",
  "\uA733": "aa",
  "\uA732": "AA",
  "\xE6": "ae",
  "\u04D5": "ae",
  "\xC6": "AE",
  "\u04D4": "AE",
  "\uA735": "ao",
  "\uA734": "AO",
  "\u{1F707}": "AR",
  "\uA737": "au",
  "\uA736": "AU",
  "\uA739": "av",
  "\uA73B": "av",
  "\uA738": "AV",
  "\uA73A": "AV",
  "\uA73D": "ay",
  "\uA73C": "AY",
  "\uAB7A": "\u1D00",
  "\u2200": "\u2C6F",
  "\u{1D217}": "\u2C6F",
  "\u15C4": "\u2C6F",
  "\uA4EF": "\u2C6F",
  "\u{1041F}": "\u2C70",
  "\u{1D41B}": "b",
  "\u{1D44F}": "b",
  "\u{1D483}": "b",
  "\u{1D4B7}": "b",
  "\u{1D4EB}": "b",
  "\u{1D51F}": "b",
  "\u{1D553}": "b",
  "\u{1D587}": "b",
  "\u{1D5BB}": "b",
  "\u{1D5EF}": "b",
  "\u{1D623}": "b",
  "\u{1D657}": "b",
  "\u{1D68B}": "b",
  "\u0184": "b",
  "\u042C": "b",
  "\u13CF": "b",
  "\u1472": "b",
  "\u15AF": "b",
  "\uFF22": "B",
  "\u212C": "B",
  "\u{1D401}": "B",
  "\u{1D435}": "B",
  "\u{1D469}": "B",
  "\u{1D4D1}": "B",
  "\u{1D505}": "B",
  "\u{1D539}": "B",
  "\u{1D56D}": "B",
  "\u{1D5A1}": "B",
  "\u{1D5D5}": "B",
  "\u{1D609}": "B",
  "\u{1D63D}": "B",
  "\u{1D671}": "B",
  "\uA7B4": "B",
  "\u0392": "B",
  "\u{1D6A9}": "B",
  "\u{1D6E3}": "B",
  "\u{1D71D}": "B",
  "\u{1D757}": "B",
  "\u{1D791}": "B",
  "\u0412": "B",
  "\u13F4": "B",
  "\u15F7": "B",
  "\uA4D0": "B",
  "\u{10282}": "B",
  "\u{102A1}": "B",
  "\u{10301}": "B",
  "\u0253": "b\u0314",
  "\u1473": "b\u0307",
  "\u0183": "b\u0304",
  "\u0182": "b\u0304",
  "\u0411": "b\u0304",
  "\u0180": "b\u0335",
  "\u048D": "b\u0335",
  "\u048C": "b\u0335",
  "\u0463": "b\u0335",
  "\u0462": "b\u0335",
  "\u147F": "b\xB7",
  "\u1481": "b\u0307\xB7",
  "\u1488": "b'",
  "\u042B": "bl",
  "\u0432": "\u0299",
  "\u13FC": "\u0299",
  "\uFF43": "c",
  "\u217D": "c",
  "\u{1D41C}": "c",
  "\u{1D450}": "c",
  "\u{1D484}": "c",
  "\u{1D4B8}": "c",
  "\u{1D4EC}": "c",
  "\u{1D520}": "c",
  "\u{1D554}": "c",
  "\u{1D588}": "c",
  "\u{1D5BC}": "c",
  "\u{1D5F0}": "c",
  "\u{1D624}": "c",
  "\u{1D658}": "c",
  "\u{1D68C}": "c",
  "\u1D04": "c",
  "\u03F2": "c",
  "\u2CA5": "c",
  "\u0441": "c",
  "\uABAF": "c",
  "\u{1043D}": "c",
  "\u2DED": "\u0368",
  "\u{1F74C}": "C",
  "\u{118F2}": "C",
  "\u{118E9}": "C",
  "\uFF23": "C",
  "\u216D": "C",
  "\u2102": "C",
  "\u212D": "C",
  "\u{1D402}": "C",
  "\u{1D436}": "C",
  "\u{1D46A}": "C",
  "\u{1D49E}": "C",
  "\u{1D4D2}": "C",
  "\u{1D56E}": "C",
  "\u{1D5A2}": "C",
  "\u{1D5D6}": "C",
  "\u{1D60A}": "C",
  "\u{1D63E}": "C",
  "\u{1D672}": "C",
  "\u03F9": "C",
  "\u2CA4": "C",
  "\u0421": "C",
  "\u13DF": "C",
  "\uA4DA": "C",
  "\u{102A2}": "C",
  "\u{10302}": "C",
  "\u{10415}": "C",
  "\u{1051C}": "C",
  "\xA2": "c\u0338",
  "\u023C": "c\u0338",
  "\u20A1": "C\u20EB",
  "\u{1F16E}": "C\u20E0",
  "\xE7": "c\u0326",
  "\u04AB": "c\u0326",
  "\xC7": "C\u0326",
  "\u04AA": "C\u0326",
  "\u0187": "C'",
  "\u2105": "c/o",
  "\u2106": "c/u",
  "\u{1F16D}": "\u33C4	\u20DD",
  "\u22F4": "\uA793",
  "\u025B": "\uA793",
  "\u03B5": "\uA793",
  "\u03F5": "\uA793",
  "\u{1D6C6}": "\uA793",
  "\u{1D6DC}": "\uA793",
  "\u{1D700}": "\uA793",
  "\u{1D716}": "\uA793",
  "\u{1D73A}": "\uA793",
  "\u{1D750}": "\uA793",
  "\u{1D774}": "\uA793",
  "\u{1D78A}": "\uA793",
  "\u{1D7AE}": "\uA793",
  "\u{1D7C4}": "\uA793",
  "\u2C89": "\uA793",
  "\u0454": "\uA793",
  "\u0511": "\uA793",
  "\uAB9B": "\uA793",
  "\u{118CE}": "\uA793",
  "\u{10429}": "\uA793",
  "\u20AC": "\uA792",
  "\u2C88": "\uA792",
  "\u0404": "\uA792",
  "\u2377": "\uA793\u0332",
  "\u037D": "\uA73F",
  "\u03FF": "\uA73E",
  "\u217E": "d",
  "\u2146": "d",
  "\u{1D41D}": "d",
  "\u{1D451}": "d",
  "\u{1D485}": "d",
  "\u{1D4B9}": "d",
  "\u{1D4ED}": "d",
  "\u{1D521}": "d",
  "\u{1D555}": "d",
  "\u{1D589}": "d",
  "\u{1D5BD}": "d",
  "\u{1D5F1}": "d",
  "\u{1D625}": "d",
  "\u{1D659}": "d",
  "\u{1D68D}": "d",
  "\u0501": "d",
  "\u13E7": "d",
  "\u146F": "d",
  "\uA4D2": "d",
  "\u216E": "D",
  "\u2145": "D",
  "\u{1D403}": "D",
  "\u{1D437}": "D",
  "\u{1D46B}": "D",
  "\u{1D49F}": "D",
  "\u{1D4D3}": "D",
  "\u{1D507}": "D",
  "\u{1D53B}": "D",
  "\u{1D56F}": "D",
  "\u{1D5A3}": "D",
  "\u{1D5D7}": "D",
  "\u{1D60B}": "D",
  "\u{1D63F}": "D",
  "\u{1D673}": "D",
  "\u13A0": "D",
  "\u15DE": "D",
  "\u15EA": "D",
  "\uA4D3": "D",
  "\u0257": "d\u0314",
  "\u0256": "d\u0328",
  "\u018C": "d\u0304",
  "\u0111": "d\u0335",
  "\u0110": "D\u0335",
  "\xD0": "D\u0335",
  "\u0189": "D\u0335",
  "\u20AB": "d\u0335\u0331",
  "\uA77A": "\uA779",
  "\u147B": "d\xB7",
  "\u1487": "d'",
  "\u02A4": "d\u021D",
  "\u01F3": "dz",
  "\u02A3": "dz",
  "\u01F2": "Dz",
  "\u01F1": "DZ",
  "\u01C6": "d\u017E",
  "\u01C5": "D\u017E",
  "\u01C4": "D\u017D",
  "\u02A5": "d\u0291",
  "\uAB70": "\u1D05",
  "\u2E39": "\u1E9F",
  "\u03B4": "\u1E9F",
  "\u{1D6C5}": "\u1E9F",
  "\u{1D6FF}": "\u1E9F",
  "\u{1D739}": "\u1E9F",
  "\u{1D773}": "\u1E9F",
  "\u{1D7AD}": "\u1E9F",
  "\u056E": "\u1E9F",
  "\u1577": "\u1E9F",
  "\u212E": "e",
  "\uFF45": "e",
  "\u212F": "e",
  "\u2147": "e",
  "\u{1D41E}": "e",
  "\u{1D452}": "e",
  "\u{1D486}": "e",
  "\u{1D4EE}": "e",
  "\u{1D522}": "e",
  "\u{1D556}": "e",
  "\u{1D58A}": "e",
  "\u{1D5BE}": "e",
  "\u{1D5F2}": "e",
  "\u{1D626}": "e",
  "\u{1D65A}": "e",
  "\u{1D68E}": "e",
  "\uAB32": "e",
  "\u0435": "e",
  "\u04BD": "e",
  "\u2DF7": "\u0364",
  "\u22FF": "E",
  "\uFF25": "E",
  "\u2130": "E",
  "\u{1D404}": "E",
  "\u{1D438}": "E",
  "\u{1D46C}": "E",
  "\u{1D4D4}": "E",
  "\u{1D508}": "E",
  "\u{1D53C}": "E",
  "\u{1D570}": "E",
  "\u{1D5A4}": "E",
  "\u{1D5D8}": "E",
  "\u{1D60C}": "E",
  "\u{1D640}": "E",
  "\u{1D674}": "E",
  "\u0395": "E",
  "\u{1D6AC}": "E",
  "\u{1D6E6}": "E",
  "\u{1D720}": "E",
  "\u{1D75A}": "E",
  "\u{1D794}": "E",
  "\u0415": "E",
  "\u2D39": "E",
  "\u13AC": "E",
  "\uA4F0": "E",
  "\u{118A6}": "E",
  "\u{118AE}": "E",
  "\u{10286}": "E",
  "\u011B": "\u0115",
  "\u011A": "\u0114",
  "\u0247": "e\u0338",
  "\u0246": "E\u0338",
  "\u04BF": "e\u0328",
  "\uAB7C": "\u1D07",
  "\u0259": "\u01DD",
  "\u04D9": "\u01DD",
  "\u2203": "\u018E",
  "\u2D3A": "\u018E",
  "\uA4F1": "\u018E",
  "\u025A": "\u01DD\u02DE",
  "\u1D14": "\u01DDo",
  "\uAB41": "\u01DDo\u0338",
  "\uAB42": "\u01DDo\u0335",
  "\u04D8": "\u018F",
  "\u{1D221}": "\u0190",
  "\u2107": "\u0190",
  "\u0510": "\u0190",
  "\u13CB": "\u0190",
  "\u{16F2D}": "\u0190",
  "\u{10401}": "\u0190",
  "\u1D9F": "\u1D4B",
  "\u1D08": "\u025C",
  "\u0437": "\u025C",
  "\u0499": "\u025C\u0326",
  "\u{10442}": "\u025E",
  "\uA79D": "\u029A",
  "\u{1042A}": "\u029A",
  "\u{1D41F}": "f",
  "\u{1D453}": "f",
  "\u{1D487}": "f",
  "\u{1D4BB}": "f",
  "\u{1D4EF}": "f",
  "\u{1D523}": "f",
  "\u{1D557}": "f",
  "\u{1D58B}": "f",
  "\u{1D5BF}": "f",
  "\u{1D5F3}": "f",
  "\u{1D627}": "f",
  "\u{1D65B}": "f",
  "\u{1D68F}": "f",
  "\uAB35": "f",
  "\uA799": "f",
  "\u017F": "f",
  "\u1E9D": "f",
  "\u0584": "f",
  "\u{1D213}": "F",
  "\u2131": "F",
  "\u{1D405}": "F",
  "\u{1D439}": "F",
  "\u{1D46D}": "F",
  "\u{1D4D5}": "F",
  "\u{1D509}": "F",
  "\u{1D53D}": "F",
  "\u{1D571}": "F",
  "\u{1D5A5}": "F",
  "\u{1D5D9}": "F",
  "\u{1D60D}": "F",
  "\u{1D641}": "F",
  "\u{1D675}": "F",
  "\uA798": "F",
  "\u03DC": "F",
  "\u{1D7CA}": "F",
  "\u15B4": "F",
  "\uA4DD": "F",
  "\u{118C2}": "F",
  "\u{118A2}": "F",
  "\u{10287}": "F",
  "\u{102A5}": "F",
  "\u{10525}": "F",
  "\u0192": "f\u0326",
  "\u0191": "F\u0326",
  "\u1D6E": "f\u0334",
  "\u213B": "FAX",
  "\uFB00": "ff",
  "\uFB03": "ffi",
  "\uFB04": "ffl",
  "\uFB01": "fi",
  "\uFB02": "fl",
  "\u02A9": "f\u014B",
  "\u15B5": "\u2132",
  "\uA4DE": "\u2132",
  "\u{1D230}": "\uA7FB",
  "\u15B7": "\uA7FB",
  "\uFF47": "g",
  "\u210A": "g",
  "\u{1D420}": "g",
  "\u{1D454}": "g",
  "\u{1D488}": "g",
  "\u{1D4F0}": "g",
  "\u{1D524}": "g",
  "\u{1D558}": "g",
  "\u{1D58C}": "g",
  "\u{1D5C0}": "g",
  "\u{1D5F4}": "g",
  "\u{1D628}": "g",
  "\u{1D65C}": "g",
  "\u{1D690}": "g",
  "\u0261": "g",
  "\u1D83": "g",
  "\u018D": "g",
  "\u0581": "g",
  "\u{1D406}": "G",
  "\u{1D43A}": "G",
  "\u{1D46E}": "G",
  "\u{1D4A2}": "G",
  "\u{1D4D6}": "G",
  "\u{1D50A}": "G",
  "\u{1D53E}": "G",
  "\u{1D572}": "G",
  "\u{1D5A6}": "G",
  "\u{1D5DA}": "G",
  "\u{1D60E}": "G",
  "\u{1D642}": "G",
  "\u{1D676}": "G",
  "\u050C": "G",
  "\u13C0": "G",
  "\u13F3": "G",
  "\uA4D6": "G",
  "\u1DA2": "\u1D4D",
  "\u0260": "g\u0314",
  "\u01E7": "\u011F",
  "\u01E6": "\u011E",
  "\u01F5": "\u0123",
  "\u01E5": "g\u0335",
  "\u01E4": "G\u0335",
  "\u0193": "G'",
  "\u050D": "\u0262",
  "\uAB90": "\u0262",
  "\u13FB": "\u0262",
  "\uFF48": "h",
  "\u210E": "h",
  "\u{1D421}": "h",
  "\u{1D489}": "h",
  "\u{1D4BD}": "h",
  "\u{1D4F1}": "h",
  "\u{1D525}": "h",
  "\u{1D559}": "h",
  "\u{1D58D}": "h",
  "\u{1D5C1}": "h",
  "\u{1D5F5}": "h",
  "\u{1D629}": "h",
  "\u{1D65D}": "h",
  "\u{1D691}": "h",
  "\u04BB": "h",
  "\u0570": "h",
  "\u13C2": "h",
  "\uFF28": "H",
  "\u210B": "H",
  "\u210C": "H",
  "\u210D": "H",
  "\u{1D407}": "H",
  "\u{1D43B}": "H",
  "\u{1D46F}": "H",
  "\u{1D4D7}": "H",
  "\u{1D573}": "H",
  "\u{1D5A7}": "H",
  "\u{1D5DB}": "H",
  "\u{1D60F}": "H",
  "\u{1D643}": "H",
  "\u{1D677}": "H",
  "\u0397": "H",
  "\u{1D6AE}": "H",
  "\u{1D6E8}": "H",
  "\u{1D722}": "H",
  "\u{1D75C}": "H",
  "\u{1D796}": "H",
  "\u2C8E": "H",
  "\u041D": "H",
  "\u13BB": "H",
  "\u157C": "H",
  "\uA4E7": "H",
  "\u{102CF}": "H",
  "\u1D78": "\u1D34",
  "\u0266": "h\u0314",
  "\uA695": "h\u0314",
  "\u13F2": "h\u0314",
  "\u2C67": "H\u0329",
  "\u04A2": "H\u0329",
  "\u0127": "h\u0335",
  "\u210F": "h\u0335",
  "\u045B": "h\u0335",
  "\u0126": "H\u0335",
  "\u04C9": "H\u0326",
  "\u04C7": "H\u0326",
  "\u043D": "\u029C",
  "\uAB8B": "\u029C",
  "\u04A3": "\u029C\u0329",
  "\u04CA": "\u029C\u0326",
  "\u04C8": "\u029C\u0326",
  "\u050A": "\u01F6",
  "\uAB80": "\u2C76",
  "\u0370": "\u2C75",
  "\u13A8": "\u2C75",
  "\u13B0": "\u2C75",
  "\uA6B1": "\u2C75",
  "\uA795": "\uA727",
  "\u02DB": "i",
  "\u2373": "i",
  "\uFF49": "i",
  "\u2170": "i",
  "\u2139": "i",
  "\u2148": "i",
  "\u{1D422}": "i",
  "\u{1D456}": "i",
  "\u{1D48A}": "i",
  "\u{1D4BE}": "i",
  "\u{1D4F2}": "i",
  "\u{1D526}": "i",
  "\u{1D55A}": "i",
  "\u{1D58E}": "i",
  "\u{1D5C2}": "i",
  "\u{1D5F6}": "i",
  "\u{1D62A}": "i",
  "\u{1D65E}": "i",
  "\u{1D692}": "i",
  "\u0131": "i",
  "\u{1D6A4}": "i",
  "\u026A": "i",
  "\u0269": "i",
  "\u03B9": "i",
  "\u1FBE": "i",
  "\u037A": "i",
  "\u{1D6CA}": "i",
  "\u{1D704}": "i",
  "\u{1D73E}": "i",
  "\u{1D778}": "i",
  "\u{1D7B2}": "i",
  "\u0456": "i",
  "\uA647": "i",
  "\u04CF": "i",
  "\uAB75": "i",
  "\u13A5": "i",
  "\u{118C3}": "i",
  "\u24DB": "\u24BE",
  "\u2378": "i\u0332",
  "\u01D0": "\u012D",
  "\u01CF": "\u012C",
  "\u0268": "i\u0335",
  "\u1D7B": "i\u0335",
  "\u1D7C": "i\u0335",
  "\u2171": "ii",
  "\u2172": "iii",
  "\u0133": "ij",
  "\u2173": "iv",
  "\u2178": "ix",
  "\uFF4A": "j",
  "\u2149": "j",
  "\u{1D423}": "j",
  "\u{1D457}": "j",
  "\u{1D48B}": "j",
  "\u{1D4BF}": "j",
  "\u{1D4F3}": "j",
  "\u{1D527}": "j",
  "\u{1D55B}": "j",
  "\u{1D58F}": "j",
  "\u{1D5C3}": "j",
  "\u{1D5F7}": "j",
  "\u{1D62B}": "j",
  "\u{1D65F}": "j",
  "\u{1D693}": "j",
  "\u03F3": "j",
  "\u0458": "j",
  "\uFF2A": "J",
  "\u{1D409}": "J",
  "\u{1D43D}": "J",
  "\u{1D471}": "J",
  "\u{1D4A5}": "J",
  "\u{1D4D9}": "J",
  "\u{1D50D}": "J",
  "\u{1D541}": "J",
  "\u{1D575}": "J",
  "\u{1D5A9}": "J",
  "\u{1D5DD}": "J",
  "\u{1D611}": "J",
  "\u{1D645}": "J",
  "\u{1D679}": "J",
  "\uA7B2": "J",
  "\u037F": "J",
  "\u0408": "J",
  "\u13AB": "J",
  "\u148D": "J",
  "\uA4D9": "J",
  "\u0249": "j\u0335",
  "\u0248": "J\u0335",
  "\u1499": "J\xB7",
  "\u{1D6A5}": "\u0237",
  "\u0575": "\u0237",
  "\uAB7B": "\u1D0A",
  "\u{1D424}": "k",
  "\u{1D458}": "k",
  "\u{1D48C}": "k",
  "\u{1D4C0}": "k",
  "\u{1D4F4}": "k",
  "\u{1D528}": "k",
  "\u{1D55C}": "k",
  "\u{1D590}": "k",
  "\u{1D5C4}": "k",
  "\u{1D5F8}": "k",
  "\u{1D62C}": "k",
  "\u{1D660}": "k",
  "\u{1D694}": "k",
  "\u212A": "K",
  "\uFF2B": "K",
  "\u{1D40A}": "K",
  "\u{1D43E}": "K",
  "\u{1D472}": "K",
  "\u{1D4A6}": "K",
  "\u{1D4DA}": "K",
  "\u{1D50E}": "K",
  "\u{1D542}": "K",
  "\u{1D576}": "K",
  "\u{1D5AA}": "K",
  "\u{1D5DE}": "K",
  "\u{1D612}": "K",
  "\u{1D646}": "K",
  "\u{1D67A}": "K",
  "\u039A": "K",
  "\u{1D6B1}": "K",
  "\u{1D6EB}": "K",
  "\u{1D725}": "K",
  "\u{1D75F}": "K",
  "\u{1D799}": "K",
  "\u2C94": "K",
  "\u041A": "K",
  "\u13E6": "K",
  "\u16D5": "K",
  "\uA4D7": "K",
  "\u{10518}": "K",
  "\u0199": "k\u0314",
  "\u2C69": "K\u0329",
  "\u049A": "K\u0329",
  "\u20AD": "K\u0335",
  "\uA740": "K\u0335",
  "\u049E": "K\u0335",
  "\u0198": "K'",
  "\u05C0": "l",
  "|": "l",
  "\u2223": "l",
  "\u23FD": "l",
  "\uFFE8": "l",
  "\u0661": "l",
  "\u06F1": "l",
  "\u{10320}": "l",
  "\u{1E8C7}": "l",
  "\u{1D7CF}": "l",
  "\u{1D7D9}": "l",
  "\u{1D7E3}": "l",
  "\u{1D7ED}": "l",
  "\u{1D7F7}": "l",
  "\u{1FBF1}": "l",
  I,
  "\uFF29": "l",
  "\u2160": "l",
  "\u2110": "l",
  "\u2111": "l",
  "\u{1D408}": "l",
  "\u{1D43C}": "l",
  "\u{1D470}": "l",
  "\u{1D4D8}": "l",
  "\u{1D540}": "l",
  "\u{1D574}": "l",
  "\u{1D5A8}": "l",
  "\u{1D5DC}": "l",
  "\u{1D610}": "l",
  "\u{1D644}": "l",
  "\u{1D678}": "l",
  "\u0196": "l",
  "\uFF4C": "l",
  "\u217C": "l",
  "\u2113": "l",
  "\u{1D425}": "l",
  "\u{1D459}": "l",
  "\u{1D48D}": "l",
  "\u{1D4C1}": "l",
  "\u{1D4F5}": "l",
  "\u{1D529}": "l",
  "\u{1D55D}": "l",
  "\u{1D591}": "l",
  "\u{1D5C5}": "l",
  "\u{1D5F9}": "l",
  "\u{1D62D}": "l",
  "\u{1D661}": "l",
  "\u{1D695}": "l",
  "\u01C0": "l",
  "\u0399": "l",
  "\u{1D6B0}": "l",
  "\u{1D6EA}": "l",
  "\u{1D724}": "l",
  "\u{1D75E}": "l",
  "\u{1D798}": "l",
  "\u2C92": "l",
  "\u0406": "l",
  "\u04C0": "l",
  "\u05D5": "l",
  "\u05DF": "l",
  "\u0627": "l",
  "\u{1EE00}": "l",
  "\u{1EE80}": "l",
  "\uFE8E": "l",
  "\uFE8D": "l",
  "\u07CA": "l",
  "\u2D4F": "l",
  "\u16C1": "l",
  "\uA4F2": "l",
  "\u{16F28}": "l",
  "\u{1028A}": "l",
  "\u{10309}": "l",
  "\u{1D22A}": "L",
  "\u216C": "L",
  "\u2112": "L",
  "\u{1D40B}": "L",
  "\u{1D43F}": "L",
  "\u{1D473}": "L",
  "\u{1D4DB}": "L",
  "\u{1D50F}": "L",
  "\u{1D543}": "L",
  "\u{1D577}": "L",
  "\u{1D5AB}": "L",
  "\u{1D5DF}": "L",
  "\u{1D613}": "L",
  "\u{1D647}": "L",
  "\u{1D67B}": "L",
  "\u2CD0": "L",
  "\u13DE": "L",
  "\u14AA": "L",
  "\uA4E1": "L",
  "\u{16F16}": "L",
  "\u{118A3}": "L",
  "\u{118B2}": "L",
  "\u{1041B}": "L",
  "\u{10526}": "L",
  "\uFD3C": "l\u030B",
  "\uFD3D": "l\u030B",
  "\u0142": "l\u0338",
  "\u0141": "L\u0338",
  "\u026D": "l\u0328",
  "\u0197": "l\u0335",
  "\u019A": "l\u0335",
  "\u026B": "l\u0334",
  "\u0625": "l\u0655",
  "\uFE88": "l\u0655",
  "\uFE87": "l\u0655",
  "\u0673": "l\u0655",
  "\u0140": "l\xB7",
  "\u013F": "l\xB7",
  "\u14B7": "l\xB7",
  "\u{1F102}": "l,",
  "\u2488": "l.",
  "\u05F1": "l'",
  "\u2493": "l2.",
  "\u33EB": "l2\u65E5",
  "\u32CB": "l2\u6708",
  "\u3364": "l2\u70B9",
  "\u2494": "l3.",
  "\u33EC": "l3\u65E5",
  "\u3365": "l3\u70B9",
  "\u2495": "l4.",
  "\u33ED": "l4\u65E5",
  "\u3366": "l4\u70B9",
  "\u2496": "l5.",
  "\u33EE": "l5\u65E5",
  "\u3367": "l5\u70B9",
  "\u2497": "l6.",
  "\u33EF": "l6\u65E5",
  "\u3368": "l6\u70B9",
  "\u2498": "l7.",
  "\u33F0": "l7\u65E5",
  "\u3369": "l7\u70B9",
  "\u2499": "l8.",
  "\u33F1": "l8\u65E5",
  "\u336A": "l8\u70B9",
  "\u249A": "l9.",
  "\u33F2": "l9\u65E5",
  "\u336B": "l9\u70B9",
  "\u01C9": "lj",
  "\u0132": "lJ",
  "\u01C8": "Lj",
  "\u01C7": "LJ",
  "\u2016": "ll",
  "\u2225": "ll",
  "\u2161": "ll",
  "\u01C1": "ll",
  "\u05F0": "ll",
  "\u{10199}": "l\u0335l\u0335",
  "\u2492": "ll.",
  "\u2162": "lll",
  "\u{10198}": "l\u0335l\u0335S\u0335",
  "\u33EA": "ll\u65E5",
  "\u32CA": "ll\u6708",
  "\u3363": "ll\u70B9",
  "\u042E": "lO",
  "\u2491": "lO.",
  "\u33E9": "lO\u65E5",
  "\u32C9": "lO\u6708",
  "\u3362": "lO\u70B9",
  "\u02AA": "ls",
  "\u20B6": "lt",
  "\u2163": "lV",
  "\u2168": "lX",
  "\u026E": "l\u021D",
  "\u02AB": "lz",
  "\u0623": "l\u0674",
  "\uFE84": "l\u0674",
  "\uFE83": "l\u0674",
  "\u0672": "l\u0674",
  "\u0675": "l\u0674",
  "\uFDF3": "l\u0643\u0628\u0631",
  "\uFDF2": "l\u0644\u0644\u0651\u0670o",
  "\u33E0": "l\u65E5",
  "\u32C0": "l\u6708",
  "\u3359": "l\u70B9",
  "\u2CD1": "\u029F",
  "\uABAE": "\u029F",
  "\u{10443}": "\u029F",
  "\uFF2D": "M",
  "\u216F": "M",
  "\u2133": "M",
  "\u{1D40C}": "M",
  "\u{1D440}": "M",
  "\u{1D474}": "M",
  "\u{1D4DC}": "M",
  "\u{1D510}": "M",
  "\u{1D544}": "M",
  "\u{1D578}": "M",
  "\u{1D5AC}": "M",
  "\u{1D5E0}": "M",
  "\u{1D614}": "M",
  "\u{1D648}": "M",
  "\u{1D67C}": "M",
  "\u039C": "M",
  "\u{1D6B3}": "M",
  "\u{1D6ED}": "M",
  "\u{1D727}": "M",
  "\u{1D761}": "M",
  "\u{1D79B}": "M",
  "\u03FA": "M",
  "\u2C98": "M",
  "\u041C": "M",
  "\u13B7": "M",
  "\u15F0": "M",
  "\u16D6": "M",
  "\uA4DF": "M",
  "\u{102B0}": "M",
  "\u{10311}": "M",
  "\u04CD": "M\u0326",
  "\u{1F76B}": "MB",
  "\u2DE8": "\u1DDF",
  "\u{1D427}": "n",
  "\u{1D45B}": "n",
  "\u{1D48F}": "n",
  "\u{1D4C3}": "n",
  "\u{1D4F7}": "n",
  "\u{1D52B}": "n",
  "\u{1D55F}": "n",
  "\u{1D593}": "n",
  "\u{1D5C7}": "n",
  "\u{1D5FB}": "n",
  "\u{1D62F}": "n",
  "\u{1D663}": "n",
  "\u{1D697}": "n",
  "\u0578": "n",
  "\u057C": "n",
  "\uFF2E": "N",
  "\u2115": "N",
  "\u{1D40D}": "N",
  "\u{1D441}": "N",
  "\u{1D475}": "N",
  "\u{1D4A9}": "N",
  "\u{1D4DD}": "N",
  "\u{1D511}": "N",
  "\u{1D579}": "N",
  "\u{1D5AD}": "N",
  "\u{1D5E1}": "N",
  "\u{1D615}": "N",
  "\u{1D649}": "N",
  "\u{1D67D}": "N",
  "\u039D": "N",
  "\u{1D6B4}": "N",
  "\u{1D6EE}": "N",
  "\u{1D728}": "N",
  "\u{1D762}": "N",
  "\u{1D79C}": "N",
  "\u2C9A": "N",
  "\uA4E0": "N",
  "\u{10513}": "N",
  "\u{1018E}": "N\u030A",
  "\u0273": "n\u0328",
  "\u019E": "n\u0329",
  "\u03B7": "n\u0329",
  "\u{1D6C8}": "n\u0329",
  "\u{1D702}": "n\u0329",
  "\u{1D73C}": "n\u0329",
  "\u{1D776}": "n\u0329",
  "\u{1D7B0}": "n\u0329",
  "\u019D": "N\u0326",
  "\u1D70": "n\u0334",
  "\u01CC": "nj",
  "\u01CB": "Nj",
  "\u01CA": "NJ",
  "\u2116": "No",
  "\u0377": "\u1D0E",
  "\u0438": "\u1D0E",
  "\u{1044D}": "\u1D0E",
  "\u0146": "\u0272",
  "\u0C02": "o",
  "\u0C82": "o",
  "\u0D02": "o",
  "\u0D82": "o",
  "\u0966": "o",
  "\u0A66": "o",
  "\u0AE6": "o",
  "\u0BE6": "o",
  "\u0C66": "o",
  "\u0CE6": "o",
  "\u0D66": "o",
  "\u0E50": "o",
  "\u0ED0": "o",
  "\u1040": "o",
  "\u0665": "o",
  "\u06F5": "o",
  "\uFF4F": "o",
  "\u2134": "o",
  "\u{1D428}": "o",
  "\u{1D45C}": "o",
  "\u{1D490}": "o",
  "\u{1D4F8}": "o",
  "\u{1D52C}": "o",
  "\u{1D560}": "o",
  "\u{1D594}": "o",
  "\u{1D5C8}": "o",
  "\u{1D5FC}": "o",
  "\u{1D630}": "o",
  "\u{1D664}": "o",
  "\u{1D698}": "o",
  "\u1D0F": "o",
  "\u1D11": "o",
  "\uAB3D": "o",
  "\u03BF": "o",
  "\u{1D6D0}": "o",
  "\u{1D70A}": "o",
  "\u{1D744}": "o",
  "\u{1D77E}": "o",
  "\u{1D7B8}": "o",
  "\u03C3": "o",
  "\u{1D6D4}": "o",
  "\u{1D70E}": "o",
  "\u{1D748}": "o",
  "\u{1D782}": "o",
  "\u{1D7BC}": "o",
  "\u2C9F": "o",
  "\u043E": "o",
  "\u10FF": "o",
  "\u0585": "o",
  "\u05E1": "o",
  "\u0647": "o",
  "\u{1EE24}": "o",
  "\u{1EE64}": "o",
  "\u{1EE84}": "o",
  "\uFEEB": "o",
  "\uFEEC": "o",
  "\uFEEA": "o",
  "\uFEE9": "o",
  "\u06BE": "o",
  "\uFBAC": "o",
  "\uFBAD": "o",
  "\uFBAB": "o",
  "\uFBAA": "o",
  "\u06C1": "o",
  "\uFBA8": "o",
  "\uFBA9": "o",
  "\uFBA7": "o",
  "\uFBA6": "o",
  "\u06D5": "o",
  "\u0D20": "o",
  "\u101D": "o",
  "\u{104EA}": "o",
  "\u{118C8}": "o",
  "\u{118D7}": "o",
  "\u{1042C}": "o",
  "\u07C0": "O",
  "\u09E6": "O",
  "\u0B66": "O",
  "\u3007": "O",
  "\u{114D0}": "O",
  "\u{118E0}": "O",
  "\u{1D7CE}": "O",
  "\u{1D7D8}": "O",
  "\u{1D7E2}": "O",
  "\u{1D7EC}": "O",
  "\u{1D7F6}": "O",
  "\u{1FBF0}": "O",
  "\uFF2F": "O",
  "\u{1D40E}": "O",
  "\u{1D442}": "O",
  "\u{1D476}": "O",
  "\u{1D4AA}": "O",
  "\u{1D4DE}": "O",
  "\u{1D512}": "O",
  "\u{1D546}": "O",
  "\u{1D57A}": "O",
  "\u{1D5AE}": "O",
  "\u{1D5E2}": "O",
  "\u{1D616}": "O",
  "\u{1D64A}": "O",
  "\u{1D67E}": "O",
  "\u039F": "O",
  "\u{1D6B6}": "O",
  "\u{1D6F0}": "O",
  "\u{1D72A}": "O",
  "\u{1D764}": "O",
  "\u{1D79E}": "O",
  "\u2C9E": "O",
  "\u041E": "O",
  "\u0555": "O",
  "\u2D54": "O",
  "\u12D0": "O",
  "\u0B20": "O",
  "\u{104C2}": "O",
  "\uA4F3": "O",
  "\u{118B5}": "O",
  "\u{10292}": "O",
  "\u{102AB}": "O",
  "\u{10404}": "O",
  "\u{10516}": "O",
  "\u2070": "\xBA",
  "\u1D52": "\xBA",
  "\u01D2": "\u014F",
  "\u01D1": "\u014E",
  "\u06FF": "o\u0302",
  "\u0150": "\xD6",
  "\xF8": "o\u0338",
  "\uAB3E": "o\u0338",
  "\xD8": "O\u0338",
  "\u2D41": "O\u0338",
  "\u01FE": "O\u0338\u0301",
  "\u0275": "o\u0335",
  "\uA74B": "o\u0335",
  "\u04E9": "o\u0335",
  "\u0473": "o\u0335",
  "\uAB8E": "o\u0335",
  "\uABBB": "o\u0335",
  "\u2296": "O\u0335",
  "\u229D": "O\u0335",
  "\u236C": "O\u0335",
  "\u{1D21A}": "O\u0335",
  "\u{1F714}": "O\u0335",
  "\u019F": "O\u0335",
  "\uA74A": "O\u0335",
  "\u03B8": "O\u0335",
  "\u03D1": "O\u0335",
  "\u{1D6C9}": "O\u0335",
  "\u{1D6DD}": "O\u0335",
  "\u{1D703}": "O\u0335",
  "\u{1D717}": "O\u0335",
  "\u{1D73D}": "O\u0335",
  "\u{1D751}": "O\u0335",
  "\u{1D777}": "O\u0335",
  "\u{1D78B}": "O\u0335",
  "\u{1D7B1}": "O\u0335",
  "\u{1D7C5}": "O\u0335",
  "\u0398": "O\u0335",
  "\u03F4": "O\u0335",
  "\u{1D6AF}": "O\u0335",
  "\u{1D6B9}": "O\u0335",
  "\u{1D6E9}": "O\u0335",
  "\u{1D6F3}": "O\u0335",
  "\u{1D723}": "O\u0335",
  "\u{1D72D}": "O\u0335",
  "\u{1D75D}": "O\u0335",
  "\u{1D767}": "O\u0335",
  "\u{1D797}": "O\u0335",
  "\u{1D7A1}": "O\u0335",
  "\u04E8": "O\u0335",
  "\u0472": "O\u0335",
  "\u2D31": "O\u0335",
  "\u13BE": "O\u0335",
  "\u13EB": "O\u0335",
  "\uAB74": "o\u031B",
  "\uFCD9": "o\u0670",
  "\u{1F101}": "O,",
  "\u{1F100}": "O.",
  "\u01A1": "o'",
  "\u01A0": "O'",
  "\u13A4": "O'",
  "%": "\xBA/\u2080",
  "\u066A": "\xBA/\u2080",
  "\u2052": "\xBA/\u2080",
  "\u2030": "\xBA/\u2080\u2080",
  "\u0609": "\xBA/\u2080\u2080",
  "\u2031": "\xBA/\u2080\u2080\u2080",
  "\u060A": "\xBA/\u2080\u2080\u2080",
  "\u0153": "oe",
  "\u0152": "OE",
  "\u0276": "o\u1D07",
  "\u221E": "oo",
  "\uA74F": "oo",
  "\uA699": "oo",
  "\uA74E": "OO",
  "\uA698": "OO",
  "\uFCD7": "o\u062C",
  "\uFC51": "o\u062C",
  "\uFCD8": "o\u0645",
  "\uFC52": "o\u0645",
  "\uFD93": "o\u0645\u062C",
  "\uFD94": "o\u0645\u0645",
  "\uFC53": "o\u0649",
  "\uFC54": "o\u0649",
  "\u0D5F": "o\u0D30o",
  "\u1010": "o\u102C",
  "\u3358": "O\u70B9",
  "\u2184": "\u0254",
  "\u1D10": "\u0254",
  "\u037B": "\u0254",
  "\u{1044B}": "\u0254",
  "\u2183": "\u0186",
  "\u03FD": "\u0186",
  "\uA4DB": "\u0186",
  "\u{10423}": "\u0186",
  "\uAB3F": "\u0254\u0338",
  "\uAB62": "\u0254e",
  "\u{1043F}": "\u0277",
  "\u2374": "p",
  "\uFF50": "p",
  "\u{1D429}": "p",
  "\u{1D45D}": "p",
  "\u{1D491}": "p",
  "\u{1D4C5}": "p",
  "\u{1D4F9}": "p",
  "\u{1D52D}": "p",
  "\u{1D561}": "p",
  "\u{1D595}": "p",
  "\u{1D5C9}": "p",
  "\u{1D5FD}": "p",
  "\u{1D631}": "p",
  "\u{1D665}": "p",
  "\u{1D699}": "p",
  "\u03C1": "p",
  "\u03F1": "p",
  "\u{1D6D2}": "p",
  "\u{1D6E0}": "p",
  "\u{1D70C}": "p",
  "\u{1D71A}": "p",
  "\u{1D746}": "p",
  "\u{1D754}": "p",
  "\u{1D780}": "p",
  "\u{1D78E}": "p",
  "\u{1D7BA}": "p",
  "\u{1D7C8}": "p",
  "\u2CA3": "p",
  "\u0440": "p",
  "\uFF30": "P",
  "\u2119": "P",
  "\u{1D40F}": "P",
  "\u{1D443}": "P",
  "\u{1D477}": "P",
  "\u{1D4AB}": "P",
  "\u{1D4DF}": "P",
  "\u{1D513}": "P",
  "\u{1D57B}": "P",
  "\u{1D5AF}": "P",
  "\u{1D5E3}": "P",
  "\u{1D617}": "P",
  "\u{1D64B}": "P",
  "\u{1D67F}": "P",
  "\u03A1": "P",
  "\u{1D6B8}": "P",
  "\u{1D6F2}": "P",
  "\u{1D72C}": "P",
  "\u{1D766}": "P",
  "\u{1D7A0}": "P",
  "\u2CA2": "P",
  "\u0420": "P",
  "\u13E2": "P",
  "\u146D": "P",
  "\uA4D1": "P",
  "\u{10295}": "P",
  "\u01A5": "p\u0314",
  "\u1D7D": "p\u0335",
  "\u1477": "p\xB7",
  "\u1486": "P'",
  "\u1D29": "\u1D18",
  "\uABB2": "\u1D18",
  "\u03C6": "\u0278",
  "\u03D5": "\u0278",
  "\u{1D6D7}": "\u0278",
  "\u{1D6DF}": "\u0278",
  "\u{1D711}": "\u0278",
  "\u{1D719}": "\u0278",
  "\u{1D74B}": "\u0278",
  "\u{1D753}": "\u0278",
  "\u{1D785}": "\u0278",
  "\u{1D78D}": "\u0278",
  "\u{1D7BF}": "\u0278",
  "\u{1D7C7}": "\u0278",
  "\u2CAB": "\u0278",
  "\u0444": "\u0278",
  "\u{1D42A}": "q",
  "\u{1D45E}": "q",
  "\u{1D492}": "q",
  "\u{1D4C6}": "q",
  "\u{1D4FA}": "q",
  "\u{1D52E}": "q",
  "\u{1D562}": "q",
  "\u{1D596}": "q",
  "\u{1D5CA}": "q",
  "\u{1D5FE}": "q",
  "\u{1D632}": "q",
  "\u{1D666}": "q",
  "\u{1D69A}": "q",
  "\u051B": "q",
  "\u0563": "q",
  "\u0566": "q",
  "\u211A": "Q",
  "\u{1D410}": "Q",
  "\u{1D444}": "Q",
  "\u{1D478}": "Q",
  "\u{1D4AC}": "Q",
  "\u{1D4E0}": "Q",
  "\u{1D514}": "Q",
  "\u{1D57C}": "Q",
  "\u{1D5B0}": "Q",
  "\u{1D5E4}": "Q",
  "\u{1D618}": "Q",
  "\u{1D64C}": "Q",
  "\u{1D680}": "Q",
  "\u2D55": "Q",
  "\u02A0": "q\u0314",
  "\u{1F700}": "QE",
  "\u1D90": "\u024B",
  "\u1D0B": "\u0138",
  "\u03BA": "\u0138",
  "\u03F0": "\u0138",
  "\u{1D6CB}": "\u0138",
  "\u{1D6DE}": "\u0138",
  "\u{1D705}": "\u0138",
  "\u{1D718}": "\u0138",
  "\u{1D73F}": "\u0138",
  "\u{1D752}": "\u0138",
  "\u{1D779}": "\u0138",
  "\u{1D78C}": "\u0138",
  "\u{1D7B3}": "\u0138",
  "\u{1D7C6}": "\u0138",
  "\u2C95": "\u0138",
  "\u043A": "\u0138",
  "\uABB6": "\u0138",
  "\u049B": "\u0138\u0329",
  "\u049F": "\u0138\u0335",
  "\u{1D42B}": "r",
  "\u{1D45F}": "r",
  "\u{1D493}": "r",
  "\u{1D4C7}": "r",
  "\u{1D4FB}": "r",
  "\u{1D52F}": "r",
  "\u{1D563}": "r",
  "\u{1D597}": "r",
  "\u{1D5CB}": "r",
  "\u{1D5FF}": "r",
  "\u{1D633}": "r",
  "\u{1D667}": "r",
  "\u{1D69B}": "r",
  "\uAB47": "r",
  "\uAB48": "r",
  "\u1D26": "r",
  "\u2C85": "r",
  "\u0433": "r",
  "\uAB81": "r",
  "\u{1D216}": "R",
  "\u211B": "R",
  "\u211C": "R",
  "\u211D": "R",
  "\u{1D411}": "R",
  "\u{1D445}": "R",
  "\u{1D479}": "R",
  "\u{1D4E1}": "R",
  "\u{1D57D}": "R",
  "\u{1D5B1}": "R",
  "\u{1D5E5}": "R",
  "\u{1D619}": "R",
  "\u{1D64D}": "R",
  "\u{1D681}": "R",
  "\u01A6": "R",
  "\u13A1": "R",
  "\u13D2": "R",
  "\u{104B4}": "R",
  "\u1587": "R",
  "\uA4E3": "R",
  "\u{16F35}": "R",
  "\u027D": "r\u0328",
  "\u027C": "r\u0329",
  "\u024D": "r\u0335",
  "\u0493": "r\u0335",
  "\u1D72": "r\u0334",
  "\u0491": "r'",
  "\u{118E3}": "rn",
  m,
  "\u217F": "rn",
  "\u{1D426}": "rn",
  "\u{1D45A}": "rn",
  "\u{1D48E}": "rn",
  "\u{1D4C2}": "rn",
  "\u{1D4F6}": "rn",
  "\u{1D52A}": "rn",
  "\u{1D55E}": "rn",
  "\u{1D592}": "rn",
  "\u{1D5C6}": "rn",
  "\u{1D5FA}": "rn",
  "\u{1D62E}": "rn",
  "\u{1D662}": "rn",
  "\u{1D696}": "rn",
  "\u{11700}": "rn",
  "\u20A5": "rn\u0338",
  "\u0271": "rn\u0326",
  "\u1D6F": "rn\u0334",
  "\u20A8": "Rs",
  "\uAB71": "\u0280",
  "\uABA2": "\u0280",
  "\u044F": "\u1D19",
  "\u1D73": "\u027E\u0334",
  "\u2129": "\u027F",
  "\uFF53": "s",
  "\u{1D42C}": "s",
  "\u{1D460}": "s",
  "\u{1D494}": "s",
  "\u{1D4C8}": "s",
  "\u{1D4FC}": "s",
  "\u{1D530}": "s",
  "\u{1D564}": "s",
  "\u{1D598}": "s",
  "\u{1D5CC}": "s",
  "\u{1D600}": "s",
  "\u{1D634}": "s",
  "\u{1D668}": "s",
  "\u{1D69C}": "s",
  "\uA731": "s",
  "\u01BD": "s",
  "\u0455": "s",
  "\uABAA": "s",
  "\u{118C1}": "s",
  "\u{10448}": "s",
  "\uFF33": "S",
  "\u{1D412}": "S",
  "\u{1D446}": "S",
  "\u{1D47A}": "S",
  "\u{1D4AE}": "S",
  "\u{1D4E2}": "S",
  "\u{1D516}": "S",
  "\u{1D54A}": "S",
  "\u{1D57E}": "S",
  "\u{1D5B2}": "S",
  "\u{1D5E6}": "S",
  "\u{1D61A}": "S",
  "\u{1D64E}": "S",
  "\u{1D682}": "S",
  "\u0405": "S",
  "\u054F": "S",
  "\u13D5": "S",
  "\u13DA": "S",
  "\uA4E2": "S",
  "\u{16F3A}": "S",
  "\u{10296}": "S",
  "\u{10420}": "S",
  "\u0282": "s\u0328",
  "\u1D74": "s\u0334",
  "\uA7B5": "\xDF",
  "\u03B2": "\xDF",
  "\u03D0": "\xDF",
  "\u{1D6C3}": "\xDF",
  "\u{1D6FD}": "\xDF",
  "\u{1D737}": "\xDF",
  "\u{1D771}": "\xDF",
  "\u{1D7AB}": "\xDF",
  "\u13F0": "\xDF",
  "\u{1F75C}": "sss",
  "\uFB06": "st",
  "\u222B": "\u0283",
  "\uAB4D": "\u0283",
  "\u2211": "\u01A9",
  "\u2140": "\u01A9",
  "\u03A3": "\u01A9",
  "\u{1D6BA}": "\u01A9",
  "\u{1D6F4}": "\u01A9",
  "\u{1D72E}": "\u01A9",
  "\u{1D768}": "\u01A9",
  "\u{1D7A2}": "\u01A9",
  "\u2D49": "\u01A9",
  "\u222C": "\u0283\u0283",
  "\u222D": "\u0283\u0283\u0283",
  "\u2A0C": "\u0283\u0283\u0283\u0283",
  "\u{1D42D}": "t",
  "\u{1D461}": "t",
  "\u{1D495}": "t",
  "\u{1D4C9}": "t",
  "\u{1D4FD}": "t",
  "\u{1D531}": "t",
  "\u{1D565}": "t",
  "\u{1D599}": "t",
  "\u{1D5CD}": "t",
  "\u{1D601}": "t",
  "\u{1D635}": "t",
  "\u{1D669}": "t",
  "\u{1D69D}": "t",
  "\u22A4": "T",
  "\u27D9": "T",
  "\u{1F768}": "T",
  "\uFF34": "T",
  "\u{1D413}": "T",
  "\u{1D447}": "T",
  "\u{1D47B}": "T",
  "\u{1D4AF}": "T",
  "\u{1D4E3}": "T",
  "\u{1D517}": "T",
  "\u{1D54B}": "T",
  "\u{1D57F}": "T",
  "\u{1D5B3}": "T",
  "\u{1D5E7}": "T",
  "\u{1D61B}": "T",
  "\u{1D64F}": "T",
  "\u{1D683}": "T",
  "\u03A4": "T",
  "\u{1D6BB}": "T",
  "\u{1D6F5}": "T",
  "\u{1D72F}": "T",
  "\u{1D769}": "T",
  "\u{1D7A3}": "T",
  "\u2CA6": "T",
  "\u0422": "T",
  "\u13A2": "T",
  "\uA4D4": "T",
  "\u{16F0A}": "T",
  "\u{118BC}": "T",
  "\u{10297}": "T",
  "\u{102B1}": "T",
  "\u{10315}": "T",
  "\u01AD": "t\u0314",
  "\u2361": "T\u0308",
  "\u023E": "T\u0338",
  "\u021A": "\u0162",
  "\u01AE": "T\u0328",
  "\u04AC": "T\u0329",
  "\u20AE": "T\u20EB",
  "\u0167": "t\u0335",
  "\u0166": "T\u0335",
  "\u1D75": "t\u0334",
  "\u10A0": "\uA786",
  "\uA728": "T3",
  "\u02A8": "t\u0255",
  "\u2121": "TEL",
  "\uA777": "tf",
  "\u02A6": "ts",
  "\u02A7": "t\u0283",
  "\uA729": "t\u021D",
  "\u03C4": "\u1D1B",
  "\u{1D6D5}": "\u1D1B",
  "\u{1D70F}": "\u1D1B",
  "\u{1D749}": "\u1D1B",
  "\u{1D783}": "\u1D1B",
  "\u{1D7BD}": "\u1D1B",
  "\u0442": "\u1D1B",
  "\uAB72": "\u1D1B",
  "\u04AD": "\u1D1B\u0329",
  "\u0163": "\u01AB",
  "\u021B": "\u01AB",
  "\u13BF": "\u01AB",
  "\u{1D42E}": "u",
  "\u{1D462}": "u",
  "\u{1D496}": "u",
  "\u{1D4CA}": "u",
  "\u{1D4FE}": "u",
  "\u{1D532}": "u",
  "\u{1D566}": "u",
  "\u{1D59A}": "u",
  "\u{1D5CE}": "u",
  "\u{1D602}": "u",
  "\u{1D636}": "u",
  "\u{1D66A}": "u",
  "\u{1D69E}": "u",
  "\uA79F": "u",
  "\u1D1C": "u",
  "\uAB4E": "u",
  "\uAB52": "u",
  "\u028B": "u",
  "\u03C5": "u",
  "\u{1D6D6}": "u",
  "\u{1D710}": "u",
  "\u{1D74A}": "u",
  "\u{1D784}": "u",
  "\u{1D7BE}": "u",
  "\u057D": "u",
  "\u{104F6}": "u",
  "\u{118D8}": "u",
  "\u222A": "U",
  "\u22C3": "U",
  "\u{1D414}": "U",
  "\u{1D448}": "U",
  "\u{1D47C}": "U",
  "\u{1D4B0}": "U",
  "\u{1D4E4}": "U",
  "\u{1D518}": "U",
  "\u{1D54C}": "U",
  "\u{1D580}": "U",
  "\u{1D5B4}": "U",
  "\u{1D5E8}": "U",
  "\u{1D61C}": "U",
  "\u{1D650}": "U",
  "\u{1D684}": "U",
  "\u054D": "U",
  "\u1200": "U",
  "\u{104CE}": "U",
  "\u144C": "U",
  "\uA4F4": "U",
  "\u{16F42}": "U",
  "\u{118B8}": "U",
  "\u01D4": "\u016D",
  "\u01D3": "\u016C",
  "\u1D7E": "u\u0335",
  "\uAB9C": "u\u0335",
  "\u0244": "U\u0335",
  "\u13CC": "U\u0335",
  "\u1458": "U\xB7",
  "\u1467": "U'",
  "\u1D6B": "ue",
  "\uAB63": "uo",
  "\u1E43": "\uAB51",
  "\u057A": "\u0270",
  "\u1223": "\u0270",
  "\u2127": "\u01B1",
  "\u162E": "\u01B1",
  "\u1634": "\u01B1",
  "\u1D7F": "\u028A\u0335",
  "\u2228": "v",
  "\u22C1": "v",
  "\uFF56": "v",
  "\u2174": "v",
  "\u{1D42F}": "v",
  "\u{1D463}": "v",
  "\u{1D497}": "v",
  "\u{1D4CB}": "v",
  "\u{1D4FF}": "v",
  "\u{1D533}": "v",
  "\u{1D567}": "v",
  "\u{1D59B}": "v",
  "\u{1D5CF}": "v",
  "\u{1D603}": "v",
  "\u{1D637}": "v",
  "\u{1D66B}": "v",
  "\u{1D69F}": "v",
  "\u1D20": "v",
  "\u03BD": "v",
  "\u{1D6CE}": "v",
  "\u{1D708}": "v",
  "\u{1D742}": "v",
  "\u{1D77C}": "v",
  "\u{1D7B6}": "v",
  "\u0475": "v",
  "\u05D8": "v",
  "\u{11706}": "v",
  "\uABA9": "v",
  "\u{118C0}": "v",
  "\u{1D20D}": "V",
  "\u0667": "V",
  "\u06F7": "V",
  "\u2164": "V",
  "\u{1D415}": "V",
  "\u{1D449}": "V",
  "\u{1D47D}": "V",
  "\u{1D4B1}": "V",
  "\u{1D4E5}": "V",
  "\u{1D519}": "V",
  "\u{1D54D}": "V",
  "\u{1D581}": "V",
  "\u{1D5B5}": "V",
  "\u{1D5E9}": "V",
  "\u{1D61D}": "V",
  "\u{1D651}": "V",
  "\u{1D685}": "V",
  "\u0474": "V",
  "\u2D38": "V",
  "\u13D9": "V",
  "\u142F": "V",
  "\uA6DF": "V",
  "\uA4E6": "V",
  "\u{16F08}": "V",
  "\u{118A0}": "V",
  "\u{1051D}": "V",
  "\u{10197}": "V\u0335",
  "\u143B": "V\xB7",
  "\u{1F76C}": "VB",
  "\u2175": "vi",
  "\u2176": "vii",
  "\u2177": "viii",
  "\u2165": "Vl",
  "\u2166": "Vll",
  "\u2167": "Vlll",
  "\u{1F708}": "V\u1DE4",
  "\u1D27": "\u028C",
  "\u{104D8}": "\u028C",
  "\u0668": "\u0245",
  "\u06F8": "\u0245",
  "\u039B": "\u0245",
  "\u{1D6B2}": "\u0245",
  "\u{1D6EC}": "\u0245",
  "\u{1D726}": "\u0245",
  "\u{1D760}": "\u0245",
  "\u{1D79A}": "\u0245",
  "\u041B": "\u0245",
  "\u2D37": "\u0245",
  "\u{104B0}": "\u0245",
  "\u1431": "\u0245",
  "\uA6CE": "\u0245",
  "\uA4E5": "\u0245",
  "\u{16F3D}": "\u0245",
  "\u{1028D}": "\u0245",
  "\u04C5": "\u0245\u0326",
  "\u143D": "\u0245\xB7",
  "\u026F": "w",
  "\u{1D430}": "w",
  "\u{1D464}": "w",
  "\u{1D498}": "w",
  "\u{1D4CC}": "w",
  "\u{1D500}": "w",
  "\u{1D534}": "w",
  "\u{1D568}": "w",
  "\u{1D59C}": "w",
  "\u{1D5D0}": "w",
  "\u{1D604}": "w",
  "\u{1D638}": "w",
  "\u{1D66C}": "w",
  "\u{1D6A0}": "w",
  "\u1D21": "w",
  "\u0461": "w",
  "\u051D": "w",
  "\u0561": "w",
  "\u{1170A}": "w",
  "\u{1170E}": "w",
  "\u{1170F}": "w",
  "\uAB83": "w",
  "\u{118EF}": "W",
  "\u{118E6}": "W",
  "\u{1D416}": "W",
  "\u{1D44A}": "W",
  "\u{1D47E}": "W",
  "\u{1D4B2}": "W",
  "\u{1D4E6}": "W",
  "\u{1D51A}": "W",
  "\u{1D54E}": "W",
  "\u{1D582}": "W",
  "\u{1D5B6}": "W",
  "\u{1D5EA}": "W",
  "\u{1D61E}": "W",
  "\u{1D652}": "W",
  "\u{1D686}": "W",
  "\u051C": "W",
  "\u13B3": "W",
  "\u13D4": "W",
  "\uA4EA": "W",
  "\u047D": "w\u0486\u0487",
  "\u{114C5}": "w\u0307",
  "\u20A9": "W\u0335",
  "\uA761": "w\u0326",
  "\u1D0D": "\u028D",
  "\u043C": "\u028D",
  "\uAB87": "\u028D",
  "\u04CE": "\u028D\u0326",
  "\u166E": "x",
  "\xD7": "x",
  "\u292B": "x",
  "\u292C": "x",
  "\u2A2F": "x",
  "\uFF58": "x",
  "\u2179": "x",
  "\u{1D431}": "x",
  "\u{1D465}": "x",
  "\u{1D499}": "x",
  "\u{1D4CD}": "x",
  "\u{1D501}": "x",
  "\u{1D535}": "x",
  "\u{1D569}": "x",
  "\u{1D59D}": "x",
  "\u{1D5D1}": "x",
  "\u{1D605}": "x",
  "\u{1D639}": "x",
  "\u{1D66D}": "x",
  "\u{1D6A1}": "x",
  "\u0445": "x",
  "\u1541": "x",
  "\u157D": "x",
  "\u2DEF": "\u036F",
  "\u166D": "X",
  "\u2573": "X",
  "\u{10322}": "X",
  "\u{118EC}": "X",
  "\uFF38": "X",
  "\u2169": "X",
  "\u{1D417}": "X",
  "\u{1D44B}": "X",
  "\u{1D47F}": "X",
  "\u{1D4B3}": "X",
  "\u{1D4E7}": "X",
  "\u{1D51B}": "X",
  "\u{1D54F}": "X",
  "\u{1D583}": "X",
  "\u{1D5B7}": "X",
  "\u{1D5EB}": "X",
  "\u{1D61F}": "X",
  "\u{1D653}": "X",
  "\u{1D687}": "X",
  "\uA7B3": "X",
  "\u03A7": "X",
  "\u{1D6BE}": "X",
  "\u{1D6F8}": "X",
  "\u{1D732}": "X",
  "\u{1D76C}": "X",
  "\u{1D7A6}": "X",
  "\u2CAC": "X",
  "\u0425": "X",
  "\u2D5D": "X",
  "\u16B7": "X",
  "\uA4EB": "X",
  "\u{10290}": "X",
  "\u{102B4}": "X",
  "\u{10317}": "X",
  "\u{10527}": "X",
  "\u2A30": "x\u0307",
  "\u04B2": "X\u0329",
  "\u{10196}": "X\u0335",
  "\u217A": "xi",
  "\u217B": "xii",
  "\u216A": "Xl",
  "\u216B": "Xll",
  "\u0263": "y",
  "\u1D8C": "y",
  "\uFF59": "y",
  "\u{1D432}": "y",
  "\u{1D466}": "y",
  "\u{1D49A}": "y",
  "\u{1D4CE}": "y",
  "\u{1D502}": "y",
  "\u{1D536}": "y",
  "\u{1D56A}": "y",
  "\u{1D59E}": "y",
  "\u{1D5D2}": "y",
  "\u{1D606}": "y",
  "\u{1D63A}": "y",
  "\u{1D66E}": "y",
  "\u{1D6A2}": "y",
  "\u028F": "y",
  "\u1EFF": "y",
  "\uAB5A": "y",
  "\u03B3": "y",
  "\u213D": "y",
  "\u{1D6C4}": "y",
  "\u{1D6FE}": "y",
  "\u{1D738}": "y",
  "\u{1D772}": "y",
  "\u{1D7AC}": "y",
  "\u0443": "y",
  "\u04AF": "y",
  "\u10E7": "y",
  "\u{118DC}": "y",
  "\uFF39": "Y",
  "\u{1D418}": "Y",
  "\u{1D44C}": "Y",
  "\u{1D480}": "Y",
  "\u{1D4B4}": "Y",
  "\u{1D4E8}": "Y",
  "\u{1D51C}": "Y",
  "\u{1D550}": "Y",
  "\u{1D584}": "Y",
  "\u{1D5B8}": "Y",
  "\u{1D5EC}": "Y",
  "\u{1D620}": "Y",
  "\u{1D654}": "Y",
  "\u{1D688}": "Y",
  "\u03A5": "Y",
  "\u03D2": "Y",
  "\u{1D6BC}": "Y",
  "\u{1D6F6}": "Y",
  "\u{1D730}": "Y",
  "\u{1D76A}": "Y",
  "\u{1D7A4}": "Y",
  "\u2CA8": "Y",
  "\u0423": "Y",
  "\u04AE": "Y",
  "\u13A9": "Y",
  "\u13BD": "Y",
  "\uA4EC": "Y",
  "\u{16F43}": "Y",
  "\u{118A4}": "Y",
  "\u{102B2}": "Y",
  "\u01B4": "y\u0314",
  "\u024F": "y\u0335",
  "\u04B1": "y\u0335",
  "\xA5": "Y\u0335",
  "\u024E": "Y\u0335",
  "\u04B0": "Y\u0335",
  "\u0292": "\u021D",
  "\uA76B": "\u021D",
  "\u2CCD": "\u021D",
  "\u04E1": "\u021D",
  "\u10F3": "\u021D",
  "\u{1D433}": "z",
  "\u{1D467}": "z",
  "\u{1D49B}": "z",
  "\u{1D4CF}": "z",
  "\u{1D503}": "z",
  "\u{1D537}": "z",
  "\u{1D56B}": "z",
  "\u{1D59F}": "z",
  "\u{1D5D3}": "z",
  "\u{1D607}": "z",
  "\u{1D63B}": "z",
  "\u{1D66F}": "z",
  "\u{1D6A3}": "z",
  "\u1D22": "z",
  "\uAB93": "z",
  "\u{118C4}": "z",
  "\u{102F5}": "Z",
  "\u{118E5}": "Z",
  "\uFF3A": "Z",
  "\u2124": "Z",
  "\u2128": "Z",
  "\u{1D419}": "Z",
  "\u{1D44D}": "Z",
  "\u{1D481}": "Z",
  "\u{1D4B5}": "Z",
  "\u{1D4E9}": "Z",
  "\u{1D585}": "Z",
  "\u{1D5B9}": "Z",
  "\u{1D5ED}": "Z",
  "\u{1D621}": "Z",
  "\u{1D655}": "Z",
  "\u{1D689}": "Z",
  "\u0396": "Z",
  "\u{1D6AD}": "Z",
  "\u{1D6E7}": "Z",
  "\u{1D721}": "Z",
  "\u{1D75B}": "Z",
  "\u{1D795}": "Z",
  "\u13C3": "Z",
  "\uA4DC": "Z",
  "\u{118A9}": "Z",
  "\u0290": "z\u0328",
  "\u01B6": "z\u0335",
  "\u01B5": "Z\u0335",
  "\u0225": "z\u0326",
  "\u0224": "Z\u0326",
  "\u1D76": "z\u0334",
  "\u01BF": "\xFE",
  "\u03F8": "\xFE",
  "\u03F7": "\xDE",
  "\u{104C4}": "\xDE",
  "\u2079": "\uA770",
  "\u1D24": "\u01A8",
  "\u03E9": "\u01A8",
  "\uA645": "\u01A8",
  "\u044C": "\u0185",
  "\uAB9F": "\u0185",
  "\u044B": "\u0185i",
  "\uAB7E": "\u0242",
  "\u02E4": "\u02C1",
  "\uA6CD": "\u02A1",
  "\u2299": "\u0298",
  "\u2609": "\u0298",
  "\u2A00": "\u0298",
  "\uA668": "\u0298",
  "\u2D59": "\u0298",
  "\u{104C3}": "\u0298",
  "\u213E": "\u0393",
  "\u{1D6AA}": "\u0393",
  "\u{1D6E4}": "\u0393",
  "\u{1D71E}": "\u0393",
  "\u{1D758}": "\u0393",
  "\u{1D792}": "\u0393",
  "\u2C84": "\u0393",
  "\u0413": "\u0393",
  "\u13B1": "\u0393",
  "\u14A5": "\u0393",
  "\u{16F07}": "\u0393",
  "\u0492": "\u0393\u0335",
  "\u14AF": "\u0393\xB7",
  "\u0490": "\u0393'",
  "\u2206": "\u0394",
  "\u25B3": "\u0394",
  "\u{1F702}": "\u0394",
  "\u{1D6AB}": "\u0394",
  "\u{1D6E5}": "\u0394",
  "\u{1D71F}": "\u0394",
  "\u{1D759}": "\u0394",
  "\u{1D793}": "\u0394",
  "\u2C86": "\u0394",
  "\u2D60": "\u0394",
  "\u1403": "\u0394",
  "\u{16F1A}": "\u0394",
  "\u{10285}": "\u0394",
  "\u{102A3}": "\u0394",
  "\u2359": "\u0394\u0332",
  "\u140F": "\u0394\xB7",
  "\u142C": "\u0394\u1420",
  "\u{1D7CB}": "\u03DD",
  "\u{1D6C7}": "\u03B6",
  "\u{1D701}": "\u03B6",
  "\u{1D73B}": "\u03B6",
  "\u{1D775}": "\u03B6",
  "\u{1D7AF}": "\u03B6",
  "\u2CE4": "\u03D7",
  "\u{1D6CC}": "\u03BB",
  "\u{1D706}": "\u03BB",
  "\u{1D740}": "\u03BB",
  "\u{1D77A}": "\u03BB",
  "\u{1D7B4}": "\u03BB",
  "\u2C96": "\u03BB",
  "\u{104DB}": "\u03BB",
  "\xB5": "\u03BC",
  "\u{1D6CD}": "\u03BC",
  "\u{1D707}": "\u03BC",
  "\u{1D741}": "\u03BC",
  "\u{1D77B}": "\u03BC",
  "\u{1D7B5}": "\u03BC",
  "\u{1D6CF}": "\u03BE",
  "\u{1D709}": "\u03BE",
  "\u{1D743}": "\u03BE",
  "\u{1D77D}": "\u03BE",
  "\u{1D7B7}": "\u03BE",
  "\u{1D6B5}": "\u039E",
  "\u{1D6EF}": "\u039E",
  "\u{1D729}": "\u039E",
  "\u{1D763}": "\u039E",
  "\u{1D79D}": "\u039E",
  "\u03D6": "\u03C0",
  "\u213C": "\u03C0",
  "\u{1D6D1}": "\u03C0",
  "\u{1D6E1}": "\u03C0",
  "\u{1D70B}": "\u03C0",
  "\u{1D71B}": "\u03C0",
  "\u{1D745}": "\u03C0",
  "\u{1D755}": "\u03C0",
  "\u{1D77F}": "\u03C0",
  "\u{1D78F}": "\u03C0",
  "\u{1D7B9}": "\u03C0",
  "\u{1D7C9}": "\u03C0",
  "\u1D28": "\u03C0",
  "\u043F": "\u03C0",
  "\u220F": "\u03A0",
  "\u213F": "\u03A0",
  "\u{1D6B7}": "\u03A0",
  "\u{1D6F1}": "\u03A0",
  "\u{1D72B}": "\u03A0",
  "\u{1D765}": "\u03A0",
  "\u{1D79F}": "\u03A0",
  "\u2CA0": "\u03A0",
  "\u041F": "\u03A0",
  "\uA6DB": "\u03A0",
  "\u{102AD}": "\u03D8",
  "\u{10312}": "\u03D8",
  "\u03DB": "\u03C2",
  "\u{1D6D3}": "\u03C2",
  "\u{1D70D}": "\u03C2",
  "\u{1D747}": "\u03C2",
  "\u{1D781}": "\u03C2",
  "\u{1D7BB}": "\u03C2",
  "\u{1D6BD}": "\u03A6",
  "\u{1D6F7}": "\u03A6",
  "\u{1D731}": "\u03A6",
  "\u{1D76B}": "\u03A6",
  "\u{1D7A5}": "\u03A6",
  "\u2CAA": "\u03A6",
  "\u0424": "\u03A6",
  "\u0553": "\u03A6",
  "\u1240": "\u03A6",
  "\u16F0": "\u03A6",
  "\u{102B3}": "\u03A6",
  "\uAB53": "\u03C7",
  "\uAB55": "\u03C7",
  "\u{1D6D8}": "\u03C7",
  "\u{1D712}": "\u03C7",
  "\u{1D74C}": "\u03C7",
  "\u{1D786}": "\u03C7",
  "\u{1D7C0}": "\u03C7",
  "\u2CAD": "\u03C7",
  "\u{1D6D9}": "\u03C8",
  "\u{1D713}": "\u03C8",
  "\u{1D74D}": "\u03C8",
  "\u{1D787}": "\u03C8",
  "\u{1D7C1}": "\u03C8",
  "\u0471": "\u03C8",
  "\u{104F9}": "\u03C8",
  "\u{1D6BF}": "\u03A8",
  "\u{1D6F9}": "\u03A8",
  "\u{1D733}": "\u03A8",
  "\u{1D76D}": "\u03A8",
  "\u{1D7A7}": "\u03A8",
  "\u2CAE": "\u03A8",
  "\u0470": "\u03A8",
  "\u{104D1}": "\u03A8",
  "\u16D8": "\u03A8",
  "\u{102B5}": "\u03A8",
  "\u2375": "\u03C9",
  "\uA7B7": "\u03C9",
  "\u{1D6DA}": "\u03C9",
  "\u{1D714}": "\u03C9",
  "\u{1D74E}": "\u03C9",
  "\u{1D788}": "\u03C9",
  "\u{1D7C2}": "\u03C9",
  "\u2CB1": "\u03C9",
  "\uA64D": "\u03C9",
  "\u2126": "\u03A9",
  "\u{1D6C0}": "\u03A9",
  "\u{1D6FA}": "\u03A9",
  "\u{1D734}": "\u03A9",
  "\u{1D76E}": "\u03A9",
  "\u{1D7A8}": "\u03A9",
  "\u162F": "\u03A9",
  "\u1635": "\u03A9",
  "\u{102B6}": "\u03A9",
  "\u2379": "\u03C9\u0332",
  "\u1F7D": "\u1FF4",
  "\u2630": "\u2CB6",
  "\u2CDC": "\u03EC",
  "\u0497": "\u0436\u0329",
  "\u0496": "\u0416\u0329",
  "\u{1D20B}": "\u0418",
  "\u0376": "\u0418",
  "\uA6A1": "\u0418",
  "\u{10425}": "\u0418",
  "\u0419": "\u040D",
  "\u048A": "\u040D\u0326",
  "\u045D": "\u0439",
  "\u048B": "\u0439\u0326",
  "\u{104BC}": "\u04C3",
  "\u1D2B": "\u043B",
  "\u04C6": "\u043B\u0326",
  "\uAB60": "\u0459",
  "\u{104EB}": "\uA669",
  "\u1DEE": "\u2DEC",
  "\u{104CD}": "\u040B",
  "\u{1D202}": "\u04FE",
  "\u{1D222}": "\u0460",
  "\u13C7": "\u0460",
  "\u15EF": "\u0460",
  "\u047C": "\u0460\u0486\u0487",
  "\u18ED": "\u0460\xB7",
  "\uA7B6": "\uA64C",
  "\u04CC": "\u04B7",
  "\u04CB": "\u04B6",
  "\u04BE": "\u04BC\u0328",
  "\u2CBD": "\u0448",
  "\u2CBC": "\u0428",
  "\uA650": "\u042Al",
  "\u2108": "\u042D",
  "\u{1F701}": "\uA658",
  "\u{16F1C}": "\uA658",
  "\uA992": "\u2C3F",
  "\u0587": "\u0565\u0582",
  "\u1294": "\u0571",
  "\uFB14": "\u0574\u0565",
  "\uFB15": "\u0574\u056B",
  "\uFB17": "\u0574\u056D",
  "\uFB13": "\u0574\u0576",
  "\u2229": "\u0548",
  "\u22C2": "\u0548",
  "\u{1D245}": "\u0548",
  "\u1260": "\u0548",
  "\u144E": "\u0548",
  "\uA4F5": "\u0548",
  "\u145A": "\u0548\xB7",
  "\u1468": "\u0548'",
  "\uFB16": "\u057E\u0576",
  "\u20BD": "\u0554",
  "\u02D3": "\u0559",
  "\u02BF": "\u0559",
  "\u2135": "\u05D0",
  "\uFB21": "\u05D0",
  "\uFB2F": "\uFB2E",
  "\uFB30": "\uFB2E",
  "\uFB4F": "\u05D0\u05DC",
  "\u2136": "\u05D1",
  "\u2137": "\u05D2",
  "\u2138": "\u05D3",
  "\uFB22": "\u05D3",
  "\uFB23": "\u05D4",
  "\uFB39": "\uFB1D",
  "\uFB24": "\u05DB",
  "\uFB25": "\u05DC",
  "\uFB26": "\u05DD",
  "\uFB20": "\u05E2",
  "\uFB27": "\u05E8",
  "\uFB2B": "\uFB2A",
  "\uFB49": "\uFB2A",
  "\uFB2D": "\uFB2C",
  "\uFB28": "\u05EA",
  "\uFE80": "\u0621",
  "\u06FD": "\u0621\u0348",
  "\uFE82": "\u0622",
  "\uFE81": "\u0622",
  "\uFB51": "\u0671",
  "\uFB50": "\u0671",
  "\u{1EE01}": "\u0628",
  "\u{1EE21}": "\u0628",
  "\u{1EE61}": "\u0628",
  "\u{1EE81}": "\u0628",
  "\u{1EEA1}": "\u0628",
  "\uFE91": "\u0628",
  "\uFE92": "\u0628",
  "\uFE90": "\u0628",
  "\uFE8F": "\u0628",
  "\u0751": "\u0628\u06DB",
  "\u08B6": "\u0628\u06E2",
  "\u08A1": "\u0628\u0654",
  "\uFCA0": "\u0628o",
  "\uFCE2": "\u0628o",
  "\uFC9C": "\u0628\u062C",
  "\uFC05": "\u0628\u062C",
  "\uFC9D": "\u0628\u062D",
  "\uFC06": "\u0628\u062D",
  "\uFDC2": "\u0628\u062D\u0649",
  "\uFC9E": "\u0628\u062E",
  "\uFC07": "\u0628\u062E",
  "\uFCD2": "\u0628\u062E",
  "\uFC4B": "\u0628\u062E",
  "\uFD9E": "\u0628\u062E\u0649",
  "\uFC6A": "\u0628\u0631",
  "\uFC6B": "\u0628\u0632",
  "\uFC9F": "\u0628\u0645",
  "\uFCE1": "\u0628\u0645",
  "\uFC6C": "\u0628\u0645",
  "\uFC08": "\u0628\u0645",
  "\uFC6D": "\u0628\u0646",
  "\uFC6E": "\u0628\u0649",
  "\uFC09": "\u0628\u0649",
  "\uFC6F": "\u0628\u0649",
  "\uFC0A": "\u0628\u0649",
  "\uFB54": "\u067B",
  "\uFB55": "\u067B",
  "\uFB53": "\u067B",
  "\uFB52": "\u067B",
  "\u06D0": "\u067B",
  "\uFBE6": "\u067B",
  "\uFBE7": "\u067B",
  "\uFBE5": "\u067B",
  "\uFBE4": "\u067B",
  "\uFB5C": "\u0680",
  "\uFB5D": "\u0680",
  "\uFB5B": "\u0680",
  "\uFB5A": "\u0680",
  "\u08A9": "\u0754",
  "\u0767": "\u0754",
  "\u2365": "\u0629",
  "\xF6": "\u0629",
  "\uFE94": "\u0629",
  "\uFE93": "\u0629",
  "\u06C3": "\u0629",
  "\u{1EE15}": "\u062A",
  "\u{1EE35}": "\u062A",
  "\u{1EE75}": "\u062A",
  "\u{1EE95}": "\u062A",
  "\u{1EEB5}": "\u062A",
  "\uFE97": "\u062A",
  "\uFE98": "\u062A",
  "\uFE96": "\u062A",
  "\uFE95": "\u062A",
  "\uFCA5": "\u062Ao",
  "\uFCE4": "\u062Ao",
  "\uFCA1": "\u062A\u062C",
  "\uFC0B": "\u062A\u062C",
  "\uFD50": "\u062A\u062C\u0645",
  "\uFDA0": "\u062A\u062C\u0649",
  "\uFD9F": "\u062A\u062C\u0649",
  "\uFCA2": "\u062A\u062D",
  "\uFC0C": "\u062A\u062D",
  "\uFD52": "\u062A\u062D\u062C",
  "\uFD51": "\u062A\u062D\u062C",
  "\uFD53": "\u062A\u062D\u0645",
  "\uFCA3": "\u062A\u062E",
  "\uFC0D": "\u062A\u062E",
  "\uFD54": "\u062A\u062E\u0645",
  "\uFDA2": "\u062A\u062E\u0649",
  "\uFDA1": "\u062A\u062E\u0649",
  "\uFC70": "\u062A\u0631",
  "\uFC71": "\u062A\u0632",
  "\uFCA4": "\u062A\u0645",
  "\uFCE3": "\u062A\u0645",
  "\uFC72": "\u062A\u0645",
  "\uFC0E": "\u062A\u0645",
  "\uFD55": "\u062A\u0645\u062C",
  "\uFD56": "\u062A\u0645\u062D",
  "\uFD57": "\u062A\u0645\u062E",
  "\uFDA4": "\u062A\u0645\u0649",
  "\uFDA3": "\u062A\u0645\u0649",
  "\uFC73": "\u062A\u0646",
  "\uFC74": "\u062A\u0649",
  "\uFC0F": "\u062A\u0649",
  "\uFC75": "\u062A\u0649",
  "\uFC10": "\u062A\u0649",
  "\uFB60": "\u067A",
  "\uFB61": "\u067A",
  "\uFB5F": "\u067A",
  "\uFB5E": "\u067A",
  "\uFB64": "\u067F",
  "\uFB65": "\u067F",
  "\uFB63": "\u067F",
  "\uFB62": "\u067F",
  "\u{1EE02}": "\u062C",
  "\u{1EE22}": "\u062C",
  "\u{1EE42}": "\u062C",
  "\u{1EE62}": "\u062C",
  "\u{1EE82}": "\u062C",
  "\u{1EEA2}": "\u062C",
  "\uFE9F": "\u062C",
  "\uFEA0": "\u062C",
  "\uFE9E": "\u062C",
  "\uFE9D": "\u062C",
  "\uFCA7": "\u062C\u062D",
  "\uFC15": "\u062C\u062D",
  "\uFDA6": "\u062C\u062D\u0649",
  "\uFDBE": "\u062C\u062D\u0649",
  "\uFDFB": "\u062C\u0644 \u062C\u0644l\u0644o",
  "\uFCA8": "\u062C\u0645",
  "\uFC16": "\u062C\u0645",
  "\uFD59": "\u062C\u0645\u062D",
  "\uFD58": "\u062C\u0645\u062D",
  "\uFDA7": "\u062C\u0645\u0649",
  "\uFDA5": "\u062C\u0645\u0649",
  "\uFD1D": "\u062C\u0649",
  "\uFD01": "\u062C\u0649",
  "\uFD1E": "\u062C\u0649",
  "\uFD02": "\u062C\u0649",
  "\uFB78": "\u0683",
  "\uFB79": "\u0683",
  "\uFB77": "\u0683",
  "\uFB76": "\u0683",
  "\uFB74": "\u0684",
  "\uFB75": "\u0684",
  "\uFB73": "\u0684",
  "\uFB72": "\u0684",
  "\uFB7C": "\u0686",
  "\uFB7D": "\u0686",
  "\uFB7B": "\u0686",
  "\uFB7A": "\u0686",
  "\uFB80": "\u0687",
  "\uFB81": "\u0687",
  "\uFB7F": "\u0687",
  "\uFB7E": "\u0687",
  "\u{1EE07}": "\u062D",
  "\u{1EE27}": "\u062D",
  "\u{1EE47}": "\u062D",
  "\u{1EE67}": "\u062D",
  "\u{1EE87}": "\u062D",
  "\u{1EEA7}": "\u062D",
  "\uFEA3": "\u062D",
  "\uFEA4": "\u062D",
  "\uFEA2": "\u062D",
  "\uFEA1": "\u062D",
  "\u0685": "\u062D\u06DB",
  "\u0681": "\u062D\u0654",
  "\u0772": "\u062D\u0654",
  "\uFCA9": "\u062D\u062C",
  "\uFC17": "\u062D\u062C",
  "\uFDBF": "\u062D\u062C\u0649",
  "\uFCAA": "\u062D\u0645",
  "\uFC18": "\u062D\u0645",
  "\uFD5B": "\u062D\u0645\u0649",
  "\uFD5A": "\u062D\u0645\u0649",
  "\uFD1B": "\u062D\u0649",
  "\uFCFF": "\u062D\u0649",
  "\uFD1C": "\u062D\u0649",
  "\uFD00": "\u062D\u0649",
  "\u{1EE17}": "\u062E",
  "\u{1EE37}": "\u062E",
  "\u{1EE57}": "\u062E",
  "\u{1EE77}": "\u062E",
  "\u{1EE97}": "\u062E",
  "\u{1EEB7}": "\u062E",
  "\uFEA7": "\u062E",
  "\uFEA8": "\u062E",
  "\uFEA6": "\u062E",
  "\uFEA5": "\u062E",
  "\uFCAB": "\u062E\u062C",
  "\uFC19": "\u062E\u062C",
  "\uFC1A": "\u062E\u062D",
  "\uFCAC": "\u062E\u0645",
  "\uFC1B": "\u062E\u0645",
  "\uFD1F": "\u062E\u0649",
  "\uFD03": "\u062E\u0649",
  "\uFD20": "\u062E\u0649",
  "\uFD04": "\u062E\u0649",
  "\u{102E1}": "\u062F",
  "\u{1EE03}": "\u062F",
  "\u{1EE83}": "\u062F",
  "\u{1EEA3}": "\u062F",
  "\uFEAA": "\u062F",
  "\uFEA9": "\u062F",
  "\u0688": "\u062F\u0615",
  "\uFB89": "\u062F\u0615",
  "\uFB88": "\u062F\u0615",
  "\u068E": "\u062F\u06DB",
  "\uFB87": "\u062F\u06DB",
  "\uFB86": "\u062F\u06DB",
  "\u06EE": "\u062F\u0302",
  "\u08AE": "\u062F\u0324\u0323",
  "\u{1EE18}": "\u0630",
  "\u{1EE98}": "\u0630",
  "\u{1EEB8}": "\u0630",
  "\uFEAC": "\u0630",
  "\uFEAB": "\u0630",
  "\uFC5B": "\u0630\u0670",
  "\u068B": "\u068A\u0615",
  "\uFB85": "\u068C",
  "\uFB84": "\u068C",
  "\uFB83": "\u068D",
  "\uFB82": "\u068D",
  "\u{1EE13}": "\u0631",
  "\u{1EE93}": "\u0631",
  "\u{1EEB3}": "\u0631",
  "\uFEAE": "\u0631",
  "\uFEAD": "\u0631",
  "\u0691": "\u0631\u0615",
  "\uFB8D": "\u0631\u0615",
  "\uFB8C": "\u0631\u0615",
  "\u0698": "\u0631\u06DB",
  "\uFB8B": "\u0631\u06DB",
  "\uFB8A": "\u0631\u06DB",
  "\u0692": "\u0631\u0306",
  "\u08B9": "\u0631\u0306\u0307",
  "\u06EF": "\u0631\u0302",
  "\u076C": "\u0631\u0654",
  "\uFC5C": "\u0631\u0670",
  "\uFDF6": "\u0631\u0633\u0648\u0644",
  "\uFDFC": "\u0631\u0649l\u0644",
  "\u{1EE06}": "\u0632",
  "\u{1EE86}": "\u0632",
  "\u{1EEA6}": "\u0632",
  "\uFEB0": "\u0632",
  "\uFEAF": "\u0632",
  "\u08B2": "\u0632\u0302",
  "\u0771": "\u0697\u0615",
  "\u{1EE0E}": "\u0633",
  "\u{1EE2E}": "\u0633",
  "\u{1EE4E}": "\u0633",
  "\u{1EE6E}": "\u0633",
  "\u{1EE8E}": "\u0633",
  "\u{1EEAE}": "\u0633",
  "\uFEB3": "\u0633",
  "\uFEB4": "\u0633",
  "\uFEB2": "\u0633",
  "\uFEB1": "\u0633",
  "\u0634": "\u0633\u06DB",
  "\u{1EE14}": "\u0633\u06DB",
  "\u{1EE34}": "\u0633\u06DB",
  "\u{1EE54}": "\u0633\u06DB",
  "\u{1EE74}": "\u0633\u06DB",
  "\u{1EE94}": "\u0633\u06DB",
  "\u{1EEB4}": "\u0633\u06DB",
  "\uFEB7": "\u0633\u06DB",
  "\uFEB8": "\u0633\u06DB",
  "\uFEB6": "\u0633\u06DB",
  "\uFEB5": "\u0633\u06DB",
  "\u077E": "\u0633\u0302",
  "\uFD31": "\u0633o",
  "\uFCE8": "\u0633o",
  "\uFD32": "\u0633\u06DBo",
  "\uFCEA": "\u0633\u06DBo",
  "\uFCAD": "\u0633\u062C",
  "\uFD34": "\u0633\u062C",
  "\uFC1C": "\u0633\u062C",
  "\uFD2D": "\u0633\u06DB\u062C",
  "\uFD37": "\u0633\u06DB\u062C",
  "\uFD25": "\u0633\u06DB\u062C",
  "\uFD09": "\u0633\u06DB\u062C",
  "\uFD5D": "\u0633\u062C\u062D",
  "\uFD5E": "\u0633\u062C\u0649",
  "\uFD69": "\u0633\u06DB\u062C\u0649",
  "\uFCAE": "\u0633\u062D",
  "\uFD35": "\u0633\u062D",
  "\uFC1D": "\u0633\u062D",
  "\uFD2E": "\u0633\u06DB\u062D",
  "\uFD38": "\u0633\u06DB\u062D",
  "\uFD26": "\u0633\u06DB\u062D",
  "\uFD0A": "\u0633\u06DB\u062D",
  "\uFD5C": "\u0633\u062D\u062C",
  "\uFD68": "\u0633\u06DB\u062D\u0645",
  "\uFD67": "\u0633\u06DB\u062D\u0645",
  "\uFDAA": "\u0633\u06DB\u062D\u0649",
  "\uFCAF": "\u0633\u062E",
  "\uFD36": "\u0633\u062E",
  "\uFC1E": "\u0633\u062E",
  "\uFD2F": "\u0633\u06DB\u062E",
  "\uFD39": "\u0633\u06DB\u062E",
  "\uFD27": "\u0633\u06DB\u062E",
  "\uFD0B": "\u0633\u06DB\u062E",
  "\uFDA8": "\u0633\u062E\u0649",
  "\uFDC6": "\u0633\u062E\u0649",
  "\uFD2A": "\u0633\u0631",
  "\uFD0E": "\u0633\u0631",
  "\uFD29": "\u0633\u06DB\u0631",
  "\uFD0D": "\u0633\u06DB\u0631",
  "\uFCB0": "\u0633\u0645",
  "\uFCE7": "\u0633\u0645",
  "\uFC1F": "\u0633\u0645",
  "\uFD30": "\u0633\u06DB\u0645",
  "\uFCE9": "\u0633\u06DB\u0645",
  "\uFD28": "\u0633\u06DB\u0645",
  "\uFD0C": "\u0633\u06DB\u0645",
  "\uFD61": "\u0633\u0645\u062C",
  "\uFD60": "\u0633\u0645\u062D",
  "\uFD5F": "\u0633\u0645\u062D",
  "\uFD6B": "\u0633\u06DB\u0645\u062E",
  "\uFD6A": "\u0633\u06DB\u0645\u062E",
  "\uFD63": "\u0633\u0645\u0645",
  "\uFD62": "\u0633\u0645\u0645",
  "\uFD6D": "\u0633\u06DB\u0645\u0645",
  "\uFD6C": "\u0633\u06DB\u0645\u0645",
  "\uFD17": "\u0633\u0649",
  "\uFCFB": "\u0633\u0649",
  "\uFD18": "\u0633\u0649",
  "\uFCFC": "\u0633\u0649",
  "\uFD19": "\u0633\u06DB\u0649",
  "\uFCFD": "\u0633\u06DB\u0649",
  "\uFD1A": "\u0633\u06DB\u0649",
  "\uFCFE": "\u0633\u06DB\u0649",
  "\u{102F2}": "\u0635",
  "\u{1EE11}": "\u0635",
  "\u{1EE31}": "\u0635",
  "\u{1EE51}": "\u0635",
  "\u{1EE71}": "\u0635",
  "\u{1EE91}": "\u0635",
  "\u{1EEB1}": "\u0635",
  "\uFEBB": "\u0635",
  "\uFEBC": "\u0635",
  "\uFEBA": "\u0635",
  "\uFEB9": "\u0635",
  "\u069E": "\u0635\u06DB",
  "\u08AF": "\u0635\u0324\u0323",
  "\uFCB1": "\u0635\u062D",
  "\uFC20": "\u0635\u062D",
  "\uFD65": "\u0635\u062D\u062D",
  "\uFD64": "\u0635\u062D\u062D",
  "\uFDA9": "\u0635\u062D\u0649",
  "\uFCB2": "\u0635\u062E",
  "\uFD2B": "\u0635\u0631",
  "\uFD0F": "\u0635\u0631",
  "\uFDF5": "\u0635\u0644\u0639\u0645",
  "\uFDF9": "\u0635\u0644\u0649",
  "\uFDF0": "\u0635\u0644\u0649",
  "\uFDFA": "\u0635\u0644\u0649 l\u0644\u0644o \u0639\u0644\u0649o \u0648\u0633\u0644\u0645",
  "\uFCB3": "\u0635\u0645",
  "\uFC21": "\u0635\u0645",
  "\uFDC5": "\u0635\u0645\u0645",
  "\uFD66": "\u0635\u0645\u0645",
  "\uFD21": "\u0635\u0649",
  "\uFD05": "\u0635\u0649",
  "\uFD22": "\u0635\u0649",
  "\uFD06": "\u0635\u0649",
  "\u{1EE19}": "\u0636",
  "\u{1EE39}": "\u0636",
  "\u{1EE59}": "\u0636",
  "\u{1EE79}": "\u0636",
  "\u{1EE99}": "\u0636",
  "\u{1EEB9}": "\u0636",
  "\uFEBF": "\u0636",
  "\uFEC0": "\u0636",
  "\uFEBE": "\u0636",
  "\uFEBD": "\u0636",
  "\uFCB4": "\u0636\u062C",
  "\uFC22": "\u0636\u062C",
  "\uFCB5": "\u0636\u062D",
  "\uFC23": "\u0636\u062D",
  "\uFD6E": "\u0636\u062D\u0649",
  "\uFDAB": "\u0636\u062D\u0649",
  "\uFCB6": "\u0636\u062E",
  "\uFC24": "\u0636\u062E",
  "\uFD70": "\u0636\u062E\u0645",
  "\uFD6F": "\u0636\u062E\u0645",
  "\uFD2C": "\u0636\u0631",
  "\uFD10": "\u0636\u0631",
  "\uFCB7": "\u0636\u0645",
  "\uFC25": "\u0636\u0645",
  "\uFD23": "\u0636\u0649",
  "\uFD07": "\u0636\u0649",
  "\uFD24": "\u0636\u0649",
  "\uFD08": "\u0636\u0649",
  "\u{102E8}": "\u0637",
  "\u{1EE08}": "\u0637",
  "\u{1EE68}": "\u0637",
  "\u{1EE88}": "\u0637",
  "\u{1EEA8}": "\u0637",
  "\uFEC3": "\u0637",
  "\uFEC4": "\u0637",
  "\uFEC2": "\u0637",
  "\uFEC1": "\u0637",
  "\u069F": "\u0637\u06DB",
  "\uFCB8": "\u0637\u062D",
  "\uFC26": "\u0637\u062D",
  "\uFD33": "\u0637\u0645",
  "\uFD3A": "\u0637\u0645",
  "\uFC27": "\u0637\u0645",
  "\uFD72": "\u0637\u0645\u062D",
  "\uFD71": "\u0637\u0645\u062D",
  "\uFD73": "\u0637\u0645\u0645",
  "\uFD74": "\u0637\u0645\u0649",
  "\uFD11": "\u0637\u0649",
  "\uFCF5": "\u0637\u0649",
  "\uFD12": "\u0637\u0649",
  "\uFCF6": "\u0637\u0649",
  "\u{1EE1A}": "\u0638",
  "\u{1EE7A}": "\u0638",
  "\u{1EE9A}": "\u0638",
  "\u{1EEBA}": "\u0638",
  "\uFEC7": "\u0638",
  "\uFEC8": "\u0638",
  "\uFEC6": "\u0638",
  "\uFEC5": "\u0638",
  "\uFCB9": "\u0638\u0645",
  "\uFD3B": "\u0638\u0645",
  "\uFC28": "\u0638\u0645",
  "\u060F": "\u0639",
  "\u{1EE0F}": "\u0639",
  "\u{1EE2F}": "\u0639",
  "\u{1EE4F}": "\u0639",
  "\u{1EE6F}": "\u0639",
  "\u{1EE8F}": "\u0639",
  "\u{1EEAF}": "\u0639",
  "\uFECB": "\u0639",
  "\uFECC": "\u0639",
  "\uFECA": "\u0639",
  "\uFEC9": "\u0639",
  "\uFCBA": "\u0639\u062C",
  "\uFC29": "\u0639\u062C",
  "\uFDC4": "\u0639\u062C\u0645",
  "\uFD75": "\u0639\u062C\u0645",
  "\uFDF7": "\u0639\u0644\u0649o",
  "\uFCBB": "\u0639\u0645",
  "\uFC2A": "\u0639\u0645",
  "\uFD77": "\u0639\u0645\u0645",
  "\uFD76": "\u0639\u0645\u0645",
  "\uFD78": "\u0639\u0645\u0649",
  "\uFDB6": "\u0639\u0645\u0649",
  "\uFD13": "\u0639\u0649",
  "\uFCF7": "\u0639\u0649",
  "\uFD14": "\u0639\u0649",
  "\uFCF8": "\u0639\u0649",
  "\u{1EE1B}": "\u063A",
  "\u{1EE3B}": "\u063A",
  "\u{1EE5B}": "\u063A",
  "\u{1EE7B}": "\u063A",
  "\u{1EE9B}": "\u063A",
  "\u{1EEBB}": "\u063A",
  "\uFECF": "\u063A",
  "\uFED0": "\u063A",
  "\uFECE": "\u063A",
  "\uFECD": "\u063A",
  "\uFCBC": "\u063A\u062C",
  "\uFC2B": "\u063A\u062C",
  "\uFCBD": "\u063A\u0645",
  "\uFC2C": "\u063A\u0645",
  "\uFD79": "\u063A\u0645\u0645",
  "\uFD7B": "\u063A\u0645\u0649",
  "\uFD7A": "\u063A\u0645\u0649",
  "\uFD15": "\u063A\u0649",
  "\uFCF9": "\u063A\u0649",
  "\uFD16": "\u063A\u0649",
  "\uFCFA": "\u063A\u0649",
  "\u{1EE10}": "\u0641",
  "\u{1EE30}": "\u0641",
  "\u{1EE70}": "\u0641",
  "\u{1EE90}": "\u0641",
  "\u{1EEB0}": "\u0641",
  "\uFED3": "\u0641",
  "\uFED4": "\u0641",
  "\uFED2": "\u0641",
  "\uFED1": "\u0641",
  "\u06A7": "\u0641",
  "\uFCBE": "\u0641\u062C",
  "\uFC2D": "\u0641\u062C",
  "\uFCBF": "\u0641\u062D",
  "\uFC2E": "\u0641\u062D",
  "\uFCC0": "\u0641\u062E",
  "\uFC2F": "\u0641\u062E",
  "\uFD7D": "\u0641\u062E\u0645",
  "\uFD7C": "\u0641\u062E\u0645",
  "\uFCC1": "\u0641\u0645",
  "\uFC30": "\u0641\u0645",
  "\uFDC1": "\u0641\u0645\u0649",
  "\uFC7C": "\u0641\u0649",
  "\uFC31": "\u0641\u0649",
  "\uFC7D": "\u0641\u0649",
  "\uFC32": "\u0641\u0649",
  "\u{1EE1E}": "\u06A1",
  "\u{1EE7E}": "\u06A1",
  "\u08BB": "\u06A1",
  "\u066F": "\u06A1",
  "\u{1EE1F}": "\u06A1",
  "\u{1EE5F}": "\u06A1",
  "\u08BC": "\u06A1",
  "\u06A4": "\u06A1\u06DB",
  "\uFB6C": "\u06A1\u06DB",
  "\uFB6D": "\u06A1\u06DB",
  "\uFB6B": "\u06A1\u06DB",
  "\uFB6A": "\u06A1\u06DB",
  "\u06A8": "\u06A1\u06DB",
  "\u08A4": "\u06A2\u06DB",
  "\uFB70": "\u06A6",
  "\uFB71": "\u06A6",
  "\uFB6F": "\u06A6",
  "\uFB6E": "\u06A6",
  "\u{1EE12}": "\u0642",
  "\u{1EE32}": "\u0642",
  "\u{1EE52}": "\u0642",
  "\u{1EE72}": "\u0642",
  "\u{1EE92}": "\u0642",
  "\u{1EEB2}": "\u0642",
  "\uFED7": "\u0642",
  "\uFED8": "\u0642",
  "\uFED6": "\u0642",
  "\uFED5": "\u0642",
  "\uFCC2": "\u0642\u062D",
  "\uFC33": "\u0642\u062D",
  "\uFDF1": "\u0642\u0644\u0649",
  "\uFCC3": "\u0642\u0645",
  "\uFC34": "\u0642\u0645",
  "\uFDB4": "\u0642\u0645\u062D",
  "\uFD7E": "\u0642\u0645\u062D",
  "\uFD7F": "\u0642\u0645\u0645",
  "\uFDB2": "\u0642\u0645\u0649",
  "\uFC7E": "\u0642\u0649",
  "\uFC35": "\u0642\u0649",
  "\uFC7F": "\u0642\u0649",
  "\uFC36": "\u0642\u0649",
  "\u{1EE0A}": "\u0643",
  "\u{1EE2A}": "\u0643",
  "\u{1EE6A}": "\u0643",
  "\uFEDB": "\u0643",
  "\uFEDC": "\u0643",
  "\uFEDA": "\u0643",
  "\uFED9": "\u0643",
  "\u06A9": "\u0643",
  "\uFB90": "\u0643",
  "\uFB91": "\u0643",
  "\uFB8F": "\u0643",
  "\uFB8E": "\u0643",
  "\u06AA": "\u0643",
  "\u06AD": "\u0643\u06DB",
  "\uFBD5": "\u0643\u06DB",
  "\uFBD6": "\u0643\u06DB",
  "\uFBD4": "\u0643\u06DB",
  "\uFBD3": "\u0643\u06DB",
  "\u0763": "\u0643\u06DB",
  "\uFC80": "\u0643l",
  "\uFC37": "\u0643l",
  "\uFCC4": "\u0643\u062C",
  "\uFC38": "\u0643\u062C",
  "\uFCC5": "\u0643\u062D",
  "\uFC39": "\u0643\u062D",
  "\uFCC6": "\u0643\u062E",
  "\uFC3A": "\u0643\u062E",
  "\uFCC7": "\u0643\u0644",
  "\uFCEB": "\u0643\u0644",
  "\uFC81": "\u0643\u0644",
  "\uFC3B": "\u0643\u0644",
  "\uFCC8": "\u0643\u0645",
  "\uFCEC": "\u0643\u0645",
  "\uFC82": "\u0643\u0645",
  "\uFC3C": "\u0643\u0645",
  "\uFDC3": "\u0643\u0645\u0645",
  "\uFDBB": "\u0643\u0645\u0645",
  "\uFDB7": "\u0643\u0645\u0649",
  "\uFC83": "\u0643\u0649",
  "\uFC3D": "\u0643\u0649",
  "\uFC84": "\u0643\u0649",
  "\uFC3E": "\u0643\u0649",
  "\u0762": "\u06AC",
  "\uFB94": "\u06AF",
  "\uFB95": "\u06AF",
  "\uFB93": "\u06AF",
  "\uFB92": "\u06AF",
  "\u08B0": "\u06AF",
  "\u06B4": "\u06AF\u06DB",
  "\uFB9C": "\u06B1",
  "\uFB9D": "\u06B1",
  "\uFB9B": "\u06B1",
  "\uFB9A": "\u06B1",
  "\uFB98": "\u06B3",
  "\uFB99": "\u06B3",
  "\uFB97": "\u06B3",
  "\uFB96": "\u06B3",
  "\u{1EE0B}": "\u0644",
  "\u{1EE2B}": "\u0644",
  "\u{1EE4B}": "\u0644",
  "\u{1EE8B}": "\u0644",
  "\u{1EEAB}": "\u0644",
  "\uFEDF": "\u0644",
  "\uFEE0": "\u0644",
  "\uFEDE": "\u0644",
  "\uFEDD": "\u0644",
  "\u06B7": "\u0644\u06DB",
  "\u06B5": "\u0644\u0306",
  "\uFEFC": "\u0644l",
  "\uFEFB": "\u0644l",
  "\uFEFA": "\u0644l\u0655",
  "\uFEF9": "\u0644l\u0655",
  "\uFEF8": "\u0644l\u0674",
  "\uFEF7": "\u0644l\u0674",
  "\uFCCD": "\u0644o",
  "\uFEF6": "\u0644\u0622",
  "\uFEF5": "\u0644\u0622",
  "\uFCC9": "\u0644\u062C",
  "\uFC3F": "\u0644\u062C",
  "\uFD83": "\u0644\u062C\u062C",
  "\uFD84": "\u0644\u062C\u062C",
  "\uFDBA": "\u0644\u062C\u0645",
  "\uFDBC": "\u0644\u062C\u0645",
  "\uFDAC": "\u0644\u062C\u0649",
  "\uFCCA": "\u0644\u062D",
  "\uFC40": "\u0644\u062D",
  "\uFDB5": "\u0644\u062D\u0645",
  "\uFD80": "\u0644\u062D\u0645",
  "\uFD82": "\u0644\u062D\u0649",
  "\uFD81": "\u0644\u062D\u0649",
  "\uFCCB": "\u0644\u062E",
  "\uFC41": "\u0644\u062E",
  "\uFD86": "\u0644\u062E\u0645",
  "\uFD85": "\u0644\u062E\u0645",
  "\uFCCC": "\u0644\u0645",
  "\uFCED": "\u0644\u0645",
  "\uFC85": "\u0644\u0645",
  "\uFC42": "\u0644\u0645",
  "\uFD88": "\u0644\u0645\u062D",
  "\uFD87": "\u0644\u0645\u062D",
  "\uFDAD": "\u0644\u0645\u0649",
  "\uFC86": "\u0644\u0649",
  "\uFC43": "\u0644\u0649",
  "\uFC87": "\u0644\u0649",
  "\uFC44": "\u0644\u0649",
  "\u{1EE0C}": "\u0645",
  "\u{1EE2C}": "\u0645",
  "\u{1EE6C}": "\u0645",
  "\u{1EE8C}": "\u0645",
  "\u{1EEAC}": "\u0645",
  "\uFEE3": "\u0645",
  "\uFEE4": "\u0645",
  "\uFEE2": "\u0645",
  "\uFEE1": "\u0645",
  "\u08A7": "\u0645\u06DB",
  "\u06FE": "\u0645\u0348",
  "\uFC88": "\u0645l",
  "\uFCCE": "\u0645\u062C",
  "\uFC45": "\u0645\u062C",
  "\uFD8C": "\u0645\u062C\u062D",
  "\uFD92": "\u0645\u062C\u062E",
  "\uFD8D": "\u0645\u062C\u0645",
  "\uFDC0": "\u0645\u062C\u0649",
  "\uFCCF": "\u0645\u062D",
  "\uFC46": "\u0645\u062D",
  "\uFD89": "\u0645\u062D\u062C",
  "\uFD8A": "\u0645\u062D\u0645",
  "\uFDF4": "\u0645\u062D\u0645\u062F",
  "\uFD8B": "\u0645\u062D\u0649",
  "\uFCD0": "\u0645\u062E",
  "\uFC47": "\u0645\u062E",
  "\uFD8E": "\u0645\u062E\u062C",
  "\uFD8F": "\u0645\u062E\u0645",
  "\uFDB9": "\u0645\u062E\u0649",
  "\uFCD1": "\u0645\u0645",
  "\uFC89": "\u0645\u0645",
  "\uFC48": "\u0645\u0645",
  "\uFDB1": "\u0645\u0645\u0649",
  "\uFC49": "\u0645\u0649",
  "\uFC4A": "\u0645\u0649",
  "\u{1EE0D}": "\u0646",
  "\u{1EE2D}": "\u0646",
  "\u{1EE4D}": "\u0646",
  "\u{1EE6D}": "\u0646",
  "\u{1EE8D}": "\u0646",
  "\u{1EEAD}": "\u0646",
  "\uFEE7": "\u0646",
  "\uFEE8": "\u0646",
  "\uFEE6": "\u0646",
  "\uFEE5": "\u0646",
  "\u0768": "\u0646\u0615",
  "\u0769": "\u0646\u0306",
  "\uFCD6": "\u0646o",
  "\uFCEF": "\u0646o",
  "\uFDB8": "\u0646\u062C\u062D",
  "\uFDBD": "\u0646\u062C\u062D",
  "\uFD98": "\u0646\u062C\u0645",
  "\uFD97": "\u0646\u062C\u0645",
  "\uFD99": "\u0646\u062C\u0649",
  "\uFDC7": "\u0646\u062C\u0649",
  "\uFCD3": "\u0646\u062D",
  "\uFC4C": "\u0646\u062D",
  "\uFD95": "\u0646\u062D\u0645",
  "\uFD96": "\u0646\u062D\u0649",
  "\uFDB3": "\u0646\u062D\u0649",
  "\uFCD4": "\u0646\u062E",
  "\uFC4D": "\u0646\u062E",
  "\uFC8A": "\u0646\u0631",
  "\uFC8B": "\u0646\u0632",
  "\uFCD5": "\u0646\u0645",
  "\uFCEE": "\u0646\u0645",
  "\uFC8C": "\u0646\u0645",
  "\uFC4E": "\u0646\u0645",
  "\uFD9B": "\u0646\u0645\u0649",
  "\uFD9A": "\u0646\u0645\u0649",
  "\uFC8D": "\u0646\u0646",
  "\uFC8E": "\u0646\u0649",
  "\uFC4F": "\u0646\u0649",
  "\uFC8F": "\u0646\u0649",
  "\uFC50": "\u0646\u0649",
  "\u06C2": "\u06C0",
  "\uFBA5": "\u06C0",
  "\uFBA4": "\u06C0",
  "\u{102E4}": "\u0648",
  "\u{1EE05}": "\u0648",
  "\u{1EE85}": "\u0648",
  "\u{1EEA5}": "\u0648",
  "\uFEEE": "\u0648",
  "\uFEED": "\u0648",
  "\u08B1": "\u0648",
  "\u06CB": "\u0648\u06DB",
  "\uFBDF": "\u0648\u06DB",
  "\uFBDE": "\u0648\u06DB",
  "\u06C7": "\u0648\u0313",
  "\uFBD8": "\u0648\u0313",
  "\uFBD7": "\u0648\u0313",
  "\u06C6": "\u0648\u0306",
  "\uFBDA": "\u0648\u0306",
  "\uFBD9": "\u0648\u0306",
  "\u06C9": "\u0648\u0302",
  "\uFBE3": "\u0648\u0302",
  "\uFBE2": "\u0648\u0302",
  "\u06C8": "\u0648\u0670",
  "\uFBDC": "\u0648\u0670",
  "\uFBDB": "\u0648\u0670",
  "\u0624": "\u0648\u0674",
  "\uFE86": "\u0648\u0674",
  "\uFE85": "\u0648\u0674",
  "\u0676": "\u0648\u0674",
  "\u0677": "\u0648\u0313\u0674",
  "\uFBDD": "\u0648\u0313\u0674",
  "\uFDF8": "\u0648\u0633\u0644\u0645",
  "\uFBE1": "\u06C5",
  "\uFBE0": "\u06C5",
  "\u066E": "\u0649",
  "\u{1EE1C}": "\u0649",
  "\u{1EE7C}": "\u0649",
  "\u06BA": "\u0649",
  "\u{1EE1D}": "\u0649",
  "\u{1EE5D}": "\u0649",
  "\uFB9F": "\u0649",
  "\uFB9E": "\u0649",
  "\u08BD": "\u0649",
  "\uFBE8": "\u0649",
  "\uFBE9": "\u0649",
  "\uFEF0": "\u0649",
  "\uFEEF": "\u0649",
  "\u064A": "\u0649",
  "\u{1EE09}": "\u0649",
  "\u{1EE29}": "\u0649",
  "\u{1EE49}": "\u0649",
  "\u{1EE69}": "\u0649",
  "\u{1EE89}": "\u0649",
  "\u{1EEA9}": "\u0649",
  "\uFEF3": "\u0649",
  "\uFEF4": "\u0649",
  "\uFEF2": "\u0649",
  "\uFEF1": "\u0649",
  "\u06CC": "\u0649",
  "\uFBFE": "\u0649",
  "\uFBFF": "\u0649",
  "\uFBFD": "\u0649",
  "\uFBFC": "\u0649",
  "\u06D2": "\u0649",
  "\uFBAF": "\u0649",
  "\uFBAE": "\u0649",
  "\u0679": "\u0649\u0615",
  "\uFB68": "\u0649\u0615",
  "\uFB69": "\u0649\u0615",
  "\uFB67": "\u0649\u0615",
  "\uFB66": "\u0649\u0615",
  "\u06BB": "\u0649\u0615",
  "\uFBA2": "\u0649\u0615",
  "\uFBA3": "\u0649\u0615",
  "\uFBA1": "\u0649\u0615",
  "\uFBA0": "\u0649\u0615",
  "\u067E": "\u0649\u06DB",
  "\uFB58": "\u0649\u06DB",
  "\uFB59": "\u0649\u06DB",
  "\uFB57": "\u0649\u06DB",
  "\uFB56": "\u0649\u06DB",
  "\u062B": "\u0649\u06DB",
  "\u{1EE16}": "\u0649\u06DB",
  "\u{1EE36}": "\u0649\u06DB",
  "\u{1EE76}": "\u0649\u06DB",
  "\u{1EE96}": "\u0649\u06DB",
  "\u{1EEB6}": "\u0649\u06DB",
  "\uFE9B": "\u0649\u06DB",
  "\uFE9C": "\u0649\u06DB",
  "\uFE9A": "\u0649\u06DB",
  "\uFE99": "\u0649\u06DB",
  "\u06BD": "\u0649\u06DB",
  "\u06D1": "\u0649\u06DB",
  "\u063F": "\u0649\u06DB",
  "\u08B7": "\u0649\u06DB\u06E2",
  "\u0756": "\u0649\u0306",
  "\u06CE": "\u0649\u0306",
  "\u08BA": "\u0649\u0306\u0307",
  "\u063D": "\u0649\u0302",
  "\u08A8": "\u0649\u0654",
  "\uFC90": "\u0649\u0670",
  "\uFC5D": "\u0649\u0670",
  "\uFCDE": "\u0649o",
  "\uFCF1": "\u0649o",
  "\uFCE6": "\u0649\u06DBo",
  "\u0626": "\u0649\u0674",
  "\uFE8B": "\u0649\u0674",
  "\uFE8C": "\u0649\u0674",
  "\uFE8A": "\u0649\u0674",
  "\uFE89": "\u0649\u0674",
  "\u0678": "\u0649\u0674",
  "\uFBEB": "\u0649\u0674l",
  "\uFBEA": "\u0649\u0674l",
  "\uFC9B": "\u0649\u0674o",
  "\uFCE0": "\u0649\u0674o",
  "\uFBED": "\u0649\u0674o",
  "\uFBEC": "\u0649\u0674o",
  "\uFBF8": "\u0649\u0674\u067B",
  "\uFBF7": "\u0649\u0674\u067B",
  "\uFBF6": "\u0649\u0674\u067B",
  "\uFC97": "\u0649\u0674\u062C",
  "\uFC00": "\u0649\u0674\u062C",
  "\uFC98": "\u0649\u0674\u062D",
  "\uFC01": "\u0649\u0674\u062D",
  "\uFC99": "\u0649\u0674\u062E",
  "\uFC64": "\u0649\u0674\u0631",
  "\uFC65": "\u0649\u0674\u0632",
  "\uFC9A": "\u0649\u0674\u0645",
  "\uFCDF": "\u0649\u0674\u0645",
  "\uFC66": "\u0649\u0674\u0645",
  "\uFC02": "\u0649\u0674\u0645",
  "\uFC67": "\u0649\u0674\u0646",
  "\uFBEF": "\u0649\u0674\u0648",
  "\uFBEE": "\u0649\u0674\u0648",
  "\uFBF1": "\u0649\u0674\u0648\u0313",
  "\uFBF0": "\u0649\u0674\u0648\u0313",
  "\uFBF3": "\u0649\u0674\u0648\u0306",
  "\uFBF2": "\u0649\u0674\u0648\u0306",
  "\uFBF5": "\u0649\u0674\u0648\u0670",
  "\uFBF4": "\u0649\u0674\u0648\u0670",
  "\uFBFB": "\u0649\u0674\u0649",
  "\uFBFA": "\u0649\u0674\u0649",
  "\uFC68": "\u0649\u0674\u0649",
  "\uFBF9": "\u0649\u0674\u0649",
  "\uFC03": "\u0649\u0674\u0649",
  "\uFC69": "\u0649\u0674\u0649",
  "\uFC04": "\u0649\u0674\u0649",
  "\uFCDA": "\u0649\u062C",
  "\uFC55": "\u0649\u062C",
  "\uFC11": "\u0649\u06DB\u062C",
  "\uFDAF": "\u0649\u062C\u0649",
  "\uFCDB": "\u0649\u062D",
  "\uFC56": "\u0649\u062D",
  "\uFDAE": "\u0649\u062D\u0649",
  "\uFCDC": "\u0649\u062E",
  "\uFC57": "\u0649\u062E",
  "\uFC91": "\u0649\u0631",
  "\uFC76": "\u0649\u06DB\u0631",
  "\uFC92": "\u0649\u0632",
  "\uFC77": "\u0649\u06DB\u0632",
  "\uFCDD": "\u0649\u0645",
  "\uFCF0": "\u0649\u0645",
  "\uFC93": "\u0649\u0645",
  "\uFC58": "\u0649\u0645",
  "\uFCA6": "\u0649\u06DB\u0645",
  "\uFCE5": "\u0649\u06DB\u0645",
  "\uFC78": "\u0649\u06DB\u0645",
  "\uFC12": "\u0649\u06DB\u0645",
  "\uFD9D": "\u0649\u0645\u0645",
  "\uFD9C": "\u0649\u0645\u0645",
  "\uFDB0": "\u0649\u0645\u0649",
  "\uFC94": "\u0649\u0646",
  "\uFC79": "\u0649\u06DB\u0646",
  "\uFC95": "\u0649\u0649",
  "\uFC59": "\u0649\u0649",
  "\uFC96": "\u0649\u0649",
  "\uFC5A": "\u0649\u0649",
  "\uFC7A": "\u0649\u06DB\u0649",
  "\uFC13": "\u0649\u06DB\u0649",
  "\uFC7B": "\u0649\u06DB\u0649",
  "\uFC14": "\u0649\u06DB\u0649",
  "\uFBB1": "\u06D3",
  "\uFBB0": "\u06D3",
  "\u{102B8}": "\u2D40",
  "\u205E": "\u2D42",
  "\u2E3D": "\u2D42",
  "\u2999": "\u2D42",
  "\uFE19": "\u2D57",
  "\u205D": "\u2D57",
  "\u22EE": "\u2D57",
  "\u0544": "\u1206",
  "\u054C": "\u1261",
  "\u053B": "\u12AE",
  "\u054A": "\u1323",
  "\u0906": "\u0905\u093E",
  "\u0912": "\u0905\u093E\u0946",
  "\u0913": "\u0905\u093E\u0947",
  "\u0914": "\u0905\u093E\u0948",
  "\u0904": "\u0905\u0946",
  "\u0911": "\u0905\u0949",
  "\u090D": "\u090F\u0945",
  "\u090E": "\u090F\u0946",
  "\u0910": "\u090F\u0947",
  "\u0908": "\u0930\u094D\u0907",
  "\u0ABD": "\u093D",
  "\u{111DC}": "\uA8FB",
  "\u{111CB}": "\u093A",
  "\u0AC1": "\u0941",
  "\u0AC2": "\u0942",
  "\u0A4B": "\u0946",
  "\u0A4D": "\u094D",
  "\u0ACD": "\u094D",
  "\u0986": "\u0985\u09BE",
  "\u09E0": "\u098B\u09C3",
  "\u09E1": "\u098B\u09C3",
  "\u{11492}": "\u0998",
  "\u{11494}": "\u099A",
  "\u{11496}": "\u099C",
  "\u{11498}": "\u099E",
  "\u{11499}": "\u099F",
  "\u{1149B}": "\u09A1",
  "\u{114AA}": "\u09A3",
  "\u{1149E}": "\u09A4",
  "\u{1149F}": "\u09A5",
  "\u{114A0}": "\u09A6",
  "\u{114A1}": "\u09A7",
  "\u{114A2}": "\u09A8",
  "\u{114A3}": "\u09AA",
  "\u{114A9}": "\u09AC",
  "\u{114A7}": "\u09AE",
  "\u{114A8}": "\u09AF",
  "\u{114AB}": "\u09B0",
  "\u{1149D}": "\u09B2",
  "\u{114AD}": "\u09B7",
  "\u{114AE}": "\u09B8",
  "\u{114C4}": "\u09BD",
  "\u{114B0}": "\u09BE",
  "\u{114B1}": "\u09BF",
  "\u{114B9}": "\u09C7",
  "\u{114BC}": "\u09CB",
  "\u{114BE}": "\u09CC",
  "\u{114C2}": "\u09CD",
  "\u{114BD}": "\u09D7",
  "\u0A09": "\u0A73\u0A41",
  "\u0A0A": "\u0A73\u0A42",
  "\u0A06": "\u0A05\u0A3E",
  "\u0A10": "\u0A05\u0A48",
  "\u0A14": "\u0A05\u0A4C",
  "\u0A07": "\u0A72\u0A3F",
  "\u0A08": "\u0A72\u0A40",
  "\u0A0F": "\u0A72\u0A47",
  "\u0A86": "\u0A85\u0ABE",
  "\u0A91": "\u0A85\u0ABE\u0AC5",
  "\u0A93": "\u0A85\u0ABE\u0AC7",
  "\u0A94": "\u0A85\u0ABE\u0AC8",
  "\u0A8D": "\u0A85\u0AC5",
  "\u0A8F": "\u0A85\u0AC7",
  "\u0A90": "\u0A85\u0AC8",
  "\u0B06": "\u0B05\u0B3E",
  "\u0BEE": "\u0B85",
  "\u0BB0": "\u0B88",
  "\u0BBE": "\u0B88",
  "\u0BEB": "\u0B88\u0BC1",
  "\u0BE8": "\u0B89",
  "\u0D09": "\u0B89",
  "\u0B8A": "\u0B89\u0BB3",
  "\u0D0A": "\u0B89\u0D57",
  "\u0BED": "\u0B8E",
  "\u0BF7": "\u0B8E\u0BB5",
  "\u0B9C": "\u0B90",
  "\u0D1C": "\u0B90",
  "\u0BE7": "\u0B95",
  "\u0BEA": "\u0B9A",
  "\u0BEC": "\u0B9A\u0BC1",
  "\u0BF2": "\u0B9A\u0BC2",
  "\u0D3A": "\u0B9F\u0BBF",
  "\u0D23": "\u0BA3",
  "\u0BFA": "\u0BA8\u0BC0",
  "\u0BF4": "\u0BAE\u0BC0",
  "\u0BF0": "\u0BAF",
  "\u0D34": "\u0BB4",
  "\u0BD7": "\u0BB3",
  "\u0BC8": "\u0BA9",
  "\u0D36": "\u0BB6",
  "\u0BF8": "\u0BB7",
  "\u0D3F": "\u0BBF",
  "\u0D40": "\u0BBF",
  "\u0BCA": "\u0BC6\u0B88",
  "\u0BCC": "\u0BC6\u0BB3",
  "\u0BCB": "\u0BC7\u0B88",
  "\u0C85": "\u0C05",
  "\u0C86": "\u0C06",
  "\u0C87": "\u0C07",
  "\u0C60": "\u0C0B\u0C3E",
  "\u0C61": "\u0C0C\u0C3E",
  "\u0C92": "\u0C12",
  "\u0C14": "\u0C12\u0C4C",
  "\u0C94": "\u0C12\u0C4C",
  "\u0C13": "\u0C12\u0C55",
  "\u0C93": "\u0C12\u0C55",
  "\u0C9C": "\u0C1C",
  "\u0C9E": "\u0C1E",
  "\u0C22": "\u0C21\u0323",
  "\u0CA3": "\u0C23",
  "\u0C25": "\u0C27\u05BC",
  "\u0C2D": "\u0C2C\u0323",
  "\u0CAF": "\u0C2F",
  "\u0C20": "\u0C30\u05BC",
  "\u0CB1": "\u0C31",
  "\u0CB2": "\u0C32",
  "\u0C37": "\u0C35\u0323",
  "\u0C39": "\u0C35\u0C3E",
  "\u0C2E": "\u0C35\u0C41",
  "\u0C42": "\u0C41\u0C3E",
  "\u0C44": "\u0C43\u0C3E",
  "\u0CE1": "\u0C8C\u0CBE",
  "\u0D08": "\u0D07\u0D57",
  "\u0D10": "\u0D0E\u0D46",
  "\u0D13": "\u0D12\u0D3E",
  "\u0D14": "\u0D12\u0D57",
  "\u0D61": "\u0D1E",
  "\u0D6B": "\u0D26\u0D4D\u0D30",
  "\u0D79": "\u0D28\u0D41",
  "\u0D0C": "\u0D28\u0D41",
  "\u0D19": "\u0D28\u0D41",
  "\u0D6F": "\u0D28\u0D4D",
  "\u0D7B": "\u0D28\u0D4D",
  "\u0D6C": "\u0D28\u0D4D\u0D28",
  "\u0D5A": "\u0D28\u0D4D\u0D2E",
  "\u0D31": "\u0D30",
  "\u0D6A": "\u0D30\u0D4D",
  "\u0D7C": "\u0D30\u0D4D",
  "\u0D6E": "\u0D35\u0D4D\u0D30",
  "\u0D76": "\u0D39\u0D4D\u0D2E",
  "\u0D42": "\u0D41",
  "\u0D43": "\u0D41",
  "\u0D48": "\u0D46\u0D46",
  "\u0DEA": "\u0DA2",
  "\u0DEB": "\u0DAF",
  "\u{11413}": "\u{11434}\u{11442}\u{11412}",
  "\u{11419}": "\u{11434}\u{11442}\u{11418}",
  "\u{11424}": "\u{11434}\u{11442}\u{11423}",
  "\u{1142A}": "\u{11434}\u{11442}\u{11429}",
  "\u{1142D}": "\u{11434}\u{11442}\u{1142C}",
  "\u{1142F}": "\u{11434}\u{11442}\u{1142E}",
  "\u{115D8}": "\u{11582}",
  "\u{115D9}": "\u{11582}",
  "\u{115DA}": "\u{11583}",
  "\u{115DB}": "\u{11584}",
  "\u{115DC}": "\u{115B2}",
  "\u{115DD}": "\u{115B3}",
  "\u0E03": "\u0E02",
  "\u0E14": "\u0E04",
  "\u0E15": "\u0E04",
  "\u0E21": "\u0E06",
  "\u0E88": "\u0E08",
  "\u0E0B": "\u0E0A",
  "\u0E0F": "\u0E0E",
  "\u0E17": "\u0E11",
  "\u0E9A": "\u0E1A",
  "\u0E9B": "\u0E1B",
  "\u0E9D": "\u0E1D",
  "\u0E9E": "\u0E1E",
  "\u0E9F": "\u0E1F",
  "\u0E26": "\u0E20",
  "\u0E8D": "\u0E22",
  "\u17D4": "\u0E2F",
  "\u0E45": "\u0E32",
  "\u0E33": "\u030A\u0E32",
  "\u17B7": "\u0E34",
  "\u17B8": "\u0E35",
  "\u17B9": "\u0E36",
  "\u17BA": "\u0E37",
  "\u0EB8": "\u0E38",
  "\u0EB9": "\u0E39",
  "\u0E41": "\u0E40\u0E40",
  "\u0EDC": "\u0EAB\u0E99",
  "\u0EDD": "\u0EAB\u0EA1",
  "\u0EB3": "\u030A\u0EB2",
  "\u0F02": "\u0F60\u0F74\u0F82\u0F7F",
  "\u0F03": "\u0F60\u0F74\u0F82\u0F14",
  "\u0F6A": "\u0F62",
  "\u0F00": "\u0F68\u0F7C\u0F7E",
  "\u0F77": "\u0FB2\u0F71\u0F80",
  "\u0F79": "\u0FB3\u0F71\u0F80",
  "\u{11CB2}": "\u{11CAA}",
  "\u1081": "\u1002\u103E",
  "\u1000": "\u1002\u102C",
  "\u1070": "\u1003\u103E",
  "\u1066": "\u1015\u103E",
  "\u101F": "\u1015\u102C",
  "\u106F": "\u1015\u102C\u103E",
  "\u107E": "\u107D\u103E",
  "\u1029": "\u101E\u103C",
  "\u102A": "\u101E\u103C\u1031\u102C\u103A",
  "\u109E": "\u1083\u030A",
  "\u17A3": "\u17A2",
  "\u19D0": "\u199E",
  "\u19D1": "\u19B1",
  "\u1A80": "\u1A45",
  "\u1A90": "\u1A45",
  "\uAA53": "\uAA01",
  "\uAA56": "\uAA23",
  "\u1B52": "\u1B0D",
  "\u1B53": "\u1B11",
  "\u1B58": "\u1B28",
  "\uA9A3": "\uA99D",
  "\u1896": "\u185C",
  "\u1855": "\u1835",
  "\u1FF6": "\u13EF",
  "\u140D": "\u1401\xB7",
  "\u142B": "\u1401\u1420",
  "\u1411": "\u1404\xB7",
  "\u1413": "\u1405\xB7",
  "\u142D": "\u1405\u1420",
  "\u1415": "\u1406\xB7",
  "\u1418": "\u140A\xB7",
  "\u142E": "\u140A\u1420",
  "\u141A": "\u140B\xB7",
  "\u18DD": "\u141E\u18DF",
  "\u14D1": "\u1421",
  "\u1540": "\u1429",
  "\u143F": "\u1432\xB7",
  "\u1443": "\u1434\xB7",
  "\u2369": "\u1435",
  "\u1447": "\u1439\xB7",
  "\u145C": "\u144F\xB7",
  "\u2E27": "\u1450",
  "\u2283": "\u1450",
  "\u145E": "\u1450\xB7",
  "\u1469": "\u1450'",
  "\u27C9": "\u1450/",
  "\u2AD7": "\u1450\u1455",
  "\u1460": "\u1451\xB7",
  "\u2E26": "\u1455",
  "\u2282": "\u1455",
  "\u1462": "\u1455\xB7",
  "\u146A": "\u1455'",
  "\u1464": "\u1456\xB7",
  "\u1475": "\u146B\xB7",
  "\u1485": "\u146B'",
  "\u1479": "\u146E\xB7",
  "\u147D": "\u1470\xB7",
  "\u1603": "\u1489",
  "\u1493": "\u1489\xB7",
  "\u1495": "\u148B\xB7",
  "\u1497": "\u148C\xB7",
  "\u149B": "\u148E\xB7",
  "\u1602": "\u1490",
  "\u149D": "\u1490\xB7",
  "\u149F": "\u1491\xB7",
  "\u14AD": "\u14A3\xB7",
  "\u14B1": "\u14A6\xB7",
  "\u14B3": "\u14A7\xB7",
  "\u14B5": "\u14A8\xB7",
  "\u14B9": "\u14AB\xB7",
  "\u14CA": "\u14C0\xB7",
  "\u18C7": "\u14C2\xB7",
  "\u18C9": "\u14C3\xB7",
  "\u18CB": "\u14C4\xB7",
  "\u18CD": "\u14C5\xB7",
  "\u14CC": "\u14C7\xB7",
  "\u14CE": "\u14C8\xB7",
  "\u1604": "\u14D3",
  "\u14DD": "\u14D3\xB7",
  "\u14DF": "\u14D5\xB7",
  "\u14E1": "\u14D6\xB7",
  "\u14E3": "\u14D7\xB7",
  "\u14E5": "\u14D8\xB7",
  "\u1607": "\u14DA",
  "\u14E7": "\u14DA\xB7",
  "\u14E9": "\u14DB\xB7",
  "\u14F7": "\u14ED\xB7",
  "\u14F9": "\u14EF\xB7",
  "\u14FB": "\u14F0\xB7",
  "\u14FD": "\u14F1\xB7",
  "\u14FF": "\u14F2\xB7",
  "\u1501": "\u14F4\xB7",
  "\u1503": "\u14F5\xB7",
  "\u150C": "\u150B<",
  "\u150E": "\u150Bb",
  "\u150D": "\u150B\u1455",
  "\u150F": "\u150B\u1490",
  "\u1518": "\u1510\xB7",
  "\u151A": "\u1511\xB7",
  "\u151C": "\u1512\xB7",
  "\u151E": "\u1513\xB7",
  "\u1520": "\u1514\xB7",
  "\u1522": "\u1515\xB7",
  "\u1524": "\u1516\xB7",
  "\u1532": "\u1528\xB7",
  "\u1534": "\u1529\xB7",
  "\u1536": "\u152A\xB7",
  "\u1538": "\u152B\xB7",
  "\u153A": "\u152D\xB7",
  "\u153C": "\u152E\xB7",
  "\u1622": "\u1543",
  "\u18E0": "\u1543\xB7",
  "\u1623": "\u1546",
  "\u1624": "\u154A",
  "\u154F": "\u154C\xB7",
  "\u1583": "\u1550b",
  "\u1584": "\u1550b\u0307",
  "\u1581": "\u1550d",
  "\u157F": "\u1550P",
  "\u166F": "\u1550\u146B",
  "\u157E": "\u1550\u146C",
  "\u1580": "\u1550\u146E",
  "\u1582": "\u1550\u1470",
  "\u1585": "\u1550\u1483",
  "\u155C": "\u155A\xB7",
  "\u18E3": "\u155E\xB7",
  "\u18E4": "\u1566\xB7",
  "\u1569": "\u1567\xB7",
  "\u18E5": "\u156B\xB7",
  "\u18E8": "\u1586\xB7",
  "\u1591": "\u1595J",
  "\u1670": "\u1595\u1489",
  "\u158E": "\u1595\u148A",
  "\u158F": "\u1595\u148B",
  "\u1590": "\u1595\u148C",
  "\u1592": "\u1595\u148E",
  "\u1593": "\u1595\u1490",
  "\u1594": "\u1595\u1491",
  "\u1673": "\u1596J",
  "\u1671": "\u1596\u148B",
  "\u1672": "\u1596\u148C",
  "\u1674": "\u1596\u148E",
  "\u1675": "\u1596\u1490",
  "\u1676": "\u1596\u1491",
  "\u18EA": "\u1597\xB7",
  "\u1677": "\u15A7\xB7",
  "\u1678": "\u15A8\xB7",
  "\u1679": "\u15A9\xB7",
  "\u167A": "\u15AA\xB7",
  "\u167B": "\u15AB\xB7",
  "\u167C": "\u15AC\xB7",
  "\u167D": "\u15AD\xB7",
  "\u2AAB": "\u15D2",
  "\u2AAA": "\u15D5",
  "\uA4F7": "\u15E1",
  "\u18F0": "\u15F4\xB7",
  "\u18F2": "\u161B\xB7",
  "\u1DBB": "\u1646",
  "\uA4ED": "\u1660",
  "\u1DBA": "\u18D4",
  "\u1D3E": "\u18D6",
  "\u18DC": "\u18DF\u141E",
  "\u02E1": "\u18F3",
  "\u02B3": "\u18F4",
  "\u02E2": "\u18F5",
  "\u18DB": "\u18F5",
  "\uA6B0": "\u16B9",
  "\u16E1": "\u16BC",
  "\u237F": "\u16BD",
  "\u16C2": "\u16BD",
  "\u{1D23F}": "\u16CB",
  "\u2191": "\u16CF",
  "\u21BF": "\u16D0",
  "\u296E": "\u16D0\u21C2",
  "\u2963": "\u16D0\u16DA",
  "\u2D63": "\u16EF",
  "\u21BE": "\u16DA",
  "\u2A21": "\u16DA",
  "\u22C4": "\u16DC",
  "\u25C7": "\u16DC",
  "\u25CA": "\u16DC",
  "\u2662": "\u16DC",
  "\u{1F754}": "\u16DC",
  "\u{118B7}": "\u16DC",
  "\u{10294}": "\u16DC",
  "\u235A": "\u16DC\u0332",
  "\u22C8": "\u16DE",
  "\u2A1D": "\u16DE",
  "\u{104D0}": "\u16E6",
  "\u2195": "\u16E8",
  "\u{10CFC}": "\u{10C82}",
  "\u{10CFA}": "\u{10CA5}",
  "\u3131": "\u1100",
  "\u11A8": "\u1100",
  "\u1101": "\u1100\u1100",
  "\u3132": "\u1100\u1100",
  "\u11A9": "\u1100\u1100",
  "\u11FA": "\u1100\u1102",
  "\u115A": "\u1100\u1103",
  "\u11C3": "\u1100\u1105",
  "\u11FB": "\u1100\u1107",
  "\u11AA": "\u1100\u1109",
  "\u3133": "\u1100\u1109",
  "\u11C4": "\u1100\u1109\u1100",
  "\u11FC": "\u1100\u110E",
  "\u11FD": "\u1100\u110F",
  "\u11FE": "\u1100\u1112",
  "\u3134": "\u1102",
  "\u11AB": "\u1102",
  "\u1113": "\u1102\u1100",
  "\u11C5": "\u1102\u1100",
  "\u1114": "\u1102\u1102",
  "\u3165": "\u1102\u1102",
  "\u11FF": "\u1102\u1102",
  "\u1115": "\u1102\u1103",
  "\u3166": "\u1102\u1103",
  "\u11C6": "\u1102\u1103",
  "\uD7CB": "\u1102\u1105",
  "\u1116": "\u1102\u1107",
  "\u115B": "\u1102\u1109",
  "\u11C7": "\u1102\u1109",
  "\u3167": "\u1102\u1109",
  "\u115C": "\u1102\u110C",
  "\u11AC": "\u1102\u110C",
  "\u3135": "\u1102\u110C",
  "\uD7CC": "\u1102\u110E",
  "\u11C9": "\u1102\u1110",
  "\u115D": "\u1102\u1112",
  "\u11AD": "\u1102\u1112",
  "\u3136": "\u1102\u1112",
  "\u11C8": "\u1102\u1140",
  "\u3168": "\u1102\u1140",
  "\u3137": "\u1103",
  "\u11AE": "\u1103",
  "\u1117": "\u1103\u1100",
  "\u11CA": "\u1103\u1100",
  "\u1104": "\u1103\u1103",
  "\u3138": "\u1103\u1103",
  "\uD7CD": "\u1103\u1103",
  "\uD7CE": "\u1103\u1103\u1107",
  "\u115E": "\u1103\u1105",
  "\u11CB": "\u1103\u1105",
  "\uA960": "\u1103\u1106",
  "\uA961": "\u1103\u1107",
  "\uD7CF": "\u1103\u1107",
  "\uA962": "\u1103\u1109",
  "\uD7D0": "\u1103\u1109",
  "\uD7D1": "\u1103\u1109\u1100",
  "\uA963": "\u1103\u110C",
  "\uD7D2": "\u1103\u110C",
  "\uD7D3": "\u1103\u110E",
  "\uD7D4": "\u1103\u1110",
  "\u3139": "\u1105",
  "\u11AF": "\u1105",
  "\uA964": "\u1105\u1100",
  "\u11B0": "\u1105\u1100",
  "\u313A": "\u1105\u1100",
  "\uA965": "\u1105\u1100\u1100",
  "\uD7D5": "\u1105\u1100\u1100",
  "\u11CC": "\u1105\u1100\u1109",
  "\u3169": "\u1105\u1100\u1109",
  "\uD7D6": "\u1105\u1100\u1112",
  "\u1118": "\u1105\u1102",
  "\u11CD": "\u1105\u1102",
  "\uA966": "\u1105\u1103",
  "\u11CE": "\u1105\u1103",
  "\u316A": "\u1105\u1103",
  "\uA967": "\u1105\u1103\u1103",
  "\u11CF": "\u1105\u1103\u1112",
  "\u1119": "\u1105\u1105",
  "\u11D0": "\u1105\u1105",
  "\uD7D7": "\u1105\u1105\u110F",
  "\uA968": "\u1105\u1106",
  "\u11B1": "\u1105\u1106",
  "\u313B": "\u1105\u1106",
  "\u11D1": "\u1105\u1106\u1100",
  "\u11D2": "\u1105\u1106\u1109",
  "\uD7D8": "\u1105\u1106\u1112",
  "\uA969": "\u1105\u1107",
  "\u11B2": "\u1105\u1107",
  "\u313C": "\u1105\u1107",
  "\uD7D9": "\u1105\u1107\u1103",
  "\uA96A": "\u1105\u1107\u1107",
  "\u11D3": "\u1105\u1107\u1109",
  "\u316B": "\u1105\u1107\u1109",
  "\uA96B": "\u1105\u1107\u110B",
  "\u11D5": "\u1105\u1107\u110B",
  "\uD7DA": "\u1105\u1107\u1111",
  "\u11D4": "\u1105\u1107\u1112",
  "\uA96C": "\u1105\u1109",
  "\u11B3": "\u1105\u1109",
  "\u313D": "\u1105\u1109",
  "\u11D6": "\u1105\u1109\u1109",
  "\u111B": "\u1105\u110B",
  "\uD7DD": "\u1105\u110B",
  "\uA96D": "\u1105\u110C",
  "\uA96E": "\u1105\u110F",
  "\u11D8": "\u1105\u110F",
  "\u11B4": "\u1105\u1110",
  "\u313E": "\u1105\u1110",
  "\u11B5": "\u1105\u1111",
  "\u313F": "\u1105\u1111",
  "\u111A": "\u1105\u1112",
  "\u3140": "\u1105\u1112",
  "\u113B": "\u1105\u1112",
  "\u11B6": "\u1105\u1112",
  "\uD7F2": "\u1105\u1112",
  "\u11D7": "\u1105\u1140",
  "\u316C": "\u1105\u1140",
  "\uD7DB": "\u1105\u114C",
  "\u11D9": "\u1105\u1159",
  "\u316D": "\u1105\u1159",
  "\uD7DC": "\u1105\u1159\u1112",
  "\u3141": "\u1106",
  "\u11B7": "\u1106",
  "\uA96F": "\u1106\u1100",
  "\u11DA": "\u1106\u1100",
  "\uD7DE": "\u1106\u1102",
  "\uD7DF": "\u1106\u1102\u1102",
  "\uA970": "\u1106\u1103",
  "\u11DB": "\u1106\u1105",
  "\uD7E0": "\u1106\u1106",
  "\u111C": "\u1106\u1107",
  "\u316E": "\u1106\u1107",
  "\u11DC": "\u1106\u1107",
  "\uD7E1": "\u1106\u1107\u1109",
  "\uA971": "\u1106\u1109",
  "\u11DD": "\u1106\u1109",
  "\u316F": "\u1106\u1109",
  "\u11DE": "\u1106\u1109\u1109",
  "\u111D": "\u1106\u110B",
  "\u3171": "\u1106\u110B",
  "\u11E2": "\u1106\u110B",
  "\uD7E2": "\u1106\u110C",
  "\u11E0": "\u1106\u110E",
  "\u11E1": "\u1106\u1112",
  "\u11DF": "\u1106\u1140",
  "\u3170": "\u1106\u1140",
  "\u3142": "\u1107",
  "\u11B8": "\u1107",
  "\u111E": "\u1107\u1100",
  "\u3172": "\u1107\u1100",
  "\u111F": "\u1107\u1102",
  "\u1120": "\u1107\u1103",
  "\u3173": "\u1107\u1103",
  "\uD7E3": "\u1107\u1103",
  "\u11E3": "\u1107\u1105",
  "\uD7E4": "\u1107\u1105\u1111",
  "\uD7E5": "\u1107\u1106",
  "\u1108": "\u1107\u1107",
  "\u3143": "\u1107\u1107",
  "\uD7E6": "\u1107\u1107",
  "\u112C": "\u1107\u1107\u110B",
  "\u3179": "\u1107\u1107\u110B",
  "\u1121": "\u1107\u1109",
  "\u3144": "\u1107\u1109",
  "\u11B9": "\u1107\u1109",
  "\u1122": "\u1107\u1109\u1100",
  "\u3174": "\u1107\u1109\u1100",
  "\u1123": "\u1107\u1109\u1103",
  "\u3175": "\u1107\u1109\u1103",
  "\uD7E7": "\u1107\u1109\u1103",
  "\u1124": "\u1107\u1109\u1107",
  "\u1125": "\u1107\u1109\u1109",
  "\u1126": "\u1107\u1109\u110C",
  "\uA972": "\u1107\u1109\u1110",
  "\u112B": "\u1107\u110B",
  "\u3178": "\u1107\u110B",
  "\u11E6": "\u1107\u110B",
  "\u1127": "\u1107\u110C",
  "\u3176": "\u1107\u110C",
  "\uD7E8": "\u1107\u110C",
  "\u1128": "\u1107\u110E",
  "\uD7E9": "\u1107\u110E",
  "\uA973": "\u1107\u110F",
  "\u1129": "\u1107\u1110",
  "\u3177": "\u1107\u1110",
  "\u112A": "\u1107\u1111",
  "\u11E4": "\u1107\u1111",
  "\uA974": "\u1107\u1112",
  "\u11E5": "\u1107\u1112",
  "\u3145": "\u1109",
  "\u11BA": "\u1109",
  "\u112D": "\u1109\u1100",
  "\u317A": "\u1109\u1100",
  "\u11E7": "\u1109\u1100",
  "\u112E": "\u1109\u1102",
  "\u317B": "\u1109\u1102",
  "\u112F": "\u1109\u1103",
  "\u317C": "\u1109\u1103",
  "\u11E8": "\u1109\u1103",
  "\u1130": "\u1109\u1105",
  "\u11E9": "\u1109\u1105",
  "\u1131": "\u1109\u1106",
  "\uD7EA": "\u1109\u1106",
  "\u1132": "\u1109\u1107",
  "\u317D": "\u1109\u1107",
  "\u11EA": "\u1109\u1107",
  "\u1133": "\u1109\u1107\u1100",
  "\uD7EB": "\u1109\u1107\u110B",
  "\u110A": "\u1109\u1109",
  "\u3146": "\u1109\u1109",
  "\u11BB": "\u1109\u1109",
  "\uD7EC": "\u1109\u1109\u1100",
  "\uD7ED": "\u1109\u1109\u1103",
  "\uA975": "\u1109\u1109\u1107",
  "\u1134": "\u1109\u1109\u1109",
  "\u1135": "\u1109\u110B",
  "\u1136": "\u1109\u110C",
  "\u317E": "\u1109\u110C",
  "\uD7EF": "\u1109\u110C",
  "\u1137": "\u1109\u110E",
  "\uD7F0": "\u1109\u110E",
  "\u1138": "\u1109\u110F",
  "\u1139": "\u1109\u1110",
  "\uD7F1": "\u1109\u1110",
  "\u113A": "\u1109\u1111",
  "\uD7EE": "\u1109\u1140",
  "\u3147": "\u110B",
  "\u11BC": "\u110B",
  "\u1141": "\u110B\u1100",
  "\u11EC": "\u110B\u1100",
  "\u11ED": "\u110B\u1100\u1100",
  "\u1142": "\u110B\u1103",
  "\uA976": "\u110B\u1105",
  "\u1143": "\u110B\u1106",
  "\u1144": "\u110B\u1107",
  "\u1145": "\u110B\u1109",
  "\u11F1": "\u110B\u1109",
  "\u3182": "\u110B\u1109",
  "\u1147": "\u110B\u110B",
  "\u3180": "\u110B\u110B",
  "\u11EE": "\u110B\u110B",
  "\u1148": "\u110B\u110C",
  "\u1149": "\u110B\u110E",
  "\u11EF": "\u110B\u110F",
  "\u114A": "\u110B\u1110",
  "\u114B": "\u110B\u1111",
  "\uA977": "\u110B\u1112",
  "\u1146": "\u110B\u1140",
  "\u11F2": "\u110B\u1140",
  "\u3183": "\u110B\u1140",
  "\u3148": "\u110C",
  "\u11BD": "\u110C",
  "\uD7F7": "\u110C\u1107",
  "\uD7F8": "\u110C\u1107\u1107",
  "\u114D": "\u110C\u110B",
  "\u110D": "\u110C\u110C",
  "\u3149": "\u110C\u110C",
  "\uD7F9": "\u110C\u110C",
  "\uA978": "\u110C\u110C\u1112",
  "\u314A": "\u110E",
  "\u11BE": "\u110E",
  "\u1152": "\u110E\u110F",
  "\u1153": "\u110E\u1112",
  "\u314B": "\u110F",
  "\u11BF": "\u110F",
  "\u314C": "\u1110",
  "\u11C0": "\u1110",
  "\uA979": "\u1110\u1110",
  "\u314D": "\u1111",
  "\u11C1": "\u1111",
  "\u1156": "\u1111\u1107",
  "\u11F3": "\u1111\u1107",
  "\uD7FA": "\u1111\u1109",
  "\u1157": "\u1111\u110B",
  "\u3184": "\u1111\u110B",
  "\u11F4": "\u1111\u110B",
  "\uD7FB": "\u1111\u1110",
  "\uA97A": "\u1111\u1112",
  "\u314E": "\u1112",
  "\u11C2": "\u1112",
  "\u11F5": "\u1112\u1102",
  "\u11F6": "\u1112\u1105",
  "\u11F7": "\u1112\u1106",
  "\u11F8": "\u1112\u1107",
  "\uA97B": "\u1112\u1109",
  "\u1158": "\u1112\u1112",
  "\u3185": "\u1112\u1112",
  "\u113D": "\u113C\u113C",
  "\u113F": "\u113E\u113E",
  "\u317F": "\u1140",
  "\u11EB": "\u1140",
  "\uD7F3": "\u1140\u1107",
  "\uD7F4": "\u1140\u1107\u110B",
  "\u3181": "\u114C",
  "\u11F0": "\u114C",
  "\uD7F5": "\u114C\u1106",
  "\uD7F6": "\u114C\u1112",
  "\u114F": "\u114E\u114E",
  "\u1151": "\u1150\u1150",
  "\u3186": "\u1159",
  "\u11F9": "\u1159",
  "\uA97C": "\u1159\u1159",
  "\u3164": "\u1160",
  "\u314F": "\u1161",
  "\u11A3": "\u1161\u30FC",
  "\u1176": "\u1161\u1169",
  "\u1177": "\u1161\u116E",
  "\u1162": "\u1161\u4E28",
  "\u3150": "\u1161\u4E28",
  "\u3151": "\u1163",
  "\u1178": "\u1163\u1169",
  "\u1179": "\u1163\u116D",
  "\u11A4": "\u1163\u116E",
  "\u1164": "\u1163\u4E28",
  "\u3152": "\u1163\u4E28",
  "\u3153": "\u1165",
  "\u117C": "\u1165\u30FC",
  "\u117A": "\u1165\u1169",
  "\u117B": "\u1165\u116E",
  "\u1166": "\u1165\u4E28",
  "\u3154": "\u1165\u4E28",
  "\u3155": "\u1167",
  "\u11A5": "\u1167\u1163",
  "\u117D": "\u1167\u1169",
  "\u117E": "\u1167\u116E",
  "\u1168": "\u1167\u4E28",
  "\u3156": "\u1167\u4E28",
  "\u3157": "\u1169",
  "\u116A": "\u1169\u1161",
  "\u3158": "\u1169\u1161",
  "\u116B": "\u1169\u1161\u4E28",
  "\u3159": "\u1169\u1161\u4E28",
  "\u11A6": "\u1169\u1163",
  "\u11A7": "\u1169\u1163\u4E28",
  "\u117F": "\u1169\u1165",
  "\u1180": "\u1169\u1165\u4E28",
  "\uD7B0": "\u1169\u1167",
  "\u1181": "\u1169\u1167\u4E28",
  "\u1182": "\u1169\u1169",
  "\uD7B1": "\u1169\u1169\u4E28",
  "\u1183": "\u1169\u116E",
  "\u116C": "\u1169\u4E28",
  "\u315A": "\u1169\u4E28",
  "\u315B": "\u116D",
  "\uD7B2": "\u116D\u1161",
  "\uD7B3": "\u116D\u1161\u4E28",
  "\u1184": "\u116D\u1163",
  "\u3187": "\u116D\u1163",
  "\u1186": "\u116D\u1163",
  "\u1185": "\u116D\u1163\u4E28",
  "\u3188": "\u116D\u1163\u4E28",
  "\uD7B4": "\u116D\u1165",
  "\u1187": "\u116D\u1169",
  "\u1188": "\u116D\u4E28",
  "\u3189": "\u116D\u4E28",
  "\u315C": "\u116E",
  "\u1189": "\u116E\u1161",
  "\u118A": "\u116E\u1161\u4E28",
  "\u116F": "\u116E\u1165",
  "\u315D": "\u116E\u1165",
  "\u118B": "\u116E\u1165\u30FC",
  "\u1170": "\u116E\u1165\u4E28",
  "\u315E": "\u116E\u1165\u4E28",
  "\uD7B5": "\u116E\u1167",
  "\u118C": "\u116E\u1167\u4E28",
  "\u118D": "\u116E\u116E",
  "\u1171": "\u116E\u4E28",
  "\u315F": "\u116E\u4E28",
  "\uD7B6": "\u116E\u4E28\u4E28",
  "\u3160": "\u1172",
  "\u118E": "\u1172\u1161",
  "\uD7B7": "\u1172\u1161\u4E28",
  "\u118F": "\u1172\u1165",
  "\u1190": "\u1172\u1165\u4E28",
  "\u1191": "\u1172\u1167",
  "\u318A": "\u1172\u1167",
  "\u1192": "\u1172\u1167\u4E28",
  "\u318B": "\u1172\u1167\u4E28",
  "\uD7B8": "\u1172\u1169",
  "\u1193": "\u1172\u116E",
  "\u1194": "\u1172\u4E28",
  "\u318C": "\u1172\u4E28",
  "\u318D": "\u119E",
  "\uD7C5": "\u119E\u1161",
  "\u119F": "\u119E\u1165",
  "\uD7C6": "\u119E\u1165\u4E28",
  "\u11A0": "\u119E\u116E",
  "\u11A2": "\u119E\u119E",
  "\u11A1": "\u119E\u4E28",
  "\u318E": "\u119E\u4E28",
  "\u30D8": "\u3078",
  "\u2341": "\u303C",
  "\u29C4": "\u303C",
  "\uA49E": "\uA04A",
  "\uA4AC": "\uA050",
  "\uA49C": "\uA0C0",
  "\uA4A8": "\uA132",
  "\uA4BF": "\uA259",
  "\uA4BE": "\uA2B1",
  "\uA494": "\uA2CD",
  "\uA4C0": "\uA3AB",
  "\uA4C2": "\uA3B5",
  "\uA4BA": "\uA3BF",
  "\uA4B0": "\uA3C2",
  "\uA4A7": "\uA458",
  "\u22A5": "\uA4D5",
  "\u27C2": "\uA4D5",
  "\u{1D21C}": "\uA4D5",
  "\uA7B1": "\uA4D5",
  "\uA79E": "\uA4E4",
  "\u2141": "\uA4E8",
  "\u2142": "\uA4F6",
  "\u{1D215}": "\uA4F6",
  "\u{1D22B}": "\uA4F6",
  "\u{16F26}": "\uA4F6",
  "\u{10411}": "\uA4F6",
  "\u2143": "\u{16F00}",
  "\u{11AE6}": "\u{11AE5}\u{11AEF}",
  "\u{11AE8}": "\u{11AE5}\u{11AE5}",
  "\u{11AE9}": "\u{11AE5}\u{11AE5}\u{11AEF}",
  "\u{11AEA}": "\u{11AE5}\u{11AE5}\u{11AF0}",
  "\u{11AE7}": "\u{11AE5}\u{11AF0}",
  "\u{11AF4}": "\u{11AF3}\u{11AEF}",
  "\u{11AF6}": "\u{11AF3}\u{11AF3}",
  "\u{11AF7}": "\u{11AF3}\u{11AF3}\u{11AEF}",
  "\u{11AF8}": "\u{11AF3}\u{11AF3}\u{11AF0}",
  "\u{11AF5}": "\u{11AF3}\u{11AF0}",
  "\u{11AEC}": "\u{11AEB}\u{11AEF}",
  "\u{11AED}": "\u{11AEB}\u{11AEB}",
  "\u{11AEE}": "\u{11AEB}\u{11AEB}\u{11AEF}",
  "\u2295": "\u{102A8}",
  "\u2A01": "\u{102A8}",
  "\u{1F728}": "\u{102A8}",
  "\uA69A": "\u{102A8}",
  "\u25BD": "\u{102BC}",
  "\u{1D214}": "\u{102BC}",
  "\u{1F704}": "\u{102BC}",
  "\u29D6": "\u{102C0}",
  "\uA79B": "\u{1043A}",
  "\uA79A": "\u{10412}",
  "\u{104A0}": "\u{10486}",
  "\u{103D1}": "\u{10382}",
  "\u{103D3}": "\u{10393}",
  "\u{12038}": "\u{1039A}",
  "\u2625": "\u{1099E}",
  "\u{132F9}": "\u{1099E}",
  "\u3039": "\u5344",
  "\uF967": "\u4E0D",
  "\u{2F800}": "\u4E3D",
  "\uFA70": "\u4E26",
  "\u239C": "\u4E28",
  "\u239F": "\u4E28",
  "\u23A2": "\u4E28",
  "\u23A5": "\u4E28",
  "\u23AA": "\u4E28",
  "\u23AE": "\u4E28",
  "\u31D1": "\u4E28",
  "\u1175": "\u4E28",
  "\u3163": "\u4E28",
  "\u2F01": "\u4E28",
  "\u119C": "\u4E28\u30FC",
  "\u1198": "\u4E28\u1161",
  "\u1199": "\u4E28\u1163",
  "\uD7BD": "\u4E28\u1163\u1169",
  "\uD7BE": "\u4E28\u1163\u4E28",
  "\uD7BF": "\u4E28\u1167",
  "\uD7C0": "\u4E28\u1167\u4E28",
  "\u119A": "\u4E28\u1169",
  "\uD7C1": "\u4E28\u1169\u4E28",
  "\uD7C2": "\u4E28\u116D",
  "\u119B": "\u4E28\u116E",
  "\uD7C3": "\u4E28\u1172",
  "\u119D": "\u4E28\u119E",
  "\uD7C4": "\u4E28\u4E28",
  "\uF905": "\u4E32",
  "\u{2F801}": "\u4E38",
  "\uF95E": "\u4E39",
  "\u{2F802}": "\u4E41",
  "\u31E0": "\u4E59",
  "\u2F04": "\u4E59",
  "\u31DF": "\u4E5A",
  "\u2E83": "\u4E5A",
  "\u31D6": "\u4E5B",
  "\u2E82": "\u4E5B",
  "\u2EF2": "\u4E80",
  "\uF91B": "\u4E82",
  "\u31DA": "\u4E85",
  "\u2F05": "\u4E85",
  "\uF9BA": "\u4E86",
  "\u30CB": "\u4E8C",
  "\u2F06": "\u4E8C",
  "\u{2F803}": "\u{20122}",
  "\u2F07": "\u4EA0",
  "\uF977": "\u4EAE",
  "\u2F08": "\u4EBA",
  "\u30A4": "\u4EBB",
  "\u2E85": "\u4EBB",
  "\uF9FD": "\u4EC0",
  "\u{2F819}": "\u4ECC",
  "\uF9A8": "\u4EE4",
  "\u{2F804}": "\u4F60",
  "\u5002": "\u4F75",
  "\u{2F807}": "\u4F75",
  "\uFA73": "\u4F80",
  "\uF92D": "\u4F86",
  "\uF9B5": "\u4F8B",
  "\uFA30": "\u4FAE",
  "\u{2F805}": "\u4FAE",
  "\u{2F806}": "\u4FBB",
  "\uF965": "\u4FBF",
  "\u503C": "\u5024",
  "\uF9D4": "\u502B",
  "\u{2F808}": "\u507A",
  "\u{2F809}": "\u5099",
  "\u{2F80B}": "\u50CF",
  "\uF9BB": "\u50DA",
  "\uFA31": "\u50E7",
  "\u{2F80A}": "\u50E7",
  "\u{2F80C}": "\u349E",
  "\u2F09": "\u513F",
  "\uFA0C": "\u5140",
  "\u2E8E": "\u5140",
  "\uFA74": "\u5145",
  "\uFA32": "\u514D",
  "\u{2F80E}": "\u514D",
  "\u{2F80F}": "\u5154",
  "\u{2F810}": "\u5164",
  "\u2F0A": "\u5165",
  "\u{2F814}": "\u5167",
  "\uFA72": "\u5168",
  "\uF978": "\u5169",
  "\u30CF": "\u516B",
  "\u2F0B": "\u516B",
  "\uF9D1": "\u516D",
  "\u{2F811}": "\u5177",
  "\u{2F812}": "\u{2051C}",
  "\u{2F91B}": "\u{20525}",
  "\uFA75": "\u5180",
  "\u{2F813}": "\u34B9",
  "\u2F0C": "\u5182",
  "\u{2F815}": "\u518D",
  "\u{2F816}": "\u{2054B}",
  "\u{2F8D2}": "\u5192",
  "\u{2F8D3}": "\u5195",
  "\u{2F9CA}": "\u34BB",
  "\u{2F8D4}": "\u6700",
  "\u2F0D": "\u5196",
  "\u{2F817}": "\u5197",
  "\u{2F818}": "\u51A4",
  "\u2F0E": "\u51AB",
  "\u{2F81A}": "\u51AC",
  "\uFA71": "\u51B5",
  "\u{2F81B}": "\u51B5",
  "\uF92E": "\u51B7",
  "\uF979": "\u51C9",
  "\uF955": "\u51CC",
  "\uF954": "\u51DC",
  "\uFA15": "\u51DE",
  "\u2F0F": "\u51E0",
  "\u{2F80D}": "\u{2063A}",
  "\u{2F81D}": "\u51F5",
  "\u2F10": "\u51F5",
  "\u2F11": "\u5200",
  "\u2E89": "\u5202",
  "\u{2F81E}": "\u5203",
  "\uFA00": "\u5207",
  "\u{2F850}": "\u5207",
  "\uF99C": "\u5217",
  "\uF9DD": "\u5229",
  "\u{2F81F}": "\u34DF",
  "\uF9FF": "\u523A",
  "\u{2F820}": "\u523B",
  "\u{2F821}": "\u5246",
  "\u{2F822}": "\u5272",
  "\u{2F823}": "\u5277",
  "\uF9C7": "\u5289",
  "\u{2F9D9}": "\u{20804}",
  "\u30AB": "\u529B",
  "\uF98A": "\u529B",
  "\u2F12": "\u529B",
  "\uF99D": "\u52A3",
  "\u{2F824}": "\u3515",
  "\u{2F992}": "\u52B3",
  "\uFA76": "\u52C7",
  "\u{2F825}": "\u52C7",
  "\uFA33": "\u52C9",
  "\u{2F826}": "\u52C9",
  "\uF952": "\u52D2",
  "\uF92F": "\u52DE",
  "\uFA34": "\u52E4",
  "\u{2F827}": "\u52E4",
  "\uF97F": "\u52F5",
  "\u2F13": "\u52F9",
  "\uFA77": "\u52FA",
  "\u{2F828}": "\u52FA",
  "\u{2F829}": "\u5305",
  "\u{2F82A}": "\u5306",
  "\u{2F9DD}": "\u{208DE}",
  "\u2F14": "\u5315",
  "\uF963": "\u5317",
  "\u{2F82B}": "\u5317",
  "\u2F15": "\u531A",
  "\u2F16": "\u5338",
  "\uF9EB": "\u533F",
  "\u2F17": "\u5341",
  "\u3038": "\u5341",
  "\u303A": "\u5345",
  "\u{2F82C}": "\u5349",
  "\u0FD6": "\u534D",
  "\u0FD5": "\u5350",
  "\uFA35": "\u5351",
  "\u{2F82D}": "\u5351",
  "\u{2F82E}": "\u535A",
  "\u30C8": "\u535C",
  "\u2F18": "\u535C",
  "\u2F19": "\u5369",
  "\u2E8B": "\u353E",
  "\u{2F82F}": "\u5373",
  "\uF91C": "\u5375",
  "\u{2F830}": "\u537D",
  "\u{2F831}": "\u537F",
  "\u{2F832}": "\u537F",
  "\u{2F833}": "\u537F",
  "\u2F1A": "\u5382",
  "\u{2F834}": "\u{20A2C}",
  "\u2F1B": "\u53B6",
  "\uF96B": "\u53C3",
  "\u2F1C": "\u53C8",
  "\u{2F836}": "\u53CA",
  "\u{2F837}": "\u53DF",
  "\u{2F838}": "\u{20B63}",
  "\u30ED": "\u53E3",
  "\u2F1D": "\u53E3",
  "\u56D7": "\u53E3",
  "\u2F1E": "\u53E3",
  "\uF906": "\u53E5",
  "\u{2F839}": "\u53EB",
  "\u{2F83A}": "\u53F1",
  "\u{2F83B}": "\u5406",
  "\uF9DE": "\u540F",
  "\uF9ED": "\u541D",
  "\u{2F83D}": "\u5438",
  "\uF980": "\u5442",
  "\u{2F83E}": "\u5448",
  "\u{2F83F}": "\u5468",
  "\u{2F83C}": "\u549E",
  "\u{2F840}": "\u54A2",
  "\uF99E": "\u54BD",
  "\u439B": "\u3588",
  "\u{2F841}": "\u54F6",
  "\u{2F842}": "\u5510",
  "\u{2F843}": "\u5553",
  "\u555F": "\u5553",
  "\uFA79": "\u5555",
  "\u{2F844}": "\u5563",
  "\u{2F845}": "\u5584",
  "\u{2F846}": "\u5584",
  "\uF90B": "\u5587",
  "\uFA7A": "\u5599",
  "\u{2F847}": "\u5599",
  "\uFA36": "\u559D",
  "\uFA78": "\u559D",
  "\u{2F848}": "\u55AB",
  "\u{2F849}": "\u55B3",
  "\uFA0D": "\u55C0",
  "\u{2F84A}": "\u55C2",
  "\uFA7B": "\u55E2",
  "\uFA37": "\u5606",
  "\u{2F84C}": "\u5606",
  "\u{2F84E}": "\u5651",
  "\u{2F84F}": "\u5674",
  "\uFA38": "\u5668",
  "\uF9A9": "\u56F9",
  "\u{2F84B}": "\u5716",
  "\u{2F84D}": "\u5717",
  "\u2F1F": "\u571F",
  "\u58EB": "\u571F",
  "\u2F20": "\u571F",
  "\u{2F855}": "\u578B",
  "\u{2F852}": "\u57CE",
  "\u39B3": "\u363D",
  "\u{2F853}": "\u57F4",
  "\u{2F854}": "\u580D",
  "\u{2F857}": "\u5831",
  "\u{2F856}": "\u5832",
  "\uFA39": "\u5840",
  "\uFA10": "\u585A",
  "\uFA7C": "\u585A",
  "\uF96C": "\u585E",
  "\u586B": "\u5861",
  "\u58FF": "\u58AB",
  "\u{2F858}": "\u58AC",
  "\uFA7D": "\u58B3",
  "\uF94A": "\u58D8",
  "\uF942": "\u58DF",
  "\u{2F859}": "\u{214E4}",
  "\u{2F851}": "\u58EE",
  "\u{2F85A}": "\u58F2",
  "\u{2F85B}": "\u58F7",
  "\u2F21": "\u5902",
  "\u{2F85C}": "\u5906",
  "\u2F22": "\u590A",
  "\u30BF": "\u5915",
  "\u2F23": "\u5915",
  "\u{2F85D}": "\u591A",
  "\u{2F85E}": "\u5922",
  "\u2F24": "\u5927",
  "\uFA7E": "\u5944",
  "\uF90C": "\u5948",
  "\uF909": "\u5951",
  "\uFA7F": "\u5954",
  "\u{2F85F}": "\u5962",
  "\uF981": "\u5973",
  "\u2F25": "\u5973",
  "\u{2F860}": "\u{216A8}",
  "\u{2F861}": "\u{216EA}",
  "\u{2F865}": "\u59D8",
  "\u{2F862}": "\u59EC",
  "\u{2F863}": "\u5A1B",
  "\u{2F864}": "\u5A27",
  "\uFA80": "\u5A62",
  "\u{2F866}": "\u5A66",
  "\u5B00": "\u5AAF",
  "\u{2F867}": "\u36EE",
  "\u{2F868}": "\u36FC",
  "\u{2F986}": "\u5AB5",
  "\u{2F869}": "\u5B08",
  "\uFA81": "\u5B28",
  "\u{2F86A}": "\u5B3E",
  "\u{2F86B}": "\u5B3E",
  "\u2F26": "\u5B50",
  "\u2F27": "\u5B80",
  "\uFA04": "\u5B85",
  "\u{2F86C}": "\u{219C8}",
  "\u{2F86D}": "\u5BC3",
  "\u{2F86E}": "\u5BD8",
  "\uF95F": "\u5BE7",
  "\uF9AA": "\u5BE7",
  "\u{2F86F}": "\u5BE7",
  "\uF9BC": "\u5BEE",
  "\u{2F870}": "\u5BF3",
  "\u{2F871}": "\u{21B18}",
  "\u2F28": "\u5BF8",
  "\u{2F872}": "\u5BFF",
  "\u{2F873}": "\u5C06",
  "\u2F29": "\u5C0F",
  "\u{2F875}": "\u5C22",
  "\u2E90": "\u5C22",
  "\u2F2A": "\u5C22",
  "\u2E8F": "\u5C23",
  "\u{2F876}": "\u3781",
  "\u2F2B": "\u5C38",
  "\uF9BD": "\u5C3F",
  "\u{2F877}": "\u5C60",
  "\uF94B": "\u5C62",
  "\uFA3B": "\u5C64",
  "\uF9DF": "\u5C65",
  "\uFA3C": "\u5C6E",
  "\u{2F878}": "\u5C6E",
  "\u2F2C": "\u5C6E",
  "\u{2F8F8}": "\u{21D0B}",
  "\u2F2D": "\u5C71",
  "\u{2F879}": "\u5CC0",
  "\u{2F87A}": "\u5C8D",
  "\u{2F87B}": "\u{21DE4}",
  "\u{2F87D}": "\u{21DE6}",
  "\uF9D5": "\u5D19",
  "\u{2F87C}": "\u5D43",
  "\uF921": "\u5D50",
  "\u{2F87F}": "\u5D6B",
  "\u{2F87E}": "\u5D6E",
  "\u{2F880}": "\u5D7C",
  "\u{2F9F4}": "\u5DB2",
  "\uF9AB": "\u5DBA",
  "\u2F2E": "\u5DDB",
  "\u{2F882}": "\u5DE2",
  "\u30A8": "\u5DE5",
  "\u2F2F": "\u5DE5",
  "\u2F30": "\u5DF1",
  "\u2E92": "\u5DF3",
  "\u{2F883}": "\u382F",
  "\u{2F884}": "\u5DFD",
  "\u2F31": "\u5DFE",
  "\u5E32": "\u5E21",
  "\u{2F885}": "\u5E28",
  "\u{2F886}": "\u5E3D",
  "\u{2F887}": "\u5E69",
  "\u{2F888}": "\u3862",
  "\u{2F889}": "\u{22183}",
  "\u2F32": "\u5E72",
  "\uF98E": "\u5E74",
  "\u{2F939}": "\u{2219F}",
  "\u2E93": "\u5E7A",
  "\u2F33": "\u5E7A",
  "\u2F34": "\u5E7F",
  "\uFA01": "\u5EA6",
  "\u{2F88A}": "\u387C",
  "\u{2F88B}": "\u5EB0",
  "\u{2F88C}": "\u5EB3",
  "\u{2F88D}": "\u5EB6",
  "\uF928": "\u5ECA",
  "\u{2F88E}": "\u5ECA",
  "\uF9A2": "\u5EC9",
  "\uFA82": "\u5ED2",
  "\uFA0B": "\u5ED3",
  "\uFA83": "\u5ED9",
  "\uF982": "\u5EEC",
  "\u2F35": "\u5EF4",
  "\u{2F890}": "\u5EFE",
  "\u2F36": "\u5EFE",
  "\u{2F891}": "\u{22331}",
  "\u{2F892}": "\u{22331}",
  "\uF943": "\u5F04",
  "\u2F37": "\u5F0B",
  "\u2F38": "\u5F13",
  "\u{2F894}": "\u5F22",
  "\u{2F895}": "\u5F22",
  "\u2F39": "\u5F50",
  "\u2E94": "\u5F51",
  "\u{2F874}": "\u5F53",
  "\u{2F896}": "\u38C7",
  "\u2F3A": "\u5F61",
  "\u{2F899}": "\u5F62",
  "\uFA84": "\u5F69",
  "\u{2F89A}": "\u5F6B",
  "\u2F3B": "\u5F73",
  "\uF9D8": "\u5F8B",
  "\u{2F89B}": "\u38E3",
  "\u{2F89C}": "\u5F9A",
  "\uF966": "\u5FA9",
  "\uFA85": "\u5FAD",
  "\u2F3C": "\u5FC3",
  "\u2E96": "\u5FC4",
  "\u2E97": "\u38FA",
  "\u{2F89D}": "\u5FCD",
  "\u{2F89E}": "\u5FD7",
  "\uF9A3": "\u5FF5",
  "\u{2F89F}": "\u5FF9",
  "\uF960": "\u6012",
  "\uF9AC": "\u601C",
  "\uFA6B": "\u6075",
  "\u{2F8A2}": "\u391C",
  "\u{2F8A1}": "\u393A",
  "\u{2F8A0}": "\u6081",
  "\uFA3D": "\u6094",
  "\u{2F8A3}": "\u6094",
  "\u{2F8A5}": "\u60C7",
  "\uFA86": "\u60D8",
  "\uF9B9": "\u60E1",
  "\u{2F8A4}": "\u{226D4}",
  "\uFA88": "\u6108",
  "\uFA3E": "\u6168",
  "\uF9D9": "\u6144",
  "\u{2F8A6}": "\u6148",
  "\u{2F8A7}": "\u614C",
  "\u{2F8A9}": "\u614C",
  "\uFA87": "\u614E",
  "\u{2F8A8}": "\u614E",
  "\uFA8A": "\u6160",
  "\u{2F8AA}": "\u617A",
  "\uFA3F": "\u618E",
  "\uFA89": "\u618E",
  "\u{2F8AB}": "\u618E",
  "\uF98F": "\u6190",
  "\u{2F8AD}": "\u61A4",
  "\u{2F8AE}": "\u61AF",
  "\u{2F8AC}": "\u61B2",
  "\uFAD0": "\u{22844}",
  "\uFACF": "\u{2284A}",
  "\u{2F8AF}": "\u61DE",
  "\uFA40": "\u61F2",
  "\uFA8B": "\u61F2",
  "\u{2F8B0}": "\u61F2",
  "\uF90D": "\u61F6",
  "\u{2F8B1}": "\u61F6",
  "\uF990": "\u6200",
  "\u2F3D": "\u6208",
  "\u{2F8B2}": "\u6210",
  "\u{2F8B3}": "\u621B",
  "\uF9D2": "\u622E",
  "\uFA8C": "\u6234",
  "\u2F3E": "\u6236",
  "\u6238": "\u6236",
  "\u2F3F": "\u624B",
  "\u2E98": "\u624C",
  "\u{2F8B4}": "\u625D",
  "\u{2F8B5}": "\u62B1",
  "\uF925": "\u62C9",
  "\uF95B": "\u62CF",
  "\uFA02": "\u62D3",
  "\u{2F8B6}": "\u62D4",
  "\u{2F8BA}": "\u62FC",
  "\uF973": "\u62FE",
  "\u{2F8B8}": "\u{22B0C}",
  "\u{2F8B9}": "\u633D",
  "\u{2F8B7}": "\u6350",
  "\u{2F8BB}": "\u6368",
  "\uF9A4": "\u637B",
  "\u{2F8BC}": "\u6383",
  "\uF975": "\u63A0",
  "\u{2F8C1}": "\u63A9",
  "\uFA8D": "\u63C4",
  "\u{2F8BD}": "\u63E4",
  "\uFA8F": "\u6452",
  "\u{2F8BE}": "\u{22BF1}",
  "\uFA8E": "\u641C",
  "\u{2F8BF}": "\u6422",
  "\u{2F8C0}": "\u63C5",
  "\u{2F8C3}": "\u6469",
  "\u{2F8C6}": "\u6477",
  "\u{2F8C4}": "\u647E",
  "\u{2F8C2}": "\u3A2E",
  "\u6409": "\u3A41",
  "\uF991": "\u649A",
  "\u{2F8C5}": "\u649D",
  "\uF930": "\u64C4",
  "\u{2F8C7}": "\u3A6C",
  "\u2F40": "\u652F",
  "\u2F41": "\u6534",
  "\u2E99": "\u6535",
  "\uFA41": "\u654F",
  "\u{2F8C8}": "\u654F",
  "\uFA90": "\u6556",
  "\u{2F8C9}": "\u656C",
  "\uF969": "\u6578",
  "\u{2F8CA}": "\u{2300A}",
  "\u2F42": "\u6587",
  "\u2EEB": "\u6589",
  "\u2F43": "\u6597",
  "\uF9BE": "\u6599",
  "\u2F44": "\u65A4",
  "\u2F45": "\u65B9",
  "\uF983": "\u65C5",
  "\u2F46": "\u65E0",
  "\u2E9B": "\u65E1",
  "\uFA42": "\u65E2",
  "\u{2F8CB}": "\u65E3",
  "\u2F47": "\u65E5",
  "\uF9E0": "\u6613",
  "\u66F6": "\u3ADA",
  "\u{2F8D1}": "\u3AE4",
  "\u{2F8CD}": "\u6649",
  "\u6669": "\u665A",
  "\uFA12": "\u6674",
  "\uFA91": "\u6674",
  "\uFA43": "\u6691",
  "\u{2F8CF}": "\u6691",
  "\uF9C5": "\u6688",
  "\u{2F8D0}": "\u3B08",
  "\u{2F8D5}": "\u669C",
  "\uFA06": "\u66B4",
  "\uF98B": "\u66C6",
  "\u{2F8CE}": "\u3B19",
  "\u{2F897}": "\u{232B8}",
  "\u2F48": "\u66F0",
  "\uF901": "\u66F4",
  "\u{2F8CC}": "\u66F8",
  "\u2F49": "\u6708",
  "\u{2F980}": "\u{2335F}",
  "\u80A6": "\u670C",
  "\u80D0": "\u670F",
  "\u80CA": "\u6710",
  "\u8101": "\u6713",
  "\u80F6": "\u3B35",
  "\uF929": "\u6717",
  "\uFA92": "\u6717",
  "\u{2F8D8}": "\u6717",
  "\u8127": "\u6718",
  "\uFA93": "\u671B",
  "\u{2F8D9}": "\u671B",
  "\u5E50": "\u3B3A",
  "\u4420": "\u3B3B",
  "\u{2F989}": "\u{23393}",
  "\u81A7": "\u6723",
  "\u{2F98A}": "\u{2339C}",
  "\u2F4A": "\u6728",
  "\uF9E1": "\u674E",
  "\u{2F8DC}": "\u6753",
  "\uFA94": "\u6756",
  "\u{2F8DB}": "\u675E",
  "\u{2F8DD}": "\u{233C3}",
  "\u67FF": "\u676E",
  "\uF9C8": "\u677B",
  "\u{2F8E0}": "\u6785",
  "\uF9F4": "\u6797",
  "\u{2F8DE}": "\u3B49",
  "\uFAD1": "\u{233D5}",
  "\uF9C9": "\u67F3",
  "\u{2F8DF}": "\u67FA",
  "\uF9DA": "\u6817",
  "\u{2F8E5}": "\u681F",
  "\u{2F8E1}": "\u6852",
  "\u{2F8E3}": "\u{2346D}",
  "\uF97A": "\u6881",
  "\uFA44": "\u6885",
  "\u{2F8E2}": "\u6885",
  "\u{2F8E4}": "\u688E",
  "\uF9E2": "\u68A8",
  "\u{2F8E6}": "\u6914",
  "\u{2F8E8}": "\u6942",
  "\uFAD2": "\u3B9D",
  "\u{2F8E7}": "\u3B9D",
  "\u69E9": "\u3BA3",
  "\u6A27": "\u699D",
  "\u{2F8E9}": "\u69A3",
  "\u{2F8EA}": "\u69EA",
  "\uF914": "\u6A02",
  "\uF95C": "\u6A02",
  "\uF9BF": "\u6A02",
  "\uF94C": "\u6A13",
  "\u{2F8EC}": "\u{236A3}",
  "\u{2F8EB}": "\u6AA8",
  "\uF931": "\u6AD3",
  "\u{2F8ED}": "\u6ADB",
  "\uF91D": "\u6B04",
  "\u{2F8EE}": "\u3C18",
  "\u2F4B": "\u6B20",
  "\u{2F8EF}": "\u6B21",
  "\u{2F8F0}": "\u{238A7}",
  "\u{2F8F1}": "\u6B54",
  "\u{2F8F2}": "\u3C4E",
  "\u2F4C": "\u6B62",
  "\u2EED": "\u6B6F",
  "\u{2F8F3}": "\u6B72",
  "\uF98C": "\u6B77",
  "\uFA95": "\u6B79",
  "\u2F4D": "\u6B79",
  "\u2E9E": "\u6B7A",
  "\u{2F8F4}": "\u6B9F",
  "\uF9A5": "\u6BAE",
  "\u2F4E": "\u6BB3",
  "\uF970": "\u6BBA",
  "\uFA96": "\u6BBA",
  "\u{2F8F5}": "\u6BBA",
  "\u{2F8F6}": "\u6BBB",
  "\u{2F8F7}": "\u{23A8D}",
  "\u2F4F": "\u6BCB",
  "\u2E9F": "\u6BCD",
  "\u{2F8F9}": "\u{23AFA}",
  "\u2F50": "\u6BD4",
  "\u2F51": "\u6BDB",
  "\u2F52": "\u6C0F",
  "\u2EA0": "\u6C11",
  "\u2F53": "\u6C14",
  "\u2F54": "\u6C34",
  "\u2EA1": "\u6C35",
  "\u2EA2": "\u6C3A",
  "\u{2F8FA}": "\u6C4E",
  "\u{2F8FE}": "\u6C67",
  "\uF972": "\u6C88",
  "\u{2F8FC}": "\u6CBF",
  "\uF968": "\u6CCC",
  "\u{2F8FD}": "\u6CCD",
  "\uF9E3": "\u6CE5",
  "\u{2F8FB}": "\u{23CBC}",
  "\uF915": "\u6D1B",
  "\uFA05": "\u6D1E",
  "\u{2F907}": "\u6D34",
  "\u{2F900}": "\u6D3E",
  "\uF9CA": "\u6D41",
  "\uFA97": "\u6D41",
  "\u{2F902}": "\u6D41",
  "\u{2F8FF}": "\u6D16",
  "\u{2F903}": "\u6D69",
  "\uF92A": "\u6D6A",
  "\uFA45": "\u6D77",
  "\u{2F901}": "\u6D77",
  "\u{2F904}": "\u6D78",
  "\u{2F905}": "\u6D85",
  "\u{2F906}": "\u{23D1E}",
  "\uF9F5": "\u6DCB",
  "\uF94D": "\u6DDA",
  "\uF9D6": "\u6DEA",
  "\u{2F90E}": "\u6DF9",
  "\uFA46": "\u6E1A",
  "\u{2F908}": "\u6E2F",
  "\u{2F909}": "\u6E6E",
  "\u6F59": "\u6E88",
  "\uFA99": "\u6ECB",
  "\u{2F90B}": "\u6ECB",
  "\uF9CB": "\u6E9C",
  "\uF9EC": "\u6EBA",
  "\u{2F90C}": "\u6EC7",
  "\uF904": "\u6ED1",
  "\uFA98": "\u6EDB",
  "\u{2F90A}": "\u3D33",
  "\uF94E": "\u6F0F",
  "\uFA47": "\u6F22",
  "\uFA9A": "\u6F22",
  "\uF992": "\u6F23",
  "\u{2F90D}": "\u{23ED1}",
  "\u{2F90F}": "\u6F6E",
  "\u{2F910}": "\u{23F5E}",
  "\u{2F911}": "\u{23F8E}",
  "\u{2F912}": "\u6FC6",
  "\uF922": "\u6FEB",
  "\uF984": "\u6FFE",
  "\u{2F915}": "\u701B",
  "\uFA9B": "\u701E",
  "\u{2F914}": "\u701E",
  "\u{2F913}": "\u7039",
  "\u{2F917}": "\u704A",
  "\u{2F916}": "\u3D96",
  "\u2F55": "\u706B",
  "\u2EA3": "\u706C",
  "\u{2F835}": "\u7070",
  "\u{2F919}": "\u7077",
  "\u{2F918}": "\u707D",
  "\uF9FB": "\u7099",
  "\u{2F91A}": "\u70AD",
  "\uF99F": "\u70C8",
  "\uF916": "\u70D9",
  "\uFA48": "\u716E",
  "\uFA9C": "\u716E",
  "\u{2F91D}": "\u{24263}",
  "\u{2F91C}": "\u7145",
  "\uF993": "\u7149",
  "\uFA6C": "\u{242EE}",
  "\u{2F91E}": "\u719C",
  "\uF9C0": "\u71CE",
  "\uF9EE": "\u71D0",
  "\u{2F91F}": "\u{243AB}",
  "\uF932": "\u7210",
  "\uF91E": "\u721B",
  "\u{2F920}": "\u7228",
  "\u2F56": "\u722A",
  "\uFA49": "\u722B",
  "\u2EA4": "\u722B",
  "\uFA9E": "\u7235",
  "\u{2F921}": "\u7235",
  "\u2F57": "\u7236",
  "\u2F58": "\u723B",
  "\u2EA6": "\u4E2C",
  "\u2F59": "\u723F",
  "\u2F5A": "\u7247",
  "\u{2F922}": "\u7250",
  "\u2F5B": "\u7259",
  "\u{2F923}": "\u{24608}",
  "\u2F5C": "\u725B",
  "\uF946": "\u7262",
  "\u{2F924}": "\u7280",
  "\u{2F925}": "\u7295",
  "\u2F5D": "\u72AC",
  "\u2EA8": "\u72AD",
  "\uFA9F": "\u72AF",
  "\uF9FA": "\u72C0",
  "\u{2F926}": "\u{24735}",
  "\uF92B": "\u72FC",
  "\uFA16": "\u732A",
  "\uFAA0": "\u732A",
  "\u{2F927}": "\u{24814}",
  "\uF9A7": "\u7375",
  "\u{2F928}": "\u737A",
  "\u2F5E": "\u7384",
  "\uF961": "\u7387",
  "\uF9DB": "\u7387",
  "\u2F5F": "\u7389",
  "\u{2F929}": "\u738B",
  "\u{2F92A}": "\u3EAC",
  "\u{2F92B}": "\u73A5",
  "\uF9AD": "\u73B2",
  "\u{2F92C}": "\u3EB8",
  "\u{2F92D}": "\u3EB8",
  "\uF917": "\u73DE",
  "\uF9CC": "\u7409",
  "\uF9E4": "\u7406",
  "\uFA4A": "\u7422",
  "\u{2F92E}": "\u7447",
  "\u{2F92F}": "\u745C",
  "\uF9AE": "\u7469",
  "\uFAA1": "\u7471",
  "\u{2F930}": "\u7471",
  "\u{2F931}": "\u7485",
  "\uF994": "\u7489",
  "\uF9EF": "\u7498",
  "\u{2F932}": "\u74CA",
  "\u2F60": "\u74DC",
  "\u2F61": "\u74E6",
  "\u{2F933}": "\u3F1B",
  "\uFAA2": "\u7506",
  "\u2F62": "\u7518",
  "\u2F63": "\u751F",
  "\u{2F934}": "\u7524",
  "\u2F64": "\u7528",
  "\u2F65": "\u7530",
  "\uFAA3": "\u753B",
  "\u{2F936}": "\u753E",
  "\u{2F935}": "\u{24C36}",
  "\uF9CD": "\u7559",
  "\uF976": "\u7565",
  "\uF962": "\u7570",
  "\u{2F938}": "\u7570",
  "\u{2F937}": "\u{24C92}",
  "\u2F66": "\u758B",
  "\u2F67": "\u7592",
  "\uF9E5": "\u75E2",
  "\u{2F93A}": "\u7610",
  "\uFAA5": "\u761F",
  "\uFAA4": "\u761D",
  "\uF9C1": "\u7642",
  "\uF90E": "\u7669",
  "\u2F68": "\u7676",
  "\u2F69": "\u767D",
  "\u{2F93B}": "\u{24FA1}",
  "\u{2F93C}": "\u{24FB8}",
  "\u2F6A": "\u76AE",
  "\u2F6B": "\u76BF",
  "\u{2F93D}": "\u{25044}",
  "\u{2F93E}": "\u3FFC",
  "\uFA17": "\u76CA",
  "\uFAA6": "\u76CA",
  "\uFAA7": "\u76DB",
  "\uF933": "\u76E7",
  "\u{2F93F}": "\u4008",
  "\u2F6C": "\u76EE",
  "\uFAA8": "\u76F4",
  "\u{2F940}": "\u76F4",
  "\u{2F942}": "\u{250F2}",
  "\u{2F941}": "\u{250F3}",
  "\uF96D": "\u7701",
  "\uFAD3": "\u4018",
  "\u{2F943}": "\u{25119}",
  "\u{2F945}": "\u771E",
  "\u{2F946}": "\u771F",
  "\u{2F947}": "\u771F",
  "\u{2F944}": "\u{25133}",
  "\uFAAA": "\u7740",
  "\uFAA9": "\u774A",
  "\u{2F948}": "\u774A",
  "\u9FC3": "\u4039",
  "\uFAD4": "\u4039",
  "\u{2F949}": "\u4039",
  "\u6663": "\u403F",
  "\u{2F94B}": "\u4046",
  "\u{2F94A}": "\u778B",
  "\uFAD5": "\u{25249}",
  "\uFA9D": "\u77A7",
  "\u2F6D": "\u77DB",
  "\u2F6E": "\u77E2",
  "\u2F6F": "\u77F3",
  "\u{2F94C}": "\u4096",
  "\u{2F94D}": "\u{2541D}",
  "\u784F": "\u7814",
  "\u{2F94E}": "\u784E",
  "\uF9CE": "\u786B",
  "\uF93B": "\u788C",
  "\u{2F94F}": "\u788C",
  "\uFA4B": "\u7891",
  "\uF947": "\u78CA",
  "\uFAAB": "\u78CC",
  "\u{2F950}": "\u78CC",
  "\uF964": "\u78FB",
  "\u{2F951}": "\u40E3",
  "\uF985": "\u792A",
  "\u2F70": "\u793A",
  "\u2EAD": "\u793B",
  "\uFA18": "\u793C",
  "\uFA4C": "\u793E",
  "\uFA4E": "\u7948",
  "\uFA4D": "\u7949",
  "\u{2F952}": "\u{25626}",
  "\uFA4F": "\u7950",
  "\uFA50": "\u7956",
  "\u{2F953}": "\u7956",
  "\uFA51": "\u795D",
  "\uFA19": "\u795E",
  "\uFA1A": "\u7965",
  "\uFA61": "\u8996",
  "\uFAB8": "\u8996",
  "\uF93C": "\u797F",
  "\u{2F954}": "\u{2569A}",
  "\uFA52": "\u798D",
  "\uFA53": "\u798E",
  "\uFA1B": "\u798F",
  "\u{2F956}": "\u798F",
  "\u{2F955}": "\u{256C5}",
  "\uF9B6": "\u79AE",
  "\u2F71": "\u79B8",
  "\u2F72": "\u79BE",
  "\uF995": "\u79CA",
  "\u{2F958}": "\u412F",
  "\u{2F957}": "\u79EB",
  "\uF956": "\u7A1C",
  "\u{2F95A}": "\u7A4A",
  "\uFA54": "\u7A40",
  "\u{2F959}": "\u7A40",
  "\u{2F95B}": "\u7A4F",
  "\u2F73": "\u7A74",
  "\uFA55": "\u7A81",
  "\u{2F95C}": "\u{2597C}",
  "\uFAAC": "\u7AB1",
  "\uF9F7": "\u7ACB",
  "\u2F74": "\u7ACB",
  "\u2EEF": "\u7ADC",
  "\u{2F95D}": "\u{25AA7}",
  "\u{2F95E}": "\u{25AA7}",
  "\u{2F95F}": "\u7AEE",
  "\u2F75": "\u7AF9",
  "\uF9F8": "\u7B20",
  "\uFA56": "\u7BC0",
  "\uFAAD": "\u7BC0",
  "\u{2F960}": "\u4202",
  "\u{2F961}": "\u{25BAB}",
  "\u{2F962}": "\u7BC6",
  "\u{2F964}": "\u4227",
  "\u{2F963}": "\u7BC9",
  "\u{2F965}": "\u{25C80}",
  "\uFAD6": "\u{25CD0}",
  "\uF9A6": "\u7C3E",
  "\uF944": "\u7C60",
  "\u2F76": "\u7C73",
  "\uFAAE": "\u7C7B",
  "\uF9F9": "\u7C92",
  "\uFA1D": "\u7CBE",
  "\u{2F966}": "\u7CD2",
  "\uFA03": "\u7CD6",
  "\u{2F968}": "\u7CE8",
  "\u{2F967}": "\u42A0",
  "\u{2F969}": "\u7CE3",
  "\uF97B": "\u7CE7",
  "\u2F77": "\u7CF8",
  "\u2EAF": "\u7CF9",
  "\u{2F96B}": "\u{25F86}",
  "\u{2F96A}": "\u7D00",
  "\uF9CF": "\u7D10",
  "\uF96A": "\u7D22",
  "\uF94F": "\u7D2F",
  "\u7D76": "\u7D55",
  "\u{2F96C}": "\u7D63",
  "\uFAAF": "\u7D5B",
  "\uF93D": "\u7DA0",
  "\uF957": "\u7DBE",
  "\u{2F96E}": "\u7DC7",
  "\uF996": "\u7DF4",
  "\uFA57": "\u7DF4",
  "\uFAB0": "\u7DF4",
  "\u{2F96F}": "\u7E02",
  "\u{2F96D}": "\u4301",
  "\uFA58": "\u7E09",
  "\uF950": "\u7E37",
  "\uFA59": "\u7E41",
  "\u{2F970}": "\u7E45",
  "\u{2F898}": "\u{261DA}",
  "\u{2F971}": "\u4334",
  "\u2F78": "\u7F36",
  "\u{2F972}": "\u{26228}",
  "\uFAB1": "\u7F3E",
  "\u{2F973}": "\u{26247}",
  "\u2F79": "\u7F51",
  "\u2EAB": "\u7F52",
  "\u2EB2": "\u7F52",
  "\u2EB1": "\u7F53",
  "\u{2F974}": "\u4359",
  "\uFA5A": "\u7F72",
  "\u{2F975}": "\u{262D9}",
  "\uF9E6": "\u7F79",
  "\u{2F976}": "\u7F7A",
  "\uF90F": "\u7F85",
  "\u{2F977}": "\u{2633E}",
  "\u2F7A": "\u7F8A",
  "\u{2F978}": "\u7F95",
  "\uF9AF": "\u7F9A",
  "\uFA1E": "\u7FBD",
  "\u2F7B": "\u7FBD",
  "\u{2F979}": "\u7FFA",
  "\uF934": "\u8001",
  "\u2F7C": "\u8001",
  "\u2EB9": "\u8002",
  "\uFA5B": "\u8005",
  "\uFAB2": "\u8005",
  "\u{2F97A}": "\u8005",
  "\u2F7D": "\u800C",
  "\u{2F97B}": "\u{264DA}",
  "\u2F7E": "\u8012",
  "\u{2F97C}": "\u{26523}",
  "\u2F7F": "\u8033",
  "\uF9B0": "\u8046",
  "\u{2F97D}": "\u8060",
  "\u{2F97E}": "\u{265A8}",
  "\uF997": "\u806F",
  "\u{2F97F}": "\u8070",
  "\uF945": "\u807E",
  "\u2F80": "\u807F",
  "\u2EBA": "\u8080",
  "\u2F81": "\u8089",
  "\uF953": "\u808B",
  "\u{2F8D6}": "\u80AD",
  "\u{2F982}": "\u80B2",
  "\u{2F981}": "\u43D5",
  "\u{2F8D7}": "\u43D9",
  "\u8141": "\u80FC",
  "\u{2F983}": "\u8103",
  "\u{2F985}": "\u813E",
  "\u{2F984}": "\u440B",
  "\u{2F8DA}": "\u6721",
  "\u{2F987}": "\u{267A7}",
  "\u{2F988}": "\u{267B5}",
  "\u6726": "\u4443",
  "\uF926": "\u81D8",
  "\u2F82": "\u81E3",
  "\uF9F6": "\u81E8",
  "\u2F83": "\u81EA",
  "\uFA5C": "\u81ED",
  "\u2F84": "\u81F3",
  "\u2F85": "\u81FC",
  "\u{2F893}": "\u8201",
  "\u{2F98B}": "\u8201",
  "\u{2F98C}": "\u8204",
  "\u2F86": "\u820C",
  "\uFA6D": "\u8218",
  "\u2F87": "\u821B",
  "\u2F88": "\u821F",
  "\u{2F98E}": "\u446B",
  "\u2F89": "\u826E",
  "\uF97C": "\u826F",
  "\u2F8A": "\u8272",
  "\u2F8B": "\u8278",
  "\uFA5D": "\u8279",
  "\uFA5E": "\u8279",
  "\u2EBE": "\u8279",
  "\u2EBF": "\u8279",
  "\u2EC0": "\u8279",
  "\u{2F990}": "\u828B",
  "\u{2F98F}": "\u8291",
  "\u{2F991}": "\u829D",
  "\u{2F993}": "\u82B1",
  "\u{2F994}": "\u82B3",
  "\u{2F995}": "\u82BD",
  "\uF974": "\u82E5",
  "\u{2F998}": "\u82E5",
  "\u{2F996}": "\u82E6",
  "\u{2F997}": "\u{26B3C}",
  "\uF9FE": "\u8336",
  "\uFAB3": "\u8352",
  "\u{2F99A}": "\u8363",
  "\u{2F999}": "\u831D",
  "\u{2F99C}": "\u8323",
  "\u{2F99D}": "\u83BD",
  "\u{2F9A0}": "\u8353",
  "\uF93E": "\u83C9",
  "\u{2F9A1}": "\u83CA",
  "\u{2F9A2}": "\u83CC",
  "\u{2F9A3}": "\u83DC",
  "\u{2F99E}": "\u83E7",
  "\uFAB4": "\u83EF",
  "\uF958": "\u83F1",
  "\uFA5F": "\u8457",
  "\u{2F99F}": "\u8457",
  "\u{2F9A4}": "\u{26C36}",
  "\u{2F99B}": "\u83AD",
  "\uF918": "\u843D",
  "\uF96E": "\u8449",
  "\u853F": "\u848D",
  "\u{2F9A6}": "\u{26CD5}",
  "\u{2F9A5}": "\u{26D6B}",
  "\uF999": "\u84EE",
  "\u{2F9A8}": "\u84F1",
  "\u{2F9A9}": "\u84F3",
  "\uF9C2": "\u84FC",
  "\u{2F9AA}": "\u8516",
  "\u{2F9A7}": "\u452B",
  "\u{2F9AC}": "\u8564",
  "\u{2F9AD}": "\u{26F2C}",
  "\uF923": "\u85CD",
  "\u{2F9AE}": "\u455D",
  "\u{2F9B0}": "\u{26FB1}",
  "\u{2F9AF}": "\u4561",
  "\uF9F0": "\u85FA",
  "\uF935": "\u8606",
  "\u{2F9B2}": "\u456B",
  "\uFA20": "\u8612",
  "\uF91F": "\u862D",
  "\u{2F9B1}": "\u{270D2}",
  "\u8641": "\u8637",
  "\uF910": "\u863F",
  "\u2F8C": "\u864D",
  "\u2EC1": "\u864E",
  "\u{2F9B3}": "\u8650",
  "\uF936": "\u865C",
  "\u{2F9B4}": "\u865C",
  "\u{2F9B5}": "\u8667",
  "\u{2F9B6}": "\u8669",
  "\u2F8D": "\u866B",
  "\u{2F9B7}": "\u86A9",
  "\u{2F9B8}": "\u8688",
  "\u{2F9BA}": "\u86E2",
  "\u{2F9B9}": "\u870E",
  "\u{2F9BC}": "\u8728",
  "\u{2F9BD}": "\u876B",
  "\u{2F9C0}": "\u87E1",
  "\uFAB5": "\u8779",
  "\u{2F9BB}": "\u8779",
  "\u{2F9BE}": "\u8786",
  "\u{2F9BF}": "\u45D7",
  "\u{2F9AB}": "\u{273CA}",
  "\uF911": "\u87BA",
  "\u{2F9C1}": "\u8801",
  "\u{2F9C2}": "\u45F9",
  "\uF927": "\u881F",
  "\u2F8E": "\u8840",
  "\uFA08": "\u884C",
  "\u2F8F": "\u884C",
  "\u{2F9C3}": "\u8860",
  "\u{2F9C4}": "\u8863",
  "\u2F90": "\u8863",
  "\u2EC2": "\u8864",
  "\uF9A0": "\u88C2",
  "\u{2F9C5}": "\u{27667}",
  "\uF9E7": "\u88CF",
  "\u{2F9C6}": "\u88D7",
  "\u{2F9C7}": "\u88DE",
  "\uF9E8": "\u88E1",
  "\uF912": "\u88F8",
  "\u{2F9C9}": "\u88FA",
  "\u{2F9C8}": "\u4635",
  "\uFA60": "\u8910",
  "\uFAB6": "\u8941",
  "\uF924": "\u8964",
  "\u2F91": "\u897E",
  "\u2EC4": "\u897F",
  "\u2EC3": "\u8980",
  "\uFAB7": "\u8986",
  "\uFA0A": "\u898B",
  "\u2F92": "\u898B",
  "\u{2F9CB}": "\u{278AE}",
  "\u2EC5": "\u89C1",
  "\u2F93": "\u89D2",
  "\u2F94": "\u8A00",
  "\u{2F9CC}": "\u{27966}",
  "\u8A7D": "\u8A2E",
  "\u8A1E": "\u46B6",
  "\u{2F9CD}": "\u46BE",
  "\u{2F9CE}": "\u46C7",
  "\u{2F9CF}": "\u8AA0",
  "\uF96F": "\u8AAA",
  "\uF9A1": "\u8AAA",
  "\uFAB9": "\u8ABF",
  "\uFABB": "\u8ACB",
  "\uF97D": "\u8AD2",
  "\uF941": "\u8AD6",
  "\uFABE": "\u8AED",
  "\u{2F9D0}": "\u8AED",
  "\uFA22": "\u8AF8",
  "\uFABA": "\u8AF8",
  "\uF95D": "\u8AFE",
  "\uFABD": "\u8AFE",
  "\uFA62": "\u8B01",
  "\uFABC": "\u8B01",
  "\uFA63": "\u8B39",
  "\uFABF": "\u8B39",
  "\uF9FC": "\u8B58",
  "\uF95A": "\u8B80",
  "\u8B8F": "\u8B86",
  "\uFAC0": "\u8B8A",
  "\u{2F9D1}": "\u8B8A",
  "\u2EC8": "\u8BA0",
  "\u2F95": "\u8C37",
  "\u2F96": "\u8C46",
  "\uF900": "\u8C48",
  "\u{2F9D2}": "\u8C55",
  "\u2F97": "\u8C55",
  "\u8C63": "\u8C5C",
  "\u2F98": "\u8C78",
  "\u{2F9D3}": "\u{27CA8}",
  "\u2F99": "\u8C9D",
  "\u{2F9D4}": "\u8CAB",
  "\u{2F9D5}": "\u8CC1",
  "\uF948": "\u8CC2",
  "\uF903": "\u8CC8",
  "\uFA64": "\u8CD3",
  "\uFA65": "\u8D08",
  "\uFAC1": "\u8D08",
  "\u{2F9D6}": "\u8D1B",
  "\u2EC9": "\u8D1D",
  "\u2F9A": "\u8D64",
  "\u2F9B": "\u8D70",
  "\u{2F9D7}": "\u8D77",
  "\u8D86": "\u8D7F",
  "\uFAD7": "\u{27ED3}",
  "\u{2F9D8}": "\u{27F2F}",
  "\u2F9C": "\u8DB3",
  "\u{2F9DA}": "\u8DCB",
  "\u{2F9DB}": "\u8DBC",
  "\u8DFA": "\u8DE5",
  "\uF937": "\u8DEF",
  "\u{2F9DC}": "\u8DF0",
  "\u8E9B": "\u8E97",
  "\u2F9D": "\u8EAB",
  "\uF902": "\u8ECA",
  "\u2F9E": "\u8ECA",
  "\u{2F9DE}": "\u8ED4",
  "\u8F27": "\u8EFF",
  "\uF998": "\u8F26",
  "\uF9D7": "\u8F2A",
  "\uFAC2": "\u8F38",
  "\u{2F9DF}": "\u8F38",
  "\uFA07": "\u8F3B",
  "\uF98D": "\u8F62",
  "\u2ECB": "\u8F66",
  "\u2F9F": "\u8F9B",
  "\u{2F98D}": "\u8F9E",
  "\uF971": "\u8FB0",
  "\u2FA0": "\u8FB0",
  "\u2FA1": "\u8FB5",
  "\uFA66": "\u8FB6",
  "\u2ECC": "\u8FB6",
  "\u2ECD": "\u8FB6",
  "\u{2F881}": "\u5DE1",
  "\uF99A": "\u9023",
  "\uFA25": "\u9038",
  "\uFA67": "\u9038",
  "\uFAC3": "\u9072",
  "\uF9C3": "\u907C",
  "\u{2F9E0}": "\u{285D2}",
  "\u{2F9E1}": "\u{285ED}",
  "\uF913": "\u908F",
  "\u2FA2": "\u9091",
  "\u{2F9E2}": "\u9094",
  "\uF92C": "\u90CE",
  "\u90DE": "\u90CE",
  "\uFA2E": "\u90CE",
  "\u{2F9E3}": "\u90F1",
  "\uFA26": "\u90FD",
  "\u{2F9E5}": "\u{2872E}",
  "\u{2F9E4}": "\u9111",
  "\u{2F9E6}": "\u911B",
  "\u2FA3": "\u9149",
  "\uF919": "\u916A",
  "\uFAC4": "\u9199",
  "\uF9B7": "\u91B4",
  "\u2FA4": "\u91C6",
  "\uF9E9": "\u91CC",
  "\u2FA5": "\u91CC",
  "\uF97E": "\u91CF",
  "\uF90A": "\u91D1",
  "\u2FA6": "\u91D1",
  "\uF9B1": "\u9234",
  "\u{2F9E7}": "\u9238",
  "\uFAC5": "\u9276",
  "\u{2F9E8}": "\u92D7",
  "\u{2F9E9}": "\u92D8",
  "\u{2F9EA}": "\u927C",
  "\uF93F": "\u9304",
  "\uF99B": "\u934A",
  "\u93AE": "\u93AD",
  "\u{2F9EB}": "\u93F9",
  "\u{2F9EC}": "\u9415",
  "\u{2F9ED}": "\u{28BFA}",
  "\u2ED0": "\u9485",
  "\u2ED1": "\u9577",
  "\u2FA7": "\u9577",
  "\u2ED2": "\u9578",
  "\u2ED3": "\u957F",
  "\u2FA8": "\u9580",
  "\u{2F9EE}": "\u958B",
  "\u{2F9EF}": "\u4995",
  "\uF986": "\u95AD",
  "\u{2F9F0}": "\u95B7",
  "\u{2F9F1}": "\u{28D77}",
  "\u2ED4": "\u95E8",
  "\u2FA9": "\u961C",
  "\u2ECF": "\u961D",
  "\u2ED6": "\u961D",
  "\uF9C6": "\u962E",
  "\uF951": "\u964B",
  "\uFA09": "\u964D",
  "\uF959": "\u9675",
  "\uF9D3": "\u9678",
  "\uFAC6": "\u967C",
  "\uF9DC": "\u9686",
  "\uF9F1": "\u96A3",
  "\u{2F9F2}": "\u49E6",
  "\u2FAA": "\u96B6",
  "\uFA2F": "\u96B7",
  "\u96B8": "\u96B7",
  "\uF9B8": "\u96B7",
  "\u2FAB": "\u96B9",
  "\u{2F9F3}": "\u96C3",
  "\uF9EA": "\u96E2",
  "\uFA68": "\u96E3",
  "\uFAC7": "\u96E3",
  "\u2FAC": "\u96E8",
  "\uF9B2": "\u96F6",
  "\uF949": "\u96F7",
  "\u{2F9F5}": "\u9723",
  "\u{2F9F6}": "\u{29145}",
  "\uF938": "\u9732",
  "\uF9B3": "\u9748",
  "\u2FAD": "\u9751",
  "\u2ED8": "\u9752",
  "\uFA1C": "\u9756",
  "\uFAC8": "\u9756",
  "\u{2F81C}": "\u{291DF}",
  "\u2FAE": "\u975E",
  "\u2FAF": "\u9762",
  "\u{2F9F7}": "\u{2921A}",
  "\u2FB0": "\u9769",
  "\u{2F9F8}": "\u4A6E",
  "\u{2F9F9}": "\u4A76",
  "\u2FB1": "\u97CB",
  "\uFAC9": "\u97DB",
  "\u{2F9FA}": "\u97E0",
  "\u2ED9": "\u97E6",
  "\u2FB2": "\u97ED",
  "\u{2F9FB}": "\u{2940A}",
  "\u2FB3": "\u97F3",
  "\uFA69": "\u97FF",
  "\uFACA": "\u97FF",
  "\u2FB4": "\u9801",
  "\u{2F9FC}": "\u4AB2",
  "\uFACB": "\u980B",
  "\u{2F9FE}": "\u980B",
  "\u{2F9FF}": "\u980B",
  "\uF9B4": "\u9818",
  "\u{2FA00}": "\u9829",
  "\u{2F9FD}": "\u{29496}",
  "\uFA6A": "\u983B",
  "\uFACC": "\u983B",
  "\uF9D0": "\u985E",
  "\u2EDA": "\u9875",
  "\u2FB5": "\u98A8",
  "\u{2FA01}": "\u{295B6}",
  "\u2EDB": "\u98CE",
  "\u2FB6": "\u98DB",
  "\u2EDC": "\u98DE",
  "\u2EDD": "\u98DF",
  "\u2FB7": "\u98DF",
  "\u2EDF": "\u98E0",
  "\u{2FA02}": "\u98E2",
  "\uFA2A": "\u98EF",
  "\uFA2B": "\u98FC",
  "\u{2FA03}": "\u4B33",
  "\uFA2C": "\u9928",
  "\u{2FA04}": "\u9929",
  "\u2EE0": "\u9963",
  "\u2FB8": "\u9996",
  "\u2FB9": "\u9999",
  "\u{2FA05}": "\u99A7",
  "\u2FBA": "\u99AC",
  "\u{2FA06}": "\u99C2",
  "\uF91A": "\u99F1",
  "\u{2FA07}": "\u99FE",
  "\uF987": "\u9A6A",
  "\u2EE2": "\u9A6C",
  "\u2FBB": "\u9AA8",
  "\u{2FA08}": "\u4BCE",
  "\u2FBC": "\u9AD8",
  "\u2FBD": "\u9ADF",
  "\u{2FA09}": "\u{29B30}",
  "\uFACD": "\u9B12",
  "\u{2FA0A}": "\u9B12",
  "\u2FBE": "\u9B25",
  "\u2FBF": "\u9B2F",
  "\u2FC0": "\u9B32",
  "\u2FC1": "\u9B3C",
  "\u2EE4": "\u9B3C",
  "\u2FC2": "\u9B5A",
  "\uF939": "\u9B6F",
  "\u{2FA0B}": "\u9C40",
  "\uF9F2": "\u9C57",
  "\u2EE5": "\u9C7C",
  "\u2FC3": "\u9CE5",
  "\u{2FA0C}": "\u9CFD",
  "\u{2FA0D}": "\u4CCE",
  "\u{2FA0F}": "\u9D67",
  "\u{2FA0E}": "\u4CED",
  "\u{2FA10}": "\u{2A0CE}",
  "\uFA2D": "\u9DB4",
  "\u{2FA12}": "\u{2A105}",
  "\u{2FA11}": "\u4CF8",
  "\uF93A": "\u9DFA",
  "\u{2FA13}": "\u{2A20E}",
  "\uF920": "\u9E1E",
  "\u9E43": "\u9E42",
  "\u2FC4": "\u9E75",
  "\uF940": "\u9E7F",
  "\u2FC5": "\u9E7F",
  "\u{2FA14}": "\u{2A291}",
  "\uF988": "\u9E97",
  "\uF9F3": "\u9E9F",
  "\u2FC6": "\u9EA5",
  "\u2EE8": "\u9EA6",
  "\u{2FA15}": "\u9EBB",
  "\u2FC7": "\u9EBB",
  "\u{2F88F}": "\u{2A392}",
  "\u2FC8": "\u9EC3",
  "\u2EE9": "\u9EC4",
  "\u2FC9": "\u9ECD",
  "\uF989": "\u9ECE",
  "\u{2FA16}": "\u4D56",
  "\u2FCA": "\u9ED1",
  "\u9ED2": "\u9ED1",
  "\uFA3A": "\u58A8",
  "\u{2FA17}": "\u9EF9",
  "\u2FCB": "\u9EF9",
  "\u2FCC": "\u9EFD",
  "\u{2FA19}": "\u9F05",
  "\u{2FA18}": "\u9EFE",
  "\u2FCD": "\u9F0E",
  "\u{2FA1A}": "\u9F0F",
  "\u2FCE": "\u9F13",
  "\u{2FA1B}": "\u9F16",
  "\u2FCF": "\u9F20",
  "\u{2FA1C}": "\u9F3B",
  "\u2FD0": "\u9F3B",
  "\uFAD8": "\u9F43",
  "\u2FD1": "\u9F4A",
  "\u2EEC": "\u9F50",
  "\u2FD2": "\u9F52",
  "\u{2FA1D}": "\u{2A600}",
  "\u2EEE": "\u9F7F",
  "\uF9C4": "\u9F8D",
  "\u2FD3": "\u9F8D",
  "\uFAD9": "\u9F8E",
  "\u2EF0": "\u9F99",
  "\uF907": "\u9F9C",
  "\uF908": "\u9F9C",
  "\uFACE": "\u9F9C",
  "\u2FD4": "\u9F9C",
  "\u2EF3": "\u9F9F",
  "\u2FD5": "\u9FA0"
};
var data = require$$0;
function escapeRegexp(str) {
  return str.replace(/([.?*+^$[\]\\(){}|-])/g, "\\$1");
}
var REPLACE_RE = RegExp(Object.keys(data).map(escapeRegexp).join("|"), "g");
function replace_fn(match) {
  return data[match];
}
function unhomoglyph(str) {
  return str.replace(REPLACE_RE, replace_fn);
}
var unhomoglyph_1 = unhomoglyph;
var pRetry$1 = { exports: {} };
var retry$2 = {};
function RetryOperation(timeouts, options) {
  if (typeof options === "boolean") {
    options = { forever: options };
  }
  this._originalTimeouts = JSON.parse(JSON.stringify(timeouts));
  this._timeouts = timeouts;
  this._options = options || {};
  this._maxRetryTime = options && options.maxRetryTime || Infinity;
  this._fn = null;
  this._errors = [];
  this._attempts = 1;
  this._operationTimeout = null;
  this._operationTimeoutCb = null;
  this._timeout = null;
  this._operationStart = null;
  this._timer = null;
  if (this._options.forever) {
    this._cachedTimeouts = this._timeouts.slice(0);
  }
}
var retry_operation = RetryOperation;
RetryOperation.prototype.reset = function() {
  this._attempts = 1;
  this._timeouts = this._originalTimeouts.slice(0);
};
RetryOperation.prototype.stop = function() {
  if (this._timeout) {
    clearTimeout(this._timeout);
  }
  if (this._timer) {
    clearTimeout(this._timer);
  }
  this._timeouts = [];
  this._cachedTimeouts = null;
};
RetryOperation.prototype.retry = function(err) {
  if (this._timeout) {
    clearTimeout(this._timeout);
  }
  if (!err) {
    return false;
  }
  var currentTime = new Date().getTime();
  if (err && currentTime - this._operationStart >= this._maxRetryTime) {
    this._errors.push(err);
    this._errors.unshift(new Error("RetryOperation timeout occurred"));
    return false;
  }
  this._errors.push(err);
  var timeout = this._timeouts.shift();
  if (timeout === void 0) {
    if (this._cachedTimeouts) {
      this._errors.splice(0, this._errors.length - 1);
      timeout = this._cachedTimeouts.slice(-1);
    } else {
      return false;
    }
  }
  var self2 = this;
  this._timer = setTimeout(function() {
    self2._attempts++;
    if (self2._operationTimeoutCb) {
      self2._timeout = setTimeout(function() {
        self2._operationTimeoutCb(self2._attempts);
      }, self2._operationTimeout);
      if (self2._options.unref) {
        self2._timeout.unref();
      }
    }
    self2._fn(self2._attempts);
  }, timeout);
  if (this._options.unref) {
    this._timer.unref();
  }
  return true;
};
RetryOperation.prototype.attempt = function(fn, timeoutOps) {
  this._fn = fn;
  if (timeoutOps) {
    if (timeoutOps.timeout) {
      this._operationTimeout = timeoutOps.timeout;
    }
    if (timeoutOps.cb) {
      this._operationTimeoutCb = timeoutOps.cb;
    }
  }
  var self2 = this;
  if (this._operationTimeoutCb) {
    this._timeout = setTimeout(function() {
      self2._operationTimeoutCb();
    }, self2._operationTimeout);
  }
  this._operationStart = new Date().getTime();
  this._fn(this._attempts);
};
RetryOperation.prototype.try = function(fn) {
  console.log("Using RetryOperation.try() is deprecated");
  this.attempt(fn);
};
RetryOperation.prototype.start = function(fn) {
  console.log("Using RetryOperation.start() is deprecated");
  this.attempt(fn);
};
RetryOperation.prototype.start = RetryOperation.prototype.try;
RetryOperation.prototype.errors = function() {
  return this._errors;
};
RetryOperation.prototype.attempts = function() {
  return this._attempts;
};
RetryOperation.prototype.mainError = function() {
  if (this._errors.length === 0) {
    return null;
  }
  var counts = {};
  var mainError = null;
  var mainErrorCount = 0;
  for (var i2 = 0; i2 < this._errors.length; i2++) {
    var error = this._errors[i2];
    var message = error.message;
    var count = (counts[message] || 0) + 1;
    counts[message] = count;
    if (count >= mainErrorCount) {
      mainError = error;
      mainErrorCount = count;
    }
  }
  return mainError;
};
(function(exports) {
  var RetryOperation2 = retry_operation;
  exports.operation = function(options) {
    var timeouts = exports.timeouts(options);
    return new RetryOperation2(timeouts, {
      forever: options && (options.forever || options.retries === Infinity),
      unref: options && options.unref,
      maxRetryTime: options && options.maxRetryTime
    });
  };
  exports.timeouts = function(options) {
    if (options instanceof Array) {
      return [].concat(options);
    }
    var opts = {
      retries: 10,
      factor: 2,
      minTimeout: 1 * 1e3,
      maxTimeout: Infinity,
      randomize: false
    };
    for (var key in options) {
      opts[key] = options[key];
    }
    if (opts.minTimeout > opts.maxTimeout) {
      throw new Error("minTimeout is greater than maxTimeout");
    }
    var timeouts = [];
    for (var i2 = 0; i2 < opts.retries; i2++) {
      timeouts.push(this.createTimeout(i2, opts));
    }
    if (options && options.forever && !timeouts.length) {
      timeouts.push(this.createTimeout(i2, opts));
    }
    timeouts.sort(function(a, b) {
      return a - b;
    });
    return timeouts;
  };
  exports.createTimeout = function(attempt, opts) {
    var random = opts.randomize ? Math.random() + 1 : 1;
    var timeout = Math.round(random * Math.max(opts.minTimeout, 1) * Math.pow(opts.factor, attempt));
    timeout = Math.min(timeout, opts.maxTimeout);
    return timeout;
  };
  exports.wrap = function(obj, options, methods) {
    if (options instanceof Array) {
      methods = options;
      options = null;
    }
    if (!methods) {
      methods = [];
      for (var key in obj) {
        if (typeof obj[key] === "function") {
          methods.push(key);
        }
      }
    }
    for (var i2 = 0; i2 < methods.length; i2++) {
      var method = methods[i2];
      var original = obj[method];
      obj[method] = function retryWrapper(original2) {
        var op = exports.operation(options);
        var args = Array.prototype.slice.call(arguments, 1);
        var callback = args.pop();
        args.push(function(err) {
          if (op.retry(err)) {
            return;
          }
          if (err) {
            arguments[0] = op.mainError();
          }
          callback.apply(this, arguments);
        });
        op.attempt(function() {
          original2.apply(obj, args);
        });
      }.bind(obj, original);
      obj[method].options = options;
    }
  };
})(retry$2);
var retry$1 = retry$2;
const retry = retry$1;
const networkErrorMsgs = [
  "Failed to fetch",
  "NetworkError when attempting to fetch resource.",
  "The Internet connection appears to be offline.",
  "Network request failed"
];
class AbortError extends Error {
  constructor(message) {
    super();
    if (message instanceof Error) {
      this.originalError = message;
      ({ message } = message);
    } else {
      this.originalError = new Error(message);
      this.originalError.stack = this.stack;
    }
    this.name = "AbortError";
    this.message = message;
  }
}
const decorateErrorWithCounts = (error, attemptNumber, options) => {
  const retriesLeft = options.retries - (attemptNumber - 1);
  error.attemptNumber = attemptNumber;
  error.retriesLeft = retriesLeft;
  return error;
};
const isNetworkError = (errorMessage) => networkErrorMsgs.includes(errorMessage);
const pRetry = (input, options) => new Promise((resolve, reject) => {
  options = __spreadValues({
    onFailedAttempt: () => {
    },
    retries: 10
  }, options);
  const operation = retry.operation(options);
  operation.attempt(async (attemptNumber) => {
    try {
      resolve(await input(attemptNumber));
    } catch (error) {
      if (!(error instanceof Error)) {
        reject(new TypeError(`Non-error was thrown: "${error}". You should only throw errors.`));
        return;
      }
      if (error instanceof AbortError) {
        operation.stop();
        reject(error.originalError);
      } else if (error instanceof TypeError && !isNetworkError(error.message)) {
        operation.stop();
        reject(error);
      } else {
        decorateErrorWithCounts(error, attemptNumber, options);
        try {
          await options.onFailedAttempt(error);
        } catch (error2) {
          reject(error2);
          return;
        }
        if (!operation.retry(error)) {
          reject(operation.mainError());
        }
      }
    }
  });
});
pRetry$1.exports = pRetry;
pRetry$1.exports.default = pRetry;
pRetry$1.exports.AbortError = AbortError;
var _interopRequireDefault = interopRequireDefault.exports;
Object.defineProperty(utils, "__esModule", {
  value: true
});
utils.DEFAULT_ALPHABET = void 0;
utils.alphabetPad = alphabetPad;
utils.averageBetweenStrings = averageBetweenStrings;
utils.baseToString = baseToString;
utils.checkObjectHasKeys = checkObjectHasKeys;
utils.checkObjectHasNoAdditionalKeys = checkObjectHasNoAdditionalKeys;
utils.chunkPromises = chunkPromises;
utils.compare = compare;
utils.decodeParams = decodeParams;
utils.deepCompare = deepCompare;
utils.deepCopy = deepCopy;
utils.deepSortedObjectEntries = deepSortedObjectEntries;
utils.defer = defer;
utils.encodeParams = encodeParams;
utils.encodeUri = encodeUri;
utils.ensureNoTrailingSlash = ensureNoTrailingSlash;
utils.escapeRegExp = escapeRegExp;
utils.getCrypto = getCrypto;
utils.globToRegexp = globToRegexp;
utils.inherits = inherits;
utils.isFunction = isFunction;
utils.isNullOrUndefined = isNullOrUndefined;
utils.isNumber = isNumber;
utils.lexicographicCompare = lexicographicCompare;
utils.nextString = nextString;
utils.normalize = normalize;
utils.polyfillSuper = polyfillSuper;
utils.prevString = prevString;
utils.promiseMapSeries = promiseMapSeries;
utils.promiseTry = promiseTry;
utils.recursivelyAssign = recursivelyAssign;
utils.removeDirectionOverrideChars = removeDirectionOverrideChars;
utils.removeElement = removeElement;
utils.removeHiddenChars = removeHiddenChars;
utils.setCrypto = setCrypto;
utils.simpleRetryOperation = simpleRetryOperation;
utils.sleep = sleep;
utils.stringToBase = stringToBase;
var _unhomoglyph = _interopRequireDefault(unhomoglyph_1);
var _pRetry = _interopRequireDefault(pRetry$1.exports);
function encodeParams(params) {
  const searchParams = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (val !== void 0 && val !== null) {
      searchParams.set(key, String(val));
    }
  }
  return searchParams.toString();
}
function decodeParams(query) {
  const o = {};
  const params = new URLSearchParams(query);
  for (const key of params.keys()) {
    const val = params.getAll(key);
    o[key] = val.length === 1 ? val[0] : val;
  }
  return o;
}
function encodeUri(pathTemplate, variables) {
  for (const key in variables) {
    if (!variables.hasOwnProperty(key)) {
      continue;
    }
    pathTemplate = pathTemplate.replace(key, encodeURIComponent(variables[key]));
  }
  return pathTemplate;
}
function removeElement(array, fn, reverse) {
  let i2;
  if (reverse) {
    for (i2 = array.length - 1; i2 >= 0; i2--) {
      if (fn(array[i2], i2, array)) {
        array.splice(i2, 1);
        return true;
      }
    }
  } else {
    for (i2 = 0; i2 < array.length; i2++) {
      if (fn(array[i2], i2, array)) {
        array.splice(i2, 1);
        return true;
      }
    }
  }
  return false;
}
function isFunction(value) {
  return Object.prototype.toString.call(value) === "[object Function]";
}
function checkObjectHasKeys(obj, keys) {
  for (let i2 = 0; i2 < keys.length; i2++) {
    if (!obj.hasOwnProperty(keys[i2])) {
      throw new Error("Missing required key: " + keys[i2]);
    }
  }
}
function checkObjectHasNoAdditionalKeys(obj, allowedKeys) {
  for (const key in obj) {
    if (!obj.hasOwnProperty(key)) {
      continue;
    }
    if (allowedKeys.indexOf(key) === -1) {
      throw new Error("Unknown key: " + key);
    }
  }
}
function deepCopy(obj) {
  return JSON.parse(JSON.stringify(obj));
}
function deepCompare(x, y) {
  if (x === y) {
    return true;
  }
  if (typeof x !== typeof y) {
    return false;
  }
  if (typeof x === "number" && isNaN(x) && isNaN(y)) {
    return true;
  }
  if (x === null || y === null) {
    return x === y;
  }
  if (!(x instanceof Object)) {
    return false;
  }
  if (x.constructor !== y.constructor || x.prototype !== y.prototype) {
    return false;
  }
  if (x instanceof RegExp || x instanceof Date) {
    return x.toString() === y.toString();
  }
  if (x instanceof Array) {
    if (x.length !== y.length) {
      return false;
    }
    for (let i2 = 0; i2 < x.length; i2++) {
      if (!deepCompare(x[i2], y[i2])) {
        return false;
      }
    }
  } else {
    let p;
    for (p in y) {
      if (y.hasOwnProperty(p) !== x.hasOwnProperty(p)) {
        return false;
      }
    }
    for (p in y) {
      if (y.hasOwnProperty(p) !== x.hasOwnProperty(p)) {
        return false;
      }
      if (!deepCompare(x[p], y[p])) {
        return false;
      }
    }
  }
  return true;
}
function deepSortedObjectEntries(obj) {
  if (typeof obj !== "object")
    return obj;
  if (obj === null || obj === void 0 || Array.isArray(obj))
    return obj;
  const pairs = [];
  for (const [k, v] of Object.entries(obj)) {
    pairs.push([k, deepSortedObjectEntries(v)]);
  }
  pairs.sort((a, b) => lexicographicCompare(a[0], b[0]));
  return pairs;
}
function inherits(ctor, superCtor) {
  ctor.super_ = superCtor;
  ctor.prototype = Object.create(superCtor.prototype, {
    constructor: {
      value: ctor,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
}
function polyfillSuper(thisArg, SuperType, ...params) {
  try {
    SuperType.call(thisArg, ...params);
  } catch (e) {
    const fakeSuper = new SuperType(...params);
    Object.assign(thisArg, fakeSuper);
  }
}
function isNumber(value) {
  return typeof value === "number" && isFinite(value);
}
function removeHiddenChars(str) {
  if (typeof str === "string") {
    return (0, _unhomoglyph.default)(str.normalize("NFD").replace(removeHiddenCharsRegex, ""));
  }
  return "";
}
function removeDirectionOverrideChars(str) {
  if (typeof str === "string") {
    return str.replace(/[\u202d-\u202e]/g, "");
  }
  return "";
}
function normalize(str) {
  return removeHiddenChars(str.toLowerCase()).replace(/[\\'!"#$%&()*+,\-./:;<=>?@[\]^_`{|}~\u2000-\u206f\u2e00-\u2e7f]/g, "").toLowerCase();
}
const removeHiddenCharsRegex = /[\u2000-\u200F\u202A-\u202F\u0300-\u036F\uFEFF\u061C\s]/g;
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function globToRegexp(glob, extended) {
  extended = typeof extended === "boolean" ? extended : true;
  let pat = escapeRegExp(glob);
  pat = pat.replace(/\\\*/g, ".*");
  pat = pat.replace(/\?/g, ".");
  if (extended) {
    pat = pat.replace(/\\\[(!|)(.*)\\]/g, function(match, p1, p2, offset, string) {
      const first = p1 && "^" || "";
      const second = p2.replace(/\\-/, "-");
      return "[" + first + second + "]";
    });
  }
  return pat;
}
function ensureNoTrailingSlash(url) {
  if (url && url.endsWith("/")) {
    return url.substr(0, url.length - 1);
  } else {
    return url;
  }
}
function sleep(ms, value) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms, value);
  });
}
function isNullOrUndefined(val) {
  return val === null || val === void 0;
}
function defer() {
  let resolve;
  let reject;
  const promise = new Promise((_resolve, _reject) => {
    resolve = _resolve;
    reject = _reject;
  });
  return {
    resolve,
    reject,
    promise
  };
}
async function promiseMapSeries(promises, fn) {
  for (const o of promises) {
    await fn(await o);
  }
}
function promiseTry(fn) {
  return new Promise((resolve) => resolve(fn()));
}
async function chunkPromises(fns, chunkSize) {
  const results = [];
  for (let i2 = 0; i2 < fns.length; i2 += chunkSize) {
    results.push(...await Promise.all(fns.slice(i2, i2 + chunkSize).map((fn) => fn())));
  }
  return results;
}
function simpleRetryOperation(promiseFn) {
  return (0, _pRetry.default)((attempt) => {
    return promiseFn(attempt);
  }, {
    forever: true,
    factor: 2,
    minTimeout: 3e3,
    maxTimeout: 15e3
  });
}
let crypto$1;
function setCrypto(c) {
  crypto$1 = c;
}
function getCrypto() {
  return crypto$1;
}
const DEFAULT_ALPHABET = (() => {
  let str = "";
  for (let c = 32; c <= 126; c++) {
    str += String.fromCharCode(c);
  }
  return str;
})();
utils.DEFAULT_ALPHABET = DEFAULT_ALPHABET;
function alphabetPad(s, n, alphabet = DEFAULT_ALPHABET) {
  return s.padEnd(n, alphabet[0]);
}
function baseToString(n, alphabet = DEFAULT_ALPHABET) {
  const len = BigInt(alphabet.length);
  if (n <= len) {
    var _alphabet;
    return (_alphabet = alphabet[Number(n) - 1]) !== null && _alphabet !== void 0 ? _alphabet : "";
  }
  let d = n / len;
  let r = Number(n % len) - 1;
  if (r < 0) {
    d -= BigInt(Math.abs(r));
    r = Number(len) - 1;
  }
  return baseToString(d, alphabet) + alphabet[r];
}
function stringToBase(s, alphabet = DEFAULT_ALPHABET) {
  const len = BigInt(alphabet.length);
  let result = BigInt(0);
  for (let i2 = s.length - 1, j = BigInt(0); i2 >= 0; i2--, j++) {
    const charIndex = s.charCodeAt(i2) - alphabet.charCodeAt(0);
    result += BigInt(1 + charIndex) * len ** j;
  }
  return result;
}
function averageBetweenStrings(a, b, alphabet = DEFAULT_ALPHABET) {
  const padN = Math.max(a.length, b.length);
  const baseA = stringToBase(alphabetPad(a, padN, alphabet), alphabet);
  const baseB = stringToBase(alphabetPad(b, padN, alphabet), alphabet);
  const avg = (baseA + baseB) / BigInt(2);
  if (avg === baseA || avg == baseB) {
    return baseToString(avg, alphabet) + alphabet[0];
  }
  return baseToString(avg, alphabet);
}
function nextString(s, alphabet = DEFAULT_ALPHABET) {
  return baseToString(stringToBase(s, alphabet) + BigInt(1), alphabet);
}
function prevString(s, alphabet = DEFAULT_ALPHABET) {
  return baseToString(stringToBase(s, alphabet) - BigInt(1), alphabet);
}
function lexicographicCompare(a, b) {
  return a < b ? -1 : a === b ? 0 : 1;
}
const collator = new Intl.Collator();
function compare(a, b) {
  return collator.compare(a, b);
}
function recursivelyAssign(target, source, ignoreNullish = false) {
  for (const [sourceKey, sourceValue] of Object.entries(source)) {
    if (target[sourceKey] instanceof Object && sourceValue) {
      recursivelyAssign(target[sourceKey], sourceValue);
      continue;
    }
    if (sourceValue !== null && sourceValue !== void 0 || !ignoreNullish) {
      target[sourceKey] = sourceValue;
      continue;
    }
  }
  return target;
}
Object.defineProperty(aes, "__esModule", {
  value: true
});
aes.calculateKeyCheck = calculateKeyCheck;
var decryptAES_1 = aes.decryptAES = decryptAES;
var encryptAES_1 = aes.encryptAES = encryptAES;
var _utils = utils;
var _olmlib = olmlib;
const subtleCrypto = typeof window !== "undefined" && window.crypto ? window.crypto.subtle || window.crypto.webkitSubtle : null;
const zeroSalt = new Uint8Array(8);
async function encryptNode(data2, key, name, ivStr) {
  const crypto2 = (0, _utils.getCrypto)();
  if (!crypto2) {
    throw new Error("No usable crypto implementation");
  }
  let iv;
  if (ivStr) {
    iv = (0, _olmlib.decodeBase64)(ivStr);
  } else {
    iv = crypto2.randomBytes(16);
    iv[8] &= 127;
  }
  const [aesKey, hmacKey] = deriveKeysNode(key, name);
  const cipher = crypto2.createCipheriv("aes-256-ctr", aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(data2, "utf8"), cipher.final()]);
  const hmac = crypto2.createHmac("sha256", hmacKey).update(ciphertext).digest("base64");
  return {
    iv: (0, _olmlib.encodeBase64)(iv),
    ciphertext: ciphertext.toString("base64"),
    mac: hmac
  };
}
async function decryptNode(data2, key, name) {
  const crypto2 = (0, _utils.getCrypto)();
  if (!crypto2) {
    throw new Error("No usable crypto implementation");
  }
  const [aesKey, hmacKey] = deriveKeysNode(key, name);
  const hmac = crypto2.createHmac("sha256", hmacKey).update(Buffer.from(data2.ciphertext, "base64")).digest("base64").replace(/=+$/g, "");
  if (hmac !== data2.mac.replace(/=+$/g, "")) {
    throw new Error(`Error decrypting secret ${name}: bad MAC`);
  }
  const decipher = crypto2.createDecipheriv("aes-256-ctr", aesKey, (0, _olmlib.decodeBase64)(data2.iv));
  return decipher.update(data2.ciphertext, "base64", "utf8") + decipher.final("utf8");
}
function deriveKeysNode(key, name) {
  const crypto2 = (0, _utils.getCrypto)();
  const prk = crypto2.createHmac("sha256", zeroSalt).update(key).digest();
  const b = Buffer.alloc(1, 1);
  const aesKey = crypto2.createHmac("sha256", prk).update(name, "utf8").update(b).digest();
  b[0] = 2;
  const hmacKey = crypto2.createHmac("sha256", prk).update(aesKey).update(name, "utf8").update(b).digest();
  return [aesKey, hmacKey];
}
async function encryptBrowser(data2, key, name, ivStr) {
  let iv;
  if (ivStr) {
    iv = (0, _olmlib.decodeBase64)(ivStr);
  } else {
    iv = new Uint8Array(16);
    window.crypto.getRandomValues(iv);
    iv[8] &= 127;
  }
  const [aesKey, hmacKey] = await deriveKeysBrowser(key, name);
  const encodedData = new TextEncoder().encode(data2);
  const ciphertext = await subtleCrypto.encrypt({
    name: "AES-CTR",
    counter: iv,
    length: 64
  }, aesKey, encodedData);
  const hmac = await subtleCrypto.sign({
    name: "HMAC"
  }, hmacKey, ciphertext);
  return {
    iv: (0, _olmlib.encodeBase64)(iv),
    ciphertext: (0, _olmlib.encodeBase64)(ciphertext),
    mac: (0, _olmlib.encodeBase64)(hmac)
  };
}
async function decryptBrowser(data2, key, name) {
  const [aesKey, hmacKey] = await deriveKeysBrowser(key, name);
  const ciphertext = (0, _olmlib.decodeBase64)(data2.ciphertext);
  if (!await subtleCrypto.verify({
    name: "HMAC"
  }, hmacKey, (0, _olmlib.decodeBase64)(data2.mac), ciphertext)) {
    throw new Error(`Error decrypting secret ${name}: bad MAC`);
  }
  const plaintext = await subtleCrypto.decrypt({
    name: "AES-CTR",
    counter: (0, _olmlib.decodeBase64)(data2.iv),
    length: 64
  }, aesKey, ciphertext);
  return new TextDecoder().decode(new Uint8Array(plaintext));
}
async function deriveKeysBrowser(key, name) {
  const hkdfkey = await subtleCrypto.importKey("raw", key, {
    name: "HKDF"
  }, false, ["deriveBits"]);
  const keybits = await subtleCrypto.deriveBits({
    name: "HKDF",
    salt: zeroSalt,
    info: new TextEncoder().encode(name),
    hash: "SHA-256"
  }, hkdfkey, 512);
  const aesKey = keybits.slice(0, 32);
  const hmacKey = keybits.slice(32);
  const aesProm = subtleCrypto.importKey("raw", aesKey, {
    name: "AES-CTR"
  }, false, ["encrypt", "decrypt"]);
  const hmacProm = subtleCrypto.importKey("raw", hmacKey, {
    name: "HMAC",
    hash: {
      name: "SHA-256"
    }
  }, false, ["sign", "verify"]);
  return await Promise.all([aesProm, hmacProm]);
}
function encryptAES(data2, key, name, ivStr) {
  return subtleCrypto ? encryptBrowser(data2, key, name, ivStr) : encryptNode(data2, key, name, ivStr);
}
function decryptAES(data2, key, name) {
  return subtleCrypto ? decryptBrowser(data2, key, name) : decryptNode(data2, key, name);
}
const ZERO_STR = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
function calculateKeyCheck(key, iv) {
  return encryptAES(ZERO_STR, key, "", iv);
}
const createClient$1 = window["mxJsSdk"].createClient;
const mxClient$1 = createClient$1({
  baseUrl: "https://matrix.org"
});
const getDeviceId$1 = () => localStorage.getItem(ConfigService.mxDeviceKey) || "";
const setDeviceId = (value) => localStorage.setItem(ConfigService.mxDeviceKey, value);
const getUserId$1 = () => localStorage.getItem(ConfigService.mxUserId) || "";
const setUserId = (value) => localStorage.setItem(ConfigService.mxUserId, value);
const setHasMxToken = (value) => localStorage.setItem(ConfigService.mxHasMxToken, value);
const setHasPickle = (value) => localStorage.setItem(ConfigService.mxHasPickleKey, value);
const getHasPickle = () => localStorage.getItem(ConfigService.mxHasPickleKey) || "";
const getClient$1 = () => mxClient$1;
const PickleKeyToAesKey = async (pickleKey) => {
  const pickleKeyBuffer = new Uint8Array(pickleKey.length);
  for (let i2 = 0; i2 < pickleKey.length; i2++) {
    pickleKeyBuffer[i2] = pickleKey.charCodeAt(i2);
  }
  const hkdfKey = await window.crypto.subtle.importKey("raw", pickleKeyBuffer, "HKDF", false, ["deriveBits"]);
  pickleKeyBuffer.fill(0);
  return new Uint8Array(await window.crypto.subtle.deriveBits({
    name: "HKDF",
    hash: "SHA-256",
    salt: new Uint8Array(32),
    info: new Uint8Array(0)
  }, hkdfKey, 256));
};
const GetPickleKey = async (userId, deviceId) => {
  if (!window.crypto || !window.crypto.subtle) {
    return null;
  }
  let data2;
  try {
    data2 = await IdbLoad(ConfigService.mxPickleKey, [userId, deviceId]);
  } catch (e) {
    console.log("idbLoad for pickleKey failed", e);
  }
  if (!data2) {
    return null;
  }
  if (!data2.encrypted || !data2.iv || !data2.cryptoKey) {
    console.log("Badly formatted pickle key");
    return null;
  }
  const additionalData = new Uint8Array(userId.length + deviceId.length + 1);
  for (let i2 = 0; i2 < userId.length; i2++) {
    additionalData[i2] = userId.charCodeAt(i2);
  }
  additionalData[userId.length] = 124;
  for (let i2 = 0; i2 < deviceId.length; i2++) {
    additionalData[userId.length + 1 + i2] = deviceId.charCodeAt(i2);
  }
  try {
    const key = await crypto.subtle.decrypt({ name: "AES-GCM", iv: data2.iv, additionalData }, data2.cryptoKey, data2.encrypted);
    return encodeUnpaddedBase64_1(key);
  } catch (e) {
    console.log("Error decrypting pickle key", e);
    return null;
  }
};
const CreatePickleKey = async (userId, deviceId) => {
  if (!window.crypto || !window.crypto.subtle) {
    return null;
  }
  const crypto2 = window.crypto;
  const randomArray = new Uint8Array(32);
  crypto2.getRandomValues(randomArray);
  const cryptoKey = await crypto2.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = new Uint8Array(32);
  crypto2.getRandomValues(iv);
  const additionalData = new Uint8Array(userId.length + deviceId.length + 1);
  for (let i2 = 0; i2 < userId.length; i2++) {
    additionalData[i2] = userId.charCodeAt(i2);
  }
  additionalData[userId.length] = 124;
  for (let i2 = 0; i2 < deviceId.length; i2++) {
    additionalData[userId.length + 1 + i2] = deviceId.charCodeAt(i2);
  }
  const encrypted = await crypto2.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, cryptoKey, randomArray);
  try {
    await IdbSave(ConfigService.mxPickleKey, [userId, deviceId], { encrypted, iv, cryptoKey });
  } catch (e) {
    return null;
  }
  return encodeUnpaddedBase64_1(randomArray);
};
const getCachedAccessToken = async () => {
  let encryptedAccessToken;
  let accessToken = localStorage.getItem(ConfigService.mxTokenKey) || "";
  try {
    encryptedAccessToken = await IdbLoad(ConfigService.mxAccountData, ConfigService.mxTokenKey);
  } catch (error) {
    console.log(`idbLoad failed to read ${ConfigService.mxTokenKey} in account table`, error);
  }
  if (!encryptedAccessToken) {
    if (accessToken) {
      try {
        await IdbSave(ConfigService.mxAccountData, ConfigService.mxTokenKey, accessToken);
        localStorage.removeItem(ConfigService.mxTokenKey);
      } catch (e) {
        console.log("migration of access token to IndexedDB failed", e);
      }
    }
  }
  const pickleKey = await GetPickleKey(getUserId$1(), getDeviceId$1());
  if (pickleKey && encryptedAccessToken) {
    const aesKey = await PickleKeyToAesKey(pickleKey);
    accessToken = await decryptAES_1(encryptedAccessToken, aesKey, "access_token");
    aesKey.fill(0);
  }
  return accessToken;
};
const cacheAccessToken = async (accessToken) => {
  if (mxClient$1.getAccessToken()) {
    setHasMxToken("true");
  } else {
    setHasMxToken("");
  }
  const pickleKey = await GetPickleKey(getUserId$1(), getDeviceId$1());
  if (pickleKey) {
    let encryptedAccessToken = null;
    try {
      const aesKey = await PickleKeyToAesKey(pickleKey);
      encryptedAccessToken = await encryptAES_1(accessToken, aesKey, "access_token");
      aesKey.fill(0);
    } catch (error) {
      console.log("Could not encrypt access token");
    }
    try {
      await IdbSave(ConfigService.mxAccountData, ConfigService.mxTokenKey, encryptedAccessToken || mxClient$1.getAccessToken());
    } catch (e) {
      localStorage.setItem(ConfigService.mxTokenKey, mxClient$1.getAccessToken());
    }
    setHasPickle("true");
  } else {
    try {
      await IdbSave(ConfigService.mxAccountData, ConfigService.mxTokenKey, mxClient$1.getAccessToken());
    } catch (e) {
      localStorage.setItem(ConfigService.mxTokenKey, mxClient$1.getAccessToken());
    }
    if (getHasPickle()) {
      console.log("Expected a pickle key, but none provided.  Encryption may not work.");
    }
  }
};
const appRegister = (ToguroVueComponent2) => {
  var _a;
  const appName = (_a = document.querySelector(`script[data-appid='${"70eb8706-b021-47ed-908c-9eefd0863a30"}']`)) == null ? void 0 : _a.getAttribute("data-appName");
  customElements.define(!appName ? "toguro-toguro" : appName, ToguroVueComponent2);
};
const reactive = window["vue3"].reactive;
const state = reactive({
  appLoaded: false,
  appAccessToken: ""
});
var AppMutationTypes;
(function(AppMutationTypes2) {
  AppMutationTypes2["SET_APP_LOADED_STATE"] = "APP - SET_APP_LOADED_STATE";
  AppMutationTypes2["SET_APP_ACCESS_TOKEN"] = "APP - SET_APP_ACCESS_TOKEN";
})(AppMutationTypes || (AppMutationTypes = {}));
const appMutations = {
  [AppMutationTypes.SET_APP_LOADED_STATE](appLoaded) {
    state.appLoaded = appLoaded;
  },
  [AppMutationTypes.SET_APP_ACCESS_TOKEN](token) {
    state.appAccessToken = token;
  }
};
function appCommitter(mutation, payload) {
  return appMutations[mutation](payload);
}
var AppActionTypes;
(function(AppActionTypes2) {
  AppActionTypes2["SETUP_APP"] = "APP - SETUP_APP";
})(AppActionTypes || (AppActionTypes = {}));
const actionOfApp = {
  async [AppActionTypes.SETUP_APP]() {
    appCommitter(AppMutationTypes.SET_APP_LOADED_STATE, true);
  }
};
function appDispatcher(action, payload) {
  actionOfApp[action](payload);
}
const InjectCssInShadowRoot = (root, selectors) => {
  const styleSheets = document.querySelectorAll(selectors);
  let innerHTML = "";
  for (let i2 = 0; i2 < styleSheets.length; i2++) {
    innerHTML += styleSheets[i2].innerHTML;
  }
  const shadowRoot = root.getRootNode();
  const styleElement = document.createElement("style");
  styleElement.innerHTML = innerHTML;
  shadowRoot.appendChild(styleElement);
};
const InjectCssInShadowRootFromString = (root, css) => {
  const shadowRoot = root.getRootNode();
  const styleElement = document.createElement("style");
  styleElement.innerHTML = css;
  shadowRoot.appendChild(styleElement);
};
var loginCss = ".login-mx {\n  display: flex;\n  flex-direction: row;\n  width: auto;\n  height: auto;\n  margin: auto auto;\n  background: #ffffff;\n  border-radius: 4px;\n  box-shadow: 0px 2px 6px -1px rgba(0, 0, 0, 0.12);\n}\n.login-mx .st0 {\n  fill: #fff;\n}\n.login-mx h4 {\n  font-size: 24px;\n  font-weight: 600;\n  color: #000;\n  opacity: 0.85;\n}\n.login-mx label {\n  font-size: 12.5px;\n  color: #000;\n  opacity: 0.8;\n  font-weight: 400;\n}\n.login-mx .log-in-area {\n  padding: 40px 30px;\n  background: #fefefe;\n  display: flex;\n  flex-direction: column;\n  align-items: flex-start;\n  padding-bottom: 20px;\n}\n.login-mx .log-in-area h4 {\n  margin-bottom: 20px;\n  color: #202224;\n}\n.login-mx .log-in-area h4 span {\n  color: #28666e;\n  font-weight: 700;\n}\n.login-mx .log-in-area .login-welcome-message {\n  line-height: 155%;\n  font-size: 14px;\n  color: #000;\n  opacity: 0.65;\n  font-weight: 400;\n  max-width: 200px;\n  margin-bottom: 30px;\n}\n.login-mx .log-in-area .error-message {\n  height: 20px;\n  color: #ed2939;\n}\n.login-mx .action-items {\n  display: flex;\n  justify-content: space-between;\n  align-items: center;\n  width: 100%;\n  height: 60px;\n}\n.login-mx .action-items a.discrete {\n  color: rgba(0, 0, 0, 0.4);\n  font-size: 14px;\n  border-bottom: solid 1px rgba(0, 0, 0, 0);\n  font-weight: 300;\n  transition: all 0.3s ease;\n  cursor: pointer;\n  margin: 0 20px;\n}\n.login-mx .action-items a.discrete:hover {\n  border-bottom: solid 1px rgba(0, 0, 0, 0.2);\n}\n.login-mx .action-items span {\n  color: rgba(0, 0, 0, 0.4);\n}\n.login-mx .action-items button {\n  -webkit-appearance: none;\n  width: auto;\n  min-width: 100px;\n  border-radius: 24px;\n  text-align: center;\n  padding: 15px 40px;\n  background-color: #127785;\n  color: #fff;\n  font-size: 14px;\n  font-weight: 500;\n  box-shadow: 0px 2px 6px -1px rgba(0, 0, 0, 0.13);\n  border: none;\n  transition: all 0.3s ease;\n  outline: 0;\n}\n.login-mx .action-items button:hover {\n  transform: translateY(-3px);\n  box-shadow: 0 2px 6px -1px rgba(40, 102, 110, 0.65);\n}\n.login-mx .action-items button:hover:active {\n  transform: scale(0.99);\n}\n.login-mx input {\n  font-size: 16px;\n  padding: 20px 0px;\n  height: 56px;\n  border: none;\n  border-bottom: solid 1px rgba(0, 0, 0, 0.1);\n  background: #fff;\n  min-width: 280px;\n  box-sizing: border-box;\n  transition: all 0.3s linear;\n  color: #000;\n  font-weight: 400;\n  -webkit-appearance: none;\n}\n.login-mx input:focus {\n  border-bottom: solid 1px #28666e;\n  outline: 0;\n  box-shadow: 0 2px 6px -8px rgba(40, 102, 110, 0.45);\n}\n.login-mx .floating-label {\n  position: relative;\n  margin-bottom: 10px;\n}\n.login-mx .floating-label label {\n  position: absolute;\n  top: calc(50% - 7px);\n  left: 0;\n  opacity: 0;\n  transition: all 0.3s ease;\n}\n.login-mx .floating-label input:not(:placeholder-shown) {\n  padding: 28px 0px 12px 0px;\n}\n.login-mx .floating-label input:not(:placeholder-shown) + label {\n  transform: translateY(-10px);\n  opacity: 0.7;\n}\n.login-mx .left {\n  width: 220px;\n  height: auto;\n  min-height: 100%;\n  position: relative;\n  background: linear-gradient(#28666e, #7c9885, #9ebaa7);\n  background-size: cover;\n  border-top-left-radius: 4px;\n  border-bottom-left-radius: 4px;\n}\n.login-mx .left svg {\n  height: 40px;\n  width: auto;\n  margin: 20px;\n}";
var en = {
  "error.cannot-login-error": "Login or password invalid",
  "welcome-back-login": "Welcome back! Log in to your account to view your latest notifications:",
  "welcome-message-login": "Sign up or Log in to your account."
};
var pt = {
  "error.cannot-login-error": "email ou senha invalidos",
  "welcome-back-login": "Bem vindo de volta! Entre na sua conta para ver as ultimas notificacoes:",
  "welcome-message-login": "Cadastre-se ou Entre na sua conta."
};
const getLang = () => navigator.language || (navigator.languages || ["en"])[0];
const LangService = {
  locale: getLang,
  messages: { en, pt },
  get: (label) => {
    const lang = (LangService.locale().split("-") || ["en"])[0];
    return LangService.messages[lang][label] || label;
  }
};
const useLang = () => {
  const $t = (label) => LangService.get(label);
  return {
    $t
  };
};
const LoginUpdateEvent = (accessToken, redirectTo = ConfigService.loginRedirectPath) => {
  return new CustomEvent("toguro-events:login-updated", {
    detail: {
      accessToken,
      redirectTo,
      logoutFunction: () => {
        IdbDelete(ConfigService.mxPickleKey, [getUserId$1(), getDeviceId$1()]);
        IdbDelete(ConfigService.mxAccountData, ConfigService.mxTokenKey);
        setUserId("");
        setHasMxToken("");
        setHasPickle("");
      }
    }
  });
};
const createFetch = window["vueUse"].createFetch;
const _fetch = createFetch({
  baseUrl: "https://matrix.org",
  options: {
    async beforeFetch({ options }) {
      return { options };
    }
  },
  fetchOptions: {
    mode: "cors"
  }
});
const ToguroUserService = {
  register: async (username, password) => {
    try {
      const { data: data2 } = await _fetch("/_matrix/client/r0/register").post({
        username,
        password
      }).json();
      const res = await _fetch("/_matrix/client/r0/register").post({
        username,
        password,
        auth: {
          session: data2.value.session,
          type: "m.login.email.identity"
        }
      }).json();
      return res.data.value;
    } catch (error) {
      console.log(error);
    }
  },
  login: async (username, password) => {
    let cachedAccessToken = await getCachedAccessToken();
    if (!cachedAccessToken) {
      const result = await getClient$1().login("m.login.password", {
        user: username,
        password,
        device_id: getDeviceId$1() || void 0
      });
      if (!result) {
        return;
      }
      if (!getDeviceId$1()) {
        setDeviceId(result.device_id);
      }
      if (!getUserId$1()) {
        setUserId(getClient$1().getUserId());
      }
      await CreatePickleKey(getUserId$1(), getDeviceId$1());
      await cacheAccessToken(getClient$1().getAccessToken());
      cachedAccessToken = await getCachedAccessToken();
    }
    window.dispatchEvent(LoginUpdateEvent(cachedAccessToken));
  }
};
const _defineComponent$2 = window["vue3"].defineComponent;
const _createElementVNode = window["vue3"].createElementVNode;
const _openBlock$2 = window["vue3"].openBlock;
const _createElementBlock$2 = window["vue3"].createElementBlock;
const _createTextVNode = window["vue3"].createTextVNode;
const _unref = window["vue3"].unref;
const _toDisplayString = window["vue3"].toDisplayString;
const _vModelText = window["vue3"].vModelText;
const _withDirectives = window["vue3"].withDirectives;
const _hoisted_1$2 = /* @__PURE__ */ _createElementVNode("div", { class: "left" }, [
  /* @__PURE__ */ _createElementVNode("svg", {
    "enable-background": "new 0 0 300 302.5",
    version: "1.1",
    viewBox: "0 0 300 302.5",
    "xml:space": "preserve",
    xmlns: "http://www.w3.org/2000/svg"
  }, [
    /* @__PURE__ */ _createElementVNode("path", {
      class: "st0",
      d: "m126 302.2c-2.3 0.7-5.7 0.2-7.7-1.2l-105-71.6c-2-1.3-3.7-4.4-3.9-6.7l-9.4-126.7c-0.2-2.4 1.1-5.6 2.8-7.2l93.2-86.4c1.7-1.6 5.1-2.6 7.4-2.3l125.6 18.9c2.3 0.4 5.2 2.3 6.4 4.4l63.5 110.1c1.2 2 1.4 5.5 0.6 7.7l-46.4 118.3c-0.9 2.2-3.4 4.6-5.7 5.3l-121.4 37.4zm63.4-102.7c2.3-0.7 4.8-3.1 5.7-5.3l19.9-50.8c0.9-2.2 0.6-5.7-0.6-7.7l-27.3-47.3c-1.2-2-4.1-4-6.4-4.4l-53.9-8c-2.3-0.4-5.7 0.7-7.4 2.3l-40 37.1c-1.7 1.6-3 4.9-2.8 7.2l4.1 54.4c0.2 2.4 1.9 5.4 3.9 6.7l45.1 30.8c2 1.3 5.4 1.9 7.7 1.2l52-16.2z"
    })
  ])
], -1);
const _hoisted_2 = {
  class: "log-in-area",
  autocomplete: "off"
};
const _hoisted_3 = /* @__PURE__ */ _createElementVNode("h4", null, [
  /* @__PURE__ */ _createTextVNode("We are "),
  /* @__PURE__ */ _createElementVNode("span", null, "My Website")
], -1);
const _hoisted_4 = {
  key: 0,
  class: "login-welcome-message"
};
const _hoisted_5 = {
  key: 1,
  class: "login-welcome-message"
};
const _hoisted_6 = { class: "error-message" };
const _hoisted_7 = { class: "floating-label" };
const _hoisted_8 = /* @__PURE__ */ _createElementVNode("label", { for: "email" }, "Email:", -1);
const _hoisted_9 = { class: "floating-label" };
const _hoisted_10 = /* @__PURE__ */ _createElementVNode("label", { for: "password" }, "Password:", -1);
const _hoisted_11 = /* @__PURE__ */ _createElementVNode("span", null, "|", -1);
const onMounted$1 = window["vue3"].onMounted;
const ref = window["vue3"].ref;
const _sfc_main$2 = /* @__PURE__ */ _defineComponent$2({
  setup(__props) {
    const root = ref();
    const email = ref("");
    const password = ref("");
    const cannotLogin = ref(false);
    const { $t } = useLang();
    const hasDeviceCached = getDeviceId$1();
    const signUp = async () => {
      console.log("TODO::");
    };
    const login = async () => {
      try {
        if (email.value.length <= 3 || password.value.length <= 3) {
          throw new Error();
        }
        await ToguroUserService.login(email.value, password.value);
      } catch (err) {
        cannotLogin.value = true;
      }
    };
    onMounted$1(() => {
      InjectCssInShadowRoot(root.value, "style[cssr-id]");
      InjectCssInShadowRootFromString(root.value, loginCss);
    });
    return (_ctx, _cache) => {
      return _openBlock$2(), _createElementBlock$2("div", {
        ref_key: "root",
        ref: root,
        class: "login-mx"
      }, [
        _hoisted_1$2,
        _createElementVNode("div", _hoisted_2, [
          _hoisted_3,
          _unref(hasDeviceCached) ? (_openBlock$2(), _createElementBlock$2("p", _hoisted_4, _toDisplayString(_unref($t)("welcome-back-login")), 1)) : (_openBlock$2(), _createElementBlock$2("p", _hoisted_5, _toDisplayString(_unref($t)("welcome-message-login")), 1)),
          _createElementVNode("span", _hoisted_6, _toDisplayString(cannotLogin.value ? _unref($t)("error.cannot-login-error") : ""), 1),
          _createElementVNode("div", _hoisted_7, [
            _withDirectives(_createElementVNode("input", {
              "onUpdate:modelValue": _cache[0] || (_cache[0] = ($event) => email.value = $event),
              placeholder: "Email",
              type: "text",
              name: "email",
              id: "email",
              autocomplete: "off"
            }, null, 512), [
              [_vModelText, email.value]
            ]),
            _hoisted_8
          ]),
          _createElementVNode("div", _hoisted_9, [
            _withDirectives(_createElementVNode("input", {
              "onUpdate:modelValue": _cache[1] || (_cache[1] = ($event) => password.value = $event),
              placeholder: "Password",
              type: "password",
              name: "password",
              id: "password",
              autocomplete: "off"
            }, null, 512), [
              [_vModelText, password.value]
            ]),
            _hoisted_10
          ]),
          _createElementVNode("div", { class: "action-items" }, [
            _createElementVNode("a", {
              class: "discrete",
              onClick: signUp
            }, "Sign up"),
            _hoisted_11,
            _createElementVNode("button", { onClick: login }, "Log in")
          ])
        ])
      ], 512);
    };
  }
});
const _defineComponent$1 = window["vue3"].defineComponent;
const _createVNode$1 = window["vue3"].createVNode;
const _openBlock$1 = window["vue3"].openBlock;
const _createElementBlock$1 = window["vue3"].createElementBlock;
const _hoisted_1$1 = { class: "toguro-main" };
const _sfc_main$1 = /* @__PURE__ */ _defineComponent$1({
  setup(__props) {
    return (_ctx, _cache) => {
      return _openBlock$1(), _createElementBlock$1("div", _hoisted_1$1, [
        _createVNode$1(_sfc_main$2)
      ]);
    };
  }
});
var _style_0 = "*,*:before,*:after{box-sizing:border-box;margin:0}ul[class],ol[class]{padding:0}body,h1,h2,h3,h4,p,ul[class],ol[class],li,figure,figcaption,blockquote,dl,dd{margin:0}body{min-height:100vh;scroll-behavior:smooth;text-rendering:optimizeSpeed;line-height:1.5;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}ul[class],ol[class]{list-style:none}a:not([class]){text-decoration-skip-ink:auto}img{max-width:100%;display:block}article>*+*{margin-top:1em}input,button,textarea,select{font:inherit}@media (prefers-reduced-motion: reduce){*{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}.toguro-app{display:flex;background:#fbfbfb;padding:20px;border-radius:5px;margin:0 auto;position:absolute;width:100%;height:100%}.toguro-main{width:100%;margin:0;display:flex;align-items:flex-start;justify-content:flex-start}\n";
var _export_sfc = (sfc, props) => {
  const target = sfc.__vccOpts || sfc;
  for (const [key, val] of props) {
    target[key] = val;
  }
  return target;
};
const _defineComponent = window["vue3"].defineComponent;
const _createVNode = window["vue3"].createVNode;
const _openBlock = window["vue3"].openBlock;
const _createElementBlock = window["vue3"].createElementBlock;
const _hoisted_1 = { class: "toguro-app" };
const onMounted = window["vue3"].onMounted;
const _sfc_main = /* @__PURE__ */ _defineComponent({
  setup(__props) {
    onMounted(() => {
      appDispatcher(AppActionTypes.SETUP_APP);
    });
    return (_ctx, _cache) => {
      return _openBlock(), _createElementBlock("div", _hoisted_1, [
        _createVNode(_sfc_main$1)
      ]);
    };
  }
});
var Toguro = /* @__PURE__ */ _export_sfc(_sfc_main, [["styles", [_style_0]]]);
const createClient = window["mxJsSdk"].createClient;
let mxClient;
const getDeviceId = () => localStorage.getItem(ConfigService.mxDeviceKey) || "";
const getUserId = () => localStorage.getItem(ConfigService.mxUserId) || "";
const getClient = () => mxClient;
const setClient = (accessToken) => mxClient = createClient({
  baseUrl: ConfigService.MatrixUrl,
  userId: getUserId(),
  deviceId: getDeviceId(),
  accessToken
});
const GetSenderAvatar = (item) => {
  if (!item) {
    return ConfigService.defaultAvatar;
  }
  return item.sender.getAvatarUrl(ConfigService.MatrixUrl, 50, 50, "scale", true, false) || ConfigService.defaultAvatar;
};
const GetMyAvatarUrl = () => mxClient.getUser(getUserId()).avatarUrl;
const GetRoomAvatar = (room) => {
  if (!room) {
    return ConfigService.defaultAvatar;
  }
  let roomAvatar = room.getAvatarUrl(ConfigService.MatrixUrl, 100, 100, "scale", true);
  if (!roomAvatar && room.getJoinedMemberCount() === 2) {
    roomAvatar = room.getAvatarFallbackMember().getAvatarUrl(ConfigService.MatrixUrl, 100, 100, "scale", true, false);
  }
  return roomAvatar || ConfigService.defaultAvatar;
};
const GetEventTime = (item) => {
  const _date = item.getDate();
  return `${_date.getHours()}:${_date.getMinutes() > 9 ? _date.getMinutes() : "0" + _date.getMinutes()}`;
};
const SendMessage = (roomId, body, callBack) => {
  const txnId = mxClient.makeTxnId();
  mxClient.sendTextMessage(roomId, body, txnId, callBack);
};
const UploadContent = (file, opts) => {
  return mxClient.uploadContent(file, opts);
};
const SendImage = (roomId, mxUrl, info, text, callback) => {
  mxClient.sendImageMessage(roomId, mxUrl, info, text, callback);
};
var mxGlobalHelper = /* @__PURE__ */ Object.freeze({
  __proto__: null,
  [Symbol.toStringTag]: "Module",
  getDeviceId,
  getUserId,
  getClient,
  setClient,
  GetSenderAvatar,
  GetMyAvatarUrl,
  GetRoomAvatar,
  GetEventTime,
  SendMessage,
  UploadContent,
  SendImage
});
window.MxToguroGlobalHelper = mxGlobalHelper;
const defineCustomElement = window["vue3"].defineCustomElement;
const ToguroVueComponent = defineCustomElement(Toguro);
appRegister(ToguroVueComponent);
getCachedAccessToken().then((value) => {
  if (value) {
    window.dispatchEvent(LoginUpdateEvent(value, `${location.pathname}`));
  }
});
