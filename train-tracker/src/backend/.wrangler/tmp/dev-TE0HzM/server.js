var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// .wrangler/tmp/bundle-sbis6h/strip-cf-connecting-ip-header.js
function stripCfConnectingIPHeader(input, init) {
  const request = new Request(input, init);
  request.headers.delete("CF-Connecting-IP");
  return request;
}
__name(stripCfConnectingIPHeader, "stripCfConnectingIPHeader");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    return Reflect.apply(target, thisArg, [
      stripCfConnectingIPHeader.apply(null, argArray)
    ]);
  }
});

// server.js
var MAP_HEX = {
  0: 0,
  1: 1,
  2: 2,
  3: 3,
  4: 4,
  5: 5,
  6: 6,
  7: 7,
  8: 8,
  9: 9,
  a: 10,
  b: 11,
  c: 12,
  d: 13,
  e: 14,
  f: 15,
  A: 10,
  B: 11,
  C: 12,
  D: 13,
  E: 14,
  F: 15
};
function fromHex(hexString) {
  const bytes = new Uint8Array(Math.floor((hexString || "").length / 2));
  let i;
  for (i = 0; i < bytes.length; i++) {
    const a = MAP_HEX[hexString[i * 2]];
    const b = MAP_HEX[hexString[i * 2 + 1]];
    if (a === void 0 || b === void 0) {
      break;
    }
    bytes[i] = a << 4 | b;
  }
  return i === bytes.length ? bytes : bytes.slice(0, i);
}
__name(fromHex, "fromHex");
var PASSWORD_LENGTH = 88;
var cryptoParams = null;
var trainsDataURL = "https://maps.amtrak.com/services/MapDataService/trains/getTrainsData";
var stationsDataURL = "https://maps.amtrak.com/services/MapDataService/stations/trainStations";
async function getDecryptedJSONData(url) {
  const rawDataBase64 = await fetch(url).then(
    (res) => res.text()
  );
  const encryptedTrainData = Uint8Array.from(atob(rawDataBase64.slice(0, -PASSWORD_LENGTH)), (m) => m.charCodeAt(0));
  const encryptedPasswordFragments = Uint8Array.from(atob(rawDataBase64.slice(-PASSWORD_LENGTH)), (m) => m.charCodeAt(0));
  if (cryptoParams === null) {
    const masterZoom = await fetch(
      "https://maps.amtrak.com/rttl/js/RoutesList.json"
    ).then((r) => r.json()).then(
      (list) => list.reduce((sum, { ZoomLevel }) => sum + (ZoomLevel ?? 0), 0)
    );
    const cryptoData = await fetch(
      "https://maps.amtrak.com/rttl/js/RoutesList.v.json"
    ).then((r) => r.json());
    cryptoParams = {
      publicKey: cryptoData.arr[masterZoom],
      // The salt and IV indices are equal to the length of any given value in the
      // array. So if salt[0] is 8 bytes long, then our value is at salt[8]. Etc.
      salt: fromHex(cryptoData.s[cryptoData.s[0].length]),
      iv: fromHex(cryptoData.v[cryptoData.v[0].length])
    };
  }
  const decryptionAlgo = {
    name: "AES-CBC",
    iv: cryptoParams.iv
  };
  let deriveKey = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(cryptoParams.publicKey, (m) => m.charCodeAt(0)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  let privateKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-1",
      iterations: 1e3,
      salt: cryptoParams.salt
    },
    deriveKey,
    {
      name: "AES-CBC",
      length: 16 * 8
    },
    false,
    ["decrypt"]
  );
  const decryptedPassword = await crypto.subtle.decrypt(decryptionAlgo, privateKey, encryptedPasswordFragments).then((m) => new TextDecoder().decode(m)).then((m) => m.split("|")[0]);
  deriveKey = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(decryptedPassword, (m) => m.charCodeAt(0)),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  privateKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-1",
      iterations: 1e3,
      salt: cryptoParams.salt
    },
    deriveKey,
    {
      name: "AES-CBC",
      length: 16 * 8
    },
    false,
    ["decrypt"]
  );
  return crypto.subtle.decrypt(decryptionAlgo, privateKey, encryptedTrainData).then((m) => new TextDecoder().decode(m));
}
__name(getDecryptedJSONData, "getDecryptedJSONData");
async function getRoutesJSONData() {
  return fetch("https://maps.amtrak.com/rttl/js/RoutesList.json").then(
    (res) => res.text()
  );
}
__name(getRoutesJSONData, "getRoutesJSONData");
var server_default = {
  /**
   * Incoming request handler.
   * Acts as tandem CORS proxy / decrypting service for frontend
   * @param {Request} req request object
   * @param env unused environment
   * @param ctx unused context
   * @returns {Promise<Response>}
   */
  async fetch(req, env, ctx) {
    const successHeaders = {
      "Content-Type": "text/json",
      "Access-Control-Allow-Origin": "*"
    };
    let res = new Response("", {
      status: 404,
      statusText: "not found"
    });
    try {
      const page = req.url.split("/").at(-1);
      if (page === "getTrains") {
        res = new Response(await getDecryptedJSONData(trainsDataURL), {
          status: 200,
          statusText: "",
          headers: successHeaders
        });
      }
      if (page === "getRoutes") {
        res = new Response(await getRoutesJSONData(), {
          status: 200,
          statusText: "",
          headers: successHeaders
        });
      }
      if (page === "getStations") {
        res = new Response(await getDecryptedJSONData(stationsDataURL), {
          status: 200,
          statusText: "",
          headers: successHeaders
        });
      }
    } catch (err) {
      console.error(err);
    }
    return res;
  }
};

// ../../node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-sbis6h/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = server_default;

// ../../node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-sbis6h/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
__name(__Facade_ScheduledController__, "__Facade_ScheduledController__");
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = (request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    };
    #dispatcher = (type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    };
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=server.js.map
