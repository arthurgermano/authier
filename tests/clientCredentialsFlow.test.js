import { describe, it, beforeEach } from "vitest";
import ClientCredentialsFlow from "../flows/ClientCredentialsFlow";
import { decodeToken, signToken, clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let ccFlow;
let CopyClientCredentialsFlow;
const copyClientData = {
  ...clientData,
  grant_types: clientData.grant_types.split(" "),
  redirect_uris: clientData.redirect_uris.split(" "),
  scopes: clientData.scopes.split(" "),
};

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyClientCredentialsFlow = class extends ClientCredentialsFlow {
    constructor(options = {}) {
      super(options);
    }
  };
  ccFlow = new ClientCredentialsFlow(copyClientData);
});

// ------------------------------------------------------------------------------------------------

describe("clientCredentialsFlow", () => {
  it("constructor() - generating a new ClientCredentialsFlow with options", () => {
    ccFlow = new ClientCredentialsFlow({
      ...copyClientData,
      scopes_required: true,
    });
    expect(ccFlow).toBeInstanceOf(ClientCredentialsFlow);
  });

  // ----------------------------------------------------------------------------------------------

  it("generateToken() -> getToken() - retrieve a token from new function", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async (data) => {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow(copyClientData);

    const token = await ccFlow.getToken({
      
      scopes_requested: ["scopeA"],
      token_info: { sub: "12345" },
    });

    expect(token).toBeTypeOf("string");
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - retrieve a token from new function and to have expected decoded information", async () => {
    let expires;
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      expires = Math.floor(Date.now() / 1000) + this.token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow(copyClientData);

    const token = await ccFlow.getToken({
      
      scopes_requested: ["scopeA"],
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(expires).toBeDefined();
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("scopeA");
    expect(decoded.exp).toBe(expires);
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - pass a missing scope", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      expires = Math.floor(Date.now() / 1000) + this.token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow(copyClientData);

    let errorExpected;
    try {
      await ccFlow.getToken({
        
        
        scopes_requested: ["scopeC"],
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("invalid_scope");
    expect(errorExpected.more_info).toBe(
      "validateScopes(): The scope scopeC is not valid"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - pass a missing scope between several scopes", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      expires = Math.floor(Date.now() / 1000) + this.token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow(copyClientData);

    let errorExpected;
    try {
      await ccFlow.getToken({
        
        
        scopes_requested: ["scopeC", "scopeA", "scopeB"],
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("invalid_scope");
    expect(errorExpected.more_info).toBe(
      "validateScopes(): The scope scopeC is not valid"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - pass scopes between several scopes", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow(copyClientData);

    const token = await ccFlow.getToken({
      
      scopes_requested: ["scopeA", "scopeB"],
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("scopeA scopeB");
    expect(decoded.exp).toBeDefined();
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - pass scopes between several scopes with match all disabled an one invalid", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow({ ...copyClientData, match_all_scopes: false });

    const token = await ccFlow.getToken({
      
      scopes_requested: ["scopeB", "scopeC"],
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("scopeB");
    expect(decoded.exp).toBeDefined();
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - pass scopes between several scopes with match all disabled an all valid", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow({ ...copyClientData, match_all_scopes: false });

    const token = await ccFlow.getToken({
      
      scopes_requested: ["scopeB", "scopeA"],
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("scopeB scopeA");
    expect(decoded.exp).toBeDefined();
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - with scopes required pass no undefined as scopes", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      expires = Math.floor(Date.now() / 1000) + this.token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow({
      ...copyClientData,
      scopes_required: true,
    });

    let errorExpected;
    try {
      await ccFlow.getToken({
        
        
        scopes_requested: undefined,
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("invalid_scope");
    expect(errorExpected.more_info).toBe(
      "validateScopes(): No scopes informed but this client requires scopes to be informed"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - with scopes required pass an empty array as scopes", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      expires = Math.floor(Date.now() / 1000) + this.token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow({
      ...copyClientData,
      scopes_required: true,
    });

    let errorExpected;
    try {
      await ccFlow.getToken({
        
        
        scopes_requested: [],
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("invalid_scope");
    expect(errorExpected.more_info).toBe(
      "validateScopes(): No scopes informed but this client requires scopes to be informed"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - with scopes NOT required pass undefined as scopes", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow({
      ...copyClientData,
      scopes_required: false,
    });

    const token = await ccFlow.getToken({
      
      scopes_requested: undefined,
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("scopeA scopeB");
    expect(decoded.exp).toBeDefined();
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - with scopes NOT required pass an empty array as scopes", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow({
      ...copyClientData,
      scopes_required: false,
    });

    const token = await ccFlow.getToken({
      
      scopes_requested: [],
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("scopeA scopeB");
    expect(decoded.exp).toBeDefined();
  });
});
