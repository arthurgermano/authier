import { describe, it, beforeEach } from "vitest";
import ClientCredentialsFlow from "../flows/ClientCredentialsFlow";
import { decodeToken, signToken, clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let ccFlow;
let CopyClientCredentialsFlow;
let clientTestData;

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyClientCredentialsFlow = class extends ClientCredentialsFlow {
    constructor(options = {}) {
      super(options);
    }
  };
  ccFlow = new ClientCredentialsFlow();
  clientTestData = Object.assign({}, clientData);
  clientTestData.grant_types = clientTestData.grant_types.split(" ");
  clientTestData.scopes = clientTestData.scopes.split(" ");
});

// ------------------------------------------------------------------------------------------------

describe("clientCredentialsFlow", () => {
  it("constructor() - generating a new ClientCredentialsFlow with options", () => {
    ccFlow = new ClientCredentialsFlow({
      scope_required: true,
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

    ccFlow = new CopyClientCredentialsFlow();

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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

    ccFlow = new CopyClientCredentialsFlow();

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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

    ccFlow = new CopyClientCredentialsFlow();

    let errorExpected;
    try {
      await ccFlow.getToken({
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
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

  it("getToken() - pass a invalid grant type", async () => {
    CopyClientCredentialsFlow.prototype.generateToken = async function (data) {
      expires = Math.floor(Date.now() / 1000) + this.token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    ccFlow = new CopyClientCredentialsFlow();

    let errorExpected;
    try {
      await ccFlow.getToken({
        client_grant_types: ["clientTestData.grant_types"],
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeB"],
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("unsupported_grant_type");
    expect(errorExpected.more_info).toBe(
      "validateGrant(): Not supported the grant type: client_credentials"
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

    ccFlow = new CopyClientCredentialsFlow();

    let errorExpected;
    try {
      await ccFlow.getToken({
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
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

    ccFlow = new CopyClientCredentialsFlow();

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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

    ccFlow = new CopyClientCredentialsFlow({ match_all_scopes: false });

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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

    ccFlow = new CopyClientCredentialsFlow({ match_all_scopes: false });

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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
      scope_required: true,
    });

    let errorExpected;
    try {
      await ccFlow.getToken({
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: undefined,
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("server_error");
    expect(errorExpected.more_info).toBe(
      "validateScopes(): scopes must be an array of strings"
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
      scope_required: true,
    });

    let errorExpected;
    try {
      await ccFlow.getToken({
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        token_info: { sub: "12345" },
      });
    } catch (error) {
      errorExpected = error;
    }
    expect(errorExpected.error).toBe("server_error");
    expect(errorExpected.more_info).toBe(
      "validateScopes(): scopes must be an array of strings"
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
      scope_required: false,
    });

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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
      scope_required: false,
    });

    const token = await ccFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
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