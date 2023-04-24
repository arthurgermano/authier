import { describe, it, beforeEach } from "vitest";
import RefreshTokenFlow from "../flows/RefreshTokenFlow.js";
import { decodeToken, signToken, clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let crtFlow;
let CopyRefreshTokenFlow;
let clientTestData;

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyRefreshTokenFlow = class extends RefreshTokenFlow {
    constructor(options = {}) {
      super(options);
    }
  };
  crtFlow = new RefreshTokenFlow();
  clientTestData = Object.assign({}, clientData);
  clientTestData.grant_types = clientTestData.grant_types.split(" ");
  clientTestData.scopes = clientTestData.scopes.split(" ");
});

// ------------------------------------------------------------------------------------------------

describe("refreshTokenFlow", () => {
  it("constructor() - generating a new RefreshTokenFlow with options", () => {
    crtFlow = new RefreshTokenFlow({
      scope_required: true,
    });
    expect(crtFlow).toBeInstanceOf(RefreshTokenFlow);
  });

  // ----------------------------------------------------------------------------------------------

  it("generateRefreshToken() -> getToken() - retrieve a token from new function", async () => {
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow();

    const token = await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      expires = Math.floor(Date.now() / 1000) + this.refresh_token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow();

    const token = await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      expires = Math.floor(Date.now() / 1000) + this.refresh_token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow();

    let errorExpected;
    try {
      await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      expires = Math.floor(Date.now() / 1000) + this.refresh_token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow();

    let errorExpected;
    try {
      await crtFlow.getToken({
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
      "validateGrant(): Not supported the grant type: refresh_token"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - pass a missing scope between several scopes", async () => {
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      expires = Math.floor(Date.now() / 1000) + this.refresh_token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow();

    let errorExpected;
    try {
      await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow();

    const token = await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow({ match_all_scopes: false });

    const token = await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow({ match_all_scopes: false });

    const token = await crtFlow.getToken({
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      expires = Math.floor(Date.now() / 1000) + this.refresh_token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow({
      scope_required: true,
    });

    let errorExpected;
    try {
      await crtFlow.getToken({
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      expires = Math.floor(Date.now() / 1000) + this.refresh_token_expires_in;
      return await signToken({
        exp: expires,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow({
      scope_required: true,
    });

    let errorExpected;
    try {
      await crtFlow.getToken({
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
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
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow({
      scope_required: false,
    });

    const token = await crtFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
      scopes_requested: undefined,
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("");
    expect(decoded.exp).toBeDefined();
  });

  // ----------------------------------------------------------------------------------------------

  it("getToken() - with scopes NOT required pass an empty array as scopes", async () => {
    CopyRefreshTokenFlow.prototype.generateRefreshToken = async function (
      data
    ) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + this.refresh_token_expires_in,
        sub: data.token_info.sub,
        iss: data.token_info.iss,
        scopes: data.scopes_granted.join(" "),
      });
    };

    crtFlow = new CopyRefreshTokenFlow({
      scope_required: false,
    });

    const token = await crtFlow.getToken({
      client_grant_types: clientTestData.grant_types,
      client_scopes: clientTestData.scopes,
      scopes_requested: [],
      token_info: { sub: "12345" },
    });

    const decoded = await decodeToken(token);
    expect(token).toBeTypeOf("string");
    expect(decoded.sub).toBe("12345");
    expect(decoded.scopes).toBe("");
    expect(decoded.exp).toBeDefined();
  });

  // --------------------------------------------------------------------------------------------

  it("validateRefreshToken() - setting a valid validateRefreshToken function and validate a given token", async () => {
    CopyRefreshTokenFlow.prototype.validateRefreshToken = (token) => {
      if (token === "qwerasdfzxc") {
        return true;
      }
    };

    crtFlow = new CopyRefreshTokenFlow();

    const token = await crtFlow.validateRefreshToken("qwerasdfzxc");
    expect(token).toBe(true);
  });

  // --------------------------------------------------------------------------------------------

  it("validateRefreshToken() - not setting a validateRefreshToken function to throw an error", async () => {
    let errorExpected;
    try {
      await crtFlow.validateRefreshToken("qwerasdfzxc");
    } catch (error) {
      errorExpected = error;
    }

    expect(errorExpected).toHaveProperty("error", "todo_error");
    expect(errorExpected).toHaveProperty(
      "error_description",
      "The code requested is not implemented yet."
    );
  });
});
