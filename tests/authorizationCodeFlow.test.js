import { describe, it, beforeEach } from "vitest";
import AuthorizationCodeFlow from "../flows/AuthorizationCodeFlow";
import { checkToken, decodeToken, signToken, clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let acFlow;
let CopyAuthorizationCodeFlow;
let clientTestData;

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyAuthorizationCodeFlow = class extends AuthorizationCodeFlow {
    constructor(options = {}) {
      super(options);
    }
  };
  acFlow = new AuthorizationCodeFlow();
  clientTestData = Object.assign({}, clientData);
  clientTestData.grant_types = clientTestData.grant_types.split(" ");
  clientTestData.scopes = clientTestData.scopes.split(" ");
  clientTestData.redirect_uris = clientTestData.redirect_uris.split(" ");
});

function setGenerateCodeFunc() {
  CopyAuthorizationCodeFlow.prototype.generateCode = async function (data) {
    return await signToken({
      exp: Math.floor(Date.now() / 1000) + this.code_expires_in,
      sub: data.code_info.sub,
      iss: data.code_info.iss,
      scopes: data.scopes_granted.join(" "),
      state: data.state,
      redirect_uri: data.redirect_uri,
    });
  };
}

function setGenerateTokenFunc() {
  CopyAuthorizationCodeFlow.prototype.generateToken = async function (data) {
    return await signToken({
      exp: Math.floor(Date.now() / 1000) + this.token_expires_in,
      sub: data.token_info.sub,
      iss: data.token_info.iss,
      scopes: data.scopes_granted.join(" "),
      redirect_uri: data.redirect_uri,
    });
  };
}

function setValidateCodeFunc() {
  CopyAuthorizationCodeFlow.prototype.validateCode = async function (code) {
    const codeToken = await checkToken(code);
    return codeToken;
  };
}

async function getValidCode() {
  setGenerateCodeFunc();
  const acFlow = new CopyAuthorizationCodeFlow();
  return await acFlow.getCode({
    response_type: "code",
    client_redirect_uris: clientTestData.redirect_uris,
    redirect_uri: "http://localhost:3000/cb",
    requested_scopes: ["scopeA"],
    client_scopes: clientTestData.scopes,
    state: "stateABCZYX",
    code_info: { sub: "12345" },
  });
}

// ------------------------------------------------------------------------------------------------

describe("authorizationCodeFlow", () => {
  it("constructor() - generating a new AuthorizationCodeFlow with options", () => {
    acFlow = new AuthorizationCodeFlow({
      scope_required: true,
    });
    expect(acFlow).toBeInstanceOf(AuthorizationCodeFlow);
  });

  // ----------------------------------------------------------------------------------------------

  describe("generateCode()", () => {
    it("generateCode() - setting a valid generateCode function with params", async () => {
      let expires;
      CopyAuthorizationCodeFlow.prototype.generateCode = async function (data) {
        expires = Math.floor(Date.now() / 1000) + this.code_expires_in;
        return await signToken({
          exp: expires,
          sub: data.code_info.sub,
          iss: data.code_info.iss,
          scopes: data.scopes_granted.join(" "),
          state: data.state,
          redirect_uri: data.redirect_uri,
        });
      };

      acFlow = new CopyAuthorizationCodeFlow();
      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: "stateABCZYX",
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(expires).toBeDefined();
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBe(expires);
      expect(decoded.state).toBe("stateABCZYX");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("generateCode() - NOT setting a valid generateCode function with params", async () => {
      let errorExpected;
      try {
        await acFlow.generateCode(
          "qwerasdfzxc",
          {},
          "qwerasdfzxc",
          "qwerasdfzxc"
        );
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

  // ----------------------------------------------------------------------------------------------

  describe("validateCode()", () => {
    it("validateCode() - setting a valid validateCode function with params", async () => {
      CopyAuthorizationCodeFlow.prototype.validateCode = async function (
        code,
        scopes_requested
      ) {
        if (code != "qwerasdfzxc") {
          return false;
        }
        if (scopes_requested != "qwerasdfzxc") {
          return false;
        }
        return true;
      };

      acFlow = new CopyAuthorizationCodeFlow();

      const codeToken = await acFlow.validateCode("qwerasdfzxc", "qwerasdfzxc");
      expect(codeToken).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateCode() - NOT setting a valid validateCode function with params", async () => {
      let errorExpected;
      try {
        await acFlow.validateCode("qwerasdfzxc", "qwerasdfzxc");
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

  // ----------------------------------------------------------------------------------------------

  describe("getCode()", () => {
    it("getCode() - passing a wrong type of response code", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "notacode",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "stateABCZYX",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateResponse(): Expected: (code) - Received: (notacode)"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing a callback not valid for the client", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/notvalid",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "stateABCZYX",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("invalid_request");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uri is not valid for the client"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined client redirect_uris", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: undefined,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "stateABCZYX",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uris must be an array of strings containing valid URIs"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined callback", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: undefined,
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "stateABCZYX",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uri must be a valid string containing a valid URI"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an wrong callback with no matching redirect_uri", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow({
        redirect_uri_required: false,
      });

      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/notvalid",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: "stateABCZYX",
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("stateABCZYX");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/notvalid");
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined scope and scope require option", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: true,
      });

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: undefined,
          client_scopes: clientTestData.scopes,
          state: "stateABCZYX",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateScopes(): scopes must be an array of strings"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined scope and scope NOT require option", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: undefined,
        client_scopes: clientTestData.scopes,
        state: "stateABCZYX",
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("stateABCZYX");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined client scopes and scope default required option", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: undefined,
          state: "stateABCZYX",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateScopes(): expected_scopes must be an array of strings"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined state with default required option", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: undefined,
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateState(): state must be a valid string"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - passing an undefined state with NOT required option", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow({
        state_required: false,
      });

      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: undefined,
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBeUndefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("getToken()", () => {
    it("getToken() - passing an undefined code", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: undefined,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected).toBeDefined();
      expect(errorExpected.message).toBe("jwt must be provided");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing valid code and retrieving a token", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeA"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBeUndefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing an undefined client grant types", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: undefined,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateGrant(): expected_grant_types must be a valid array"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing an invalid client grant types", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: ["undefined"],
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("unsupported_grant_type");
      expect(errorExpected.more_info).toBe(
        "validateGrant(): Not supported the grant type: authorization_code"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing missing scope between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA", "scopeC"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
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

    // --------------------------------------------------------------------------------------------

    it("getToken() - pass scopes between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeA", "scopeB"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - pass scopes between several scopes with match all disabled an one invalid", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow({ match_all_scopes: false });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeB", "scopeC"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - pass scopes between several scopes with match all disabled an all invalid", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow({ match_all_scopes: false });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeB", "scopeA"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeB scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing missing scope between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA", "scopeC"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
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

    // --------------------------------------------------------------------------------------------

    it("getToken() - with scopes required pass undefined as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow({ scope_required: true });

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: undefined,
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
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

    // --------------------------------------------------------------------------------------------

    it("getToken() - with scopes required pass undefined as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow({ scope_required: true });

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: [],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
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

    // --------------------------------------------------------------------------------------------

    it("getToken() - with scopes NOT required pass undefined as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow({ scope_required: false });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: undefined,
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with scopes NOT required pass an empty array as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow({ scope_required: false });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing a callback not valid for the client", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: [],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/notavalidcb",
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("invalid_request");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uri is not valid for the client"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing an undefined client redirect_uris", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: [],
          client_redirect_uris: undefined,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uris must be an array of strings containing valid URIs"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing an undefined callback", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: undefined,
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uri must be a valid string containing a valid URI"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing an wrong callback with no matching redirect_uri", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode();
      acFlow = new CopyAuthorizationCodeFlow();

      let errorExpected;
      try {
        await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/notavalidcb",
          token_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected.error).toBe("invalid_request");
      expect(errorExpected.more_info).toBe(
        "validateRedirectUri(): redirect_uri is not valid for the client"
      );
    });
  });
});
