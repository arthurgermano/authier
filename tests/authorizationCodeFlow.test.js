import { describe, it, beforeEach } from "vitest";
import AuthorizationCodeFlow from "../flows/AuthorizationCodeFlow";
import {
  checkToken,
  decodeToken,
  signToken,
  clientData,
  generateVerifier,
  generateChallenge,
} from "./utils.js";

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
  CopyAuthorizationCodeFlow.prototype.validateCode =
    async function validateCode(args) {
      try {
        return await checkToken(args.code);
      } catch (error) {
        throw error;
      }
    };
}

async function getValidCode(options, params = {}) {
  setGenerateCodeFunc();
  const acFlow = new CopyAuthorizationCodeFlow(options);
  return await acFlow.getCode({
    response_type: "code",
    client_redirect_uris: clientTestData.redirect_uris,
    redirect_uri: "http://localhost:3000/cb",
    requested_scopes: ["scopeA"],
    client_scopes: clientTestData.scopes,
    state: "stateABCZYX",
    code_info: { sub: "12345" },
    ...params,
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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });
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
      CopyAuthorizationCodeFlow.prototype.validateCode = async function (args) {
        if (args.code != "qwerasdfzxc") {
          return false;
        }
        if (args.scopes_requested != "qwerasdfzxc") {
          return false;
        }
        return true;
      };

      acFlow = new CopyAuthorizationCodeFlow();

      const codeToken = await acFlow.validateCode({
        code: "qwerasdfzxc",
        scopes_requested: "qwerasdfzxc",
      });
      expect(codeToken).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateCode() - NOT setting a valid validateCode function with params", async () => {
      let errorExpected;
      try {
        await acFlow.validateCode({
          code: "qwerasdfzxc",
          scopes_requested: "qwerasdfzxc",
        });
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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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
        pkce_required: false,
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
        pkce_required: false,
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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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
        pkce_required: false,
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

      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({
        match_all_scopes: false,
        pkce_required: false,
      });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({
        match_all_scopes: false,
        pkce_required: false,
      });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: true,
        pkce_required: false,
      });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: true,
        pkce_required: false,
      });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
        pkce_required: false,
      });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
        pkce_required: false,
      });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

      const code = await getValidCode({ pkce_required: false });
      acFlow = new CopyAuthorizationCodeFlow({ pkce_required: false });

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

  // ----------------------------------------------------------------------------------------------

  describe("getCode() - with PKCE", () => {
    it("getCode() - with PKCE - passing a wrong type of response code", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing a callback not valid for the client", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined client redirect_uris", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined callback", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an wrong callback with no matching redirect_uri", async () => {
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
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined scope and scope require option", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined scope and scope NOT require option", async () => {
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
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined client scopes and scope default required option", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined state with default required option", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
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

    it("getCode() - with PKCE - passing an undefined state with NOT required option", async () => {
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
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBeUndefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - with PKCE - specifying algorithm to PKCE", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow({
        mapping_challenge_methods: {
          S256: "sha256",
        },
      });

      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: "wqeasdzxc",
        code_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("wqeasdzxc");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - with PKCE - specifying wrong algorithm to PKCE", async () => {
      setGenerateCodeFunc();

      let errorExpected;
      try {
        acFlow = new CopyAuthorizationCodeFlow({
          mapping_challenge_methods: {
            S258: "sha256",
          },
        });
        const codeToken = await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "wqeasdzxc",
          code_info: { sub: "12345" },
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
        });
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected.error).toBe("invalid_request");
      expect(errorExpected.more_info).toBe(
        "The requested algorithm S256 is not supported by this server!"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - with PKCE - allowing plain method as code challenge method", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow({
        allow_plain_pkce_method: true,
      });
      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: "wqeasdzxc",
        code_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "plain",
      });
      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("wqeasdzxc");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - with PKCE - specifying plain when not allowed", async () => {
      setGenerateCodeFunc();

      let errorExpected;
      try {
        acFlow = new CopyAuthorizationCodeFlow();
        const codeToken = await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "wqeasdzxc",
          code_info: { sub: "12345" },
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "plain",
        });
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected.error).toBe("invalid_request");
      expect(errorExpected.more_info).toBe(
        "The requested algorithm plain is not supported by this server!"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - with PKCE - not informing pkce code challenge", async () => {
      setGenerateCodeFunc();

      let errorExpected;
      try {
        acFlow = new CopyAuthorizationCodeFlow();
        const codeToken = await acFlow.getCode({
          response_type: "code",
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientTestData.scopes,
          state: "wqeasdzxc",
          code_info: { sub: "12345" },
        });
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        'The code challenge "undefined" is not correct or is missing!'
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getCode() - with PKCE - not informing pkce code challenge method", async () => {
      setGenerateCodeFunc();

      acFlow = new CopyAuthorizationCodeFlow();
      const codeToken = await acFlow.getCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: "wqeasdzxc",
        code_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
      });

      const decoded = await decodeToken(codeToken);
      expect(codeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("wqeasdzxc");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("getToken() - with PKCE", () => {
    it("getToken() - with PKCE - passing an undefined code", async () => {
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected).toBeDefined();
      expect(errorExpected.message).toBe("jwt must be provided");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - passing valid code and retrieving a token", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow();

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeA"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - passing an undefined client grant types", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - passing an invalid client grant types", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - passing missing scope between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - pass scopes between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow();

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeA", "scopeB"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - pass scopes between several scopes with match all disabled an one invalid", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        match_all_scopes: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeB", "scopeC"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - pass scopes between several scopes with match all disabled an all invalid", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        match_all_scopes: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: ["scopeB", "scopeA"],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeB scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - passing missing scope between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - with scopes required pass undefined as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: true,
      });

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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - with scopes required pass undefined as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: true,
      });

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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - with scopes NOT required pass undefined as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: undefined,
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - with scopes NOT required pass an empty array as scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - passing a callback not valid for the client", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - passing an undefined client redirect_uris", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - passing an undefined callback", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - passing an wrong callback with no matching redirect_uri", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
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
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
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

    it("getToken() - with PKCE - specifying algorithm to PKCE", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - specifying wrong algorithm to PKCE", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(
        {
          mapping_challenge_methods: {
            S256: "sha256",
          },
        },
        {
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S256",
        }
      );
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      let errorExpected;
      try {
        const token = await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: ["scopeA"],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_challenge_method: "S258",
          code_verifier:
            "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
        });
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        'The algorithm "S258" is not supported by this client or server'
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - omitting code challenge method - default S256", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - testing plain code challenge method", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(
        { allow_plain_pkce_method: true },
        {
          code_challenge: "testePlain",
          code_challenge_method: "plain",
        }
      );
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
        allow_plain_pkce_method: true,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "testePlain",
        code_challenge_method: "plain",
        code_verifier: "testePlain",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - testing plain code challenge method passing wrong challenge verifier", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(
        { allow_plain_pkce_method: true },
        {
          code_challenge: "testePlain",
          code_challenge_method: "plain",
        }
      );
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
        allow_plain_pkce_method: true,
      });

      let errorExpected;
      try {
        const token = await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: [],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
          code_challenge: "testePlain",
          code_challenge_method: "plain",
          code_verifier: "testePlainWrong",
        });
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "The code verifier is not matching the code challenge!"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - testing s256 code challenge method", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_verifier:
          "BB32OXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - testing s256 code challenge method with wrong code verifier", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidCode(undefined, {
        code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
        code_challenge_method: "S256",
      });
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
      });

      let errorExpected;
      try {
        const token = await acFlow.getToken({
          code: code,
          client_grant_types: clientTestData.grant_types,
          client_scopes: clientTestData.scopes,
          scopes_requested: [],
          client_redirect_uris: clientTestData.redirect_uris,
          redirect_uri: "http://localhost:3000/cb",
          token_info: { sub: "12345" },
          code_challenge: "UcFg4J3qoHQxPDDayo347Kk9QTFUBOAlvuUYttOJMJU",
          code_verifier:
            "BBOXv3qmG6OIe3sTZHjbbP3NW.wltvQ_k73ZHlA42uELwbqX3Xlm4jx_Bv8QQN3sBHMW2c2NSyDYuB0YUFTV2-XjwbfCOK8F_UfbU~72EWJ0dGFOs2.9~giG0TEFXk",
        });
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected.error).toBe("server_error");
      expect(errorExpected.more_info).toBe(
        "The code verifier is not matching the code challenge!"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - with PKCE - testing different code challenge method", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const verifier = generateVerifier();
      const challege = generateChallenge(verifier, "sha512");

      const code = await getValidCode(
        {
          mapping_challenge_methods: {
            S512: "sha512",
          },
        },
        {
          code_challenge: challege,
          code_challenge_method: "S512",
        }
      );
      acFlow = new CopyAuthorizationCodeFlow({
        scope_required: false,
        mapping_challenge_methods: {
          S512: "sha512",
        },
      });

      const token = await acFlow.getToken({
        code: code,
        client_grant_types: clientTestData.grant_types,
        client_scopes: clientTestData.scopes,
        scopes_requested: [],
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        token_info: { sub: "12345" },
        code_challenge: challege,
        code_challenge_method: "S512",
        code_verifier: verifier,
      });

      const decoded = await decodeToken(token);
      expect(token).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });
  });
});
