import { describe, it, beforeEach } from "vitest";
import DeviceCodeFlow from "../flows/DeviceCodeFlow";
import { checkToken, decodeToken, signToken, clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let dcFlow;
let CopyDeviceCodeFlow;
let clientTestData;

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyDeviceCodeFlow = class extends DeviceCodeFlow {
    constructor(options = {}) {
      super(options);
    }
  };
  dcFlow = new DeviceCodeFlow();
  clientTestData = Object.assign({}, clientData);
  clientTestData.grant_types = clientTestData.grant_types.split(" ");
  clientTestData.scopes = clientTestData.scopes.split(" ");
  clientTestData.redirect_uris = clientTestData.redirect_uris.split(" ");
});

function setGenerateDeviceCodeFunc() {
  CopyDeviceCodeFlow.prototype.generateDeviceCode =
    async function generateDeviceCode(args) {
      return await signToken({
        exp: Math.floor(Date.now() / 1000) + args.expires_in,
        scopes: args.scopes_granted || "",
        verification_uri: args.verification_uri,
        user_code: args.user_code,
      });
    };
}

function setGenerateTokenFunc() {
  CopyDeviceCodeFlow.prototype.generateToken = async function (data) {
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
  CopyDeviceCodeFlow.prototype.validateDeviceCode =
    async function validateDeviceCode(args) {
      try {
        return await checkToken(args.device_code);
      } catch (error) {
        throw error;
      }
    };
}

async function getValidDeviceCode(options, params = {}) {
  setGenerateDeviceCodeFunc();
  const dcFlow = new CopyDeviceCodeFlow(options);
  return await dcFlow.requestDeviceCode({
    interval: 5,
    expires_in: 1800,
    add_chars: "-",
    only_numbers: false,
    user_code_size: 10,
    verification_uri: "http://localhost:3000/cb",
    requested_scopes: ["scopeA"],
    client_scopes: clientData.scopes.split(" "),
    ...params,
  });
}

// ------------------------------------------------------------------------------------------------

describe("deviceCodeFlow", () => {
  it("constructor() - generating a new DeviceCodeFlow with options", () => {
    dcFlow = new DeviceCodeFlow({
      scope_required: true,
    });
    expect(dcFlow).toBeInstanceOf(DeviceCodeFlow);
  });

  // ----------------------------------------------------------------------------------------------

  describe("generateDeviceCode()", () => {
    it("generateDeviceCode() - setting a valid generateDeviceCode function with params", async () => {
      let expires;
      CopyDeviceCodeFlow.prototype.generateDeviceCode =
        async function generateDeviceCode(args) {
          expires = Math.floor(Date.now() / 1000) + args.expires_in;
          return await signToken({
            exp: expires,
            scopes: args.scopes_granted.join(" ") || "",
            verification_uri: args.verification_uri,
            user_code: args.user_code,
          });
        };

      dcFlow = new CopyDeviceCodeFlow();
      const { device_code, user_code } = await dcFlow.requestDeviceCode({
        interval: 5,
        expires_in: 1800,
        add_chars: "-",
        only_numbers: false,
        user_code_size: 10,
        verification_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientData.scopes.split(" "),
      });
      const decoded = await decodeToken(device_code);
      expect(device_code).toBeTypeOf("string");
      expect(expires).toBeDefined();
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBe(expires);
      expect(decoded.verification_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("generateDeviceCode() - NOT setting a valid generateDeviceCode function with params", async () => {
      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
          interval: 5,
          expires_in: 1800,
          add_chars: "-",
          only_numbers: false,
          user_code_size: 10,
          verification_uri: "http://localhost:3000/cb",
          requested_scopes: ["scopeA"],
          client_scopes: clientData.scopes.split(" "),
        });
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected).toHaveProperty("error", "todo_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "generateDeviceCode(): not implemented yet!"
      );
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("validateDeviceCode()", () => {
    it("validateDeviceCode() - setting a valid validateDeviceCode function with params", async () => {
      CopyDeviceCodeFlow.prototype.validateDeviceCode =
        async function validateDeviceCode(args) {
          try {
            if (args.device_code != "qwerasdfzxc") {
              return false;
            }
            if (args.scopes_requested != "qwerasdfzxc") {
              return false;
            }
            return true;
          } catch (error) {
            throw error;
          }
        };

      dcFlow = new CopyDeviceCodeFlow();

      const decodeToken = await dcFlow.validateDeviceCode({
        device_code: "qwerasdfzxc",
        scopes_requested: "qwerasdfzxc",
      });
      expect(decodeToken).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateDeviceCode() - NOT setting a valid validateDeviceCode function with params", async () => {
      let errorExpected;
      try {
        await dcFlow.validateDeviceCode({
          device_code: "qwerasdfzxc",
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
  // TODO!!!
  describe("requestDeviceCode()", () => {
    it("requestDeviceCode() - passing a wrong type of response code", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing a callback not valid for the client", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing an undefined client redirect_uris", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing an undefined callback", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing an wrong callback with no matching redirect_uri", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow({
        redirect_uri_required: false,
      });

      const decodeToken = await dcFlow.requestDeviceCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/notvalid",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: "stateABCZYX",
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(decodeToken);
      expect(decodeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("stateABCZYX");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/notvalid");
    });

    // --------------------------------------------------------------------------------------------

    it("requestDeviceCode() - passing an undefined scope and scope require option", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow({
        scope_required: true,
      });

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing an undefined scope and scope NOT require option", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      const decodeToken = await dcFlow.requestDeviceCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: undefined,
        client_scopes: clientTestData.scopes,
        state: "stateABCZYX",
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(decodeToken);
      expect(decodeToken).toBeTypeOf("string");
      expect(decoded.sub).toBe("12345");
      expect(decoded.scopes).toBe("scopeA scopeB");
      expect(decoded.exp).toBeDefined();
      expect(decoded.state).toBe("stateABCZYX");
      expect(decoded.redirect_uri).toBe("http://localhost:3000/cb");
    });

    // --------------------------------------------------------------------------------------------

    it("requestDeviceCode() - passing an undefined client scopes and scope default required option", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing an undefined state with default required option", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.requestDeviceCode({
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

    it("requestDeviceCode() - passing an undefined state with NOT required option", async () => {
      setGenerateDeviceCodeFunc();

      dcFlow = new CopyDeviceCodeFlow({
        state_required: false,
      });

      const decodeToken = await dcFlow.requestDeviceCode({
        response_type: "code",
        client_redirect_uris: clientTestData.redirect_uris,
        redirect_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientTestData.scopes,
        state: undefined,
        code_info: { sub: "12345" },
      });

      const decoded = await decodeToken(decodeToken);
      expect(decodeToken).toBeTypeOf("string");
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

      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      const token = await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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
        "validateGrant(): Not supported the grant type: device_code"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - passing missing scope between several scopes", async () => {
      setValidateCodeFunc();
      setGenerateTokenFunc();

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      const token = await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow({
        match_all_scopes: false,
      });

      const token = await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow({
        match_all_scopes: false,
      });

      const token = await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow({
        scope_required: true,
      });

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow({
        scope_required: true,
      });

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow({
        scope_required: false,
      });

      const token = await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow({
        scope_required: false,
      });

      const token = await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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

      const code = await getValidDeviceCode();
      dcFlow = new CopyDeviceCodeFlow();

      let errorExpected;
      try {
        await dcFlow.getToken({
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
