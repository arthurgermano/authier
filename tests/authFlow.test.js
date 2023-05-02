import { describe, it, beforeEach } from "vitest";
import AuthFlow from "../flows/AuthFlow.js";
import { clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let authFlow;
let CopyAuthFlow;
const copyClientData = {
  ...clientData,
  grant_types: clientData.grant_types.split(" "),
  redirect_uris: clientData.redirect_uris.split(" "),
  scopes: clientData.scopes.split(" "),
};

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyAuthFlow = class extends AuthFlow {};
  authFlow = new AuthFlow(copyClientData);
});

// ------------------------------------------------------------------------------------------------

describe("authFlow", () => {
  describe("validateRedirectUri()", () => {
    it("validateRedirectUri() - validating a valid and supported redirect_uri", () => {
      expect(authFlow.validateRedirectUri("http://localhost:3000/cb")).toBe(
        true
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a invalid redirect_uri", () => {
      let errorExpected;
      try {
        authFlow.validateRedirectUri("http://localhost:3000/callback");
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected).toHaveProperty("error", "invalid_request");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateRedirectUri(): redirect_uri is not valid for the client"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a invalid param redirect_uri", () => {
      let errorExpected;
      try {
        authFlow.validateRedirectUri(undefined);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_request");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateRedirectUri(): redirect_uri must be a valid string containing a valid URI"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a valid url with encoding", () => {
      authFlow = new AuthFlow({ ...copyClientData, is_uri_encoded: true });
      expect(
        authFlow.validateRedirectUri("http%3A%2F%2Flocalhost%3A3000%2Fcb")
      ).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a invalid url with encoding", () => {
      let errorExpected;
      authFlow = new AuthFlow({ ...copyClientData, is_uri_encoded: true });
      try {
        authFlow.validateRedirectUri("http://localhost:3000/cb");
      } catch (error) {
        errorExpected = error;
      }
      expect(errorExpected).toHaveProperty("error", "invalid_request");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateRedirectUri(): redirect_uri is not valid for the client"
      );
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("validateScopes()", () => {
    it("validateScopes() - validating a valid scope", () => {
      expect(authFlow.validateScopes(["scopeA"])).toEqual(["scopeA"]);
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid scope", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(["scopeX"]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scope scopeX is not valid"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid param scope - required scope", () => {
      let errorExpected;
      try {
        authFlow = new AuthFlow({ ...copyClientData, scopes: [] });
        authFlow.validateScopes(["scopeA", "scopeB"]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scopes requested are not valid for this client - this client has no scopes"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid param expected scope", () => {
      let errorExpected;
      try {
        authFlow.validateScopes();
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): No scopes informed but this client requires scopes to be informed"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a valid scopes among several scopes", () => {
      authFlow = new AuthFlow({ ...copyClientData, match_all_scopes: false });
      expect(authFlow.validateScopes(["scopeC", "scopeB"])).toEqual(["scopeB"]);
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid scopes among several scopes", () => {
      let errorExpected;
      try {
        authFlow = new AuthFlow({ ...copyClientData });
        authFlow.validateScopes(["scopeX", "scopeY"]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scope scopeX is not valid"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating valid scopes with match all scopes enabled", () => {
      expect(authFlow.validateScopes(["scopeA", "scopeB"])).toEqual([
        "scopeA",
        "scopeB",
      ]);
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating invalid scopes with match all scopes enabled", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(["scopeX", "scopeY"]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scope scopeX is not valid"
      );
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("generateToken()", () => {
    it("generateToken() - setting a valid generateToken function and retrieve a token from new function", async () => {
      CopyAuthFlow.prototype.generateToken = (params) => {
        return {
          access_token: "qwerasdfzxc",
          expires_in: 3600,
          token_type: "Bearer",
          params: "param",
        };
      };

      authFlow = new CopyAuthFlow();

      const token = await authFlow.generateToken("param");
      expect(token).toHaveProperty("access_token", "qwerasdfzxc");
      expect(token).toHaveProperty("expires_in", 3600);
      expect(token).toHaveProperty("token_type", "Bearer");
      expect(token).toHaveProperty("params", "param");
    });

    // --------------------------------------------------------------------------------------------

    it("generateToken() - not setting a generateToken function to throw an error", async () => {
      let errorExpected;
      try {
        await authFlow.generateToken();
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "todo_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "generateToken(): not implemented yet!"
      );
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("getToken()", () => {
    it("getToken() - setting a valid getToken function and retrieve a token information", async () => {
      CopyAuthFlow.prototype.getToken = (token) => {
        return {
          sub: "1234567890",
          name: "John Doe",
          admin: true,
          iat: 1516239022,
          exp: 1516239022,
          scope: "scopeA scopeB",
        };
      };

      authFlow = new CopyAuthFlow();

      const token = await authFlow.getToken("qwerasdfzxc");
      expect(token).toHaveProperty("sub", "1234567890");
      expect(token).toHaveProperty("name", "John Doe");
      expect(token).toHaveProperty("admin", true);
      expect(token).toHaveProperty("exp", 1516239022);
    });

    // --------------------------------------------------------------------------------------------

    it("getToken() - not setting a getToken function to throw an error", async () => {
      let errorExpected;
      try {
        await authFlow.getToken("qwerasdfzxc");
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "todo_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "getToken(): not implemented yet!"
      );
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("validateToken()", () => {
    it("validateToken() - setting a valid validateToken function and validate a given token", async () => {
      CopyAuthFlow.prototype.validateToken = (token) => {
        if (token === "qwerasdfzxc") {
          return true;
        }
      };

      authFlow = new CopyAuthFlow();

      const token = await authFlow.validateToken("qwerasdfzxc");
      expect(token).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateToken() - not setting a validateToken function to throw an error", async () => {
      let errorExpected;
      try {
        await authFlow.validateToken("qwerasdfzxc");
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "todo_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateToken(): not implemented yet!"
      );
    });
  });
});
