import { describe, it, beforeEach } from "vitest";
import AuthFlow from "../flows/AuthFlow.js";

// ------------------------------------------------------------------------------------------------

let authFlow;
let CopyAuthFlow;

// ------------------------------------------------------------------------------------------------

beforeEach(() => {
  CopyAuthFlow = class extends AuthFlow {};
  authFlow = new AuthFlow();
});

// ------------------------------------------------------------------------------------------------

describe("authFlow", () => {
  describe("validateRedirectUri()", () => {
    it("validateRedirectUri() - validating a valid and supported redirect_uri", () => {
      expect(
        authFlow.validateRedirectUri("http://localhost:3000/callback", [
          "http://localhost:3000/callback",
        ])
      ).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a invalid redirect_uri", () => {
      let errorExpected;
      try {
        authFlow.validateRedirectUri("http://localhost:3000/callback", [
          "http://localhost:3000/callback2",
        ]);
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
        authFlow.validateRedirectUri(undefined, [
          "http://localhost:3000/callback",
        ]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "server_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateRedirectUri(): redirect_uri must be a valid string containing a valid URI"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a invalid param redirect_uris", () => {
      let errorExpected;
      try {
        authFlow.validateRedirectUri(
          "http://localhost:3000/callback",
          undefined
        );
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "server_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateRedirectUri(): redirect_uris must be an array of strings containing valid URIs"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a valid url with encoding", () => {
      expect(
        authFlow.validateRedirectUri(
          "http%3A%2F%2Flocalhost%3A3000%2Fcallback%2Fteste%3Fid%3D1%26name%3DServer",
          ["http://localhost:3000/callback/teste?id=1&name=Server"],
          true
        )
      ).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateRedirectUri() - validating a invalid url with encoding", () => {
      let errorExpected;
      try {
        authFlow.validateRedirectUri(
          "http://localhost:3000/callback/teste?id=1&name=Server",
          ["http://localhost:3000/callback/teste?id=1&name=Server"],
          true
        );
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

  describe("validateState()", () => {
    it("validateState() - validating a valid state", () => {
      expect(authFlow.validateState("qwerasdfzxc", "qwerasdfzxc")).toBe(true);
    });

    // --------------------------------------------------------------------------------------------

    it("validateState() - validating a invalid state", () => {
      let errorExpected;
      try {
        authFlow.validateState("qwerasdfzxc", "qwerasdfzxc2");
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_request");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateState(): state is different from the expected state"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateState() - validating a invalid param state", () => {
      let errorExpected;
      try {
        authFlow.validateState(undefined, "qwerasdfzxc");
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "server_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateState(): state must be a valid string"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateState() - validating a invalid param expected state", () => {
      let errorExpected;
      try {
        authFlow.validateState("qwerasdfzxc", undefined);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "server_error");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateState(): expected_state must be a valid string"
      );
    });
  });

  // ----------------------------------------------------------------------------------------------

  describe("validateScopes()", () => {
    it("validateScopes() - validating a valid scope", () => {
      expect(
        authFlow.validateScopes(["scopeA"], ["scopeA", "scopeB"], false)
      ).toEqual(["scopeA"]);
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid scope", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(["scopeA"], ["scopeB"]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scope scopeB is not valid"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid param scope - required scope", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(undefined, ["scopeA", "scopeB"], true, true);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scopes requested are not valid for this client"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid param expected scope", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(["scopeA"], undefined, true, true);
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
      expect(
        authFlow.validateScopes(
          ["scopeC", "scopeB"],
          ["scopeD", "scopeB"],
          false,
          true
        )
      ).toEqual(["scopeB"]);
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating a invalid scopes among several scopes", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(["scopeC", "scopeB"], ["scopeD", "scopeA"]);
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scope scopeD is not valid"
      );
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating valid scopes with match all scopes enabled", () => {
      expect(
        authFlow.validateScopes(
          ["scopeC", "scopeB"],
          ["scopeB", "scopeC"],
          true
        )
      ).toEqual(["scopeB", "scopeC"]);
    });

    // --------------------------------------------------------------------------------------------

    it("validateScopes() - validating invalid scopes with match all scopes enabled", () => {
      let errorExpected;
      try {
        authFlow.validateScopes(
          ["scopeC", "scopeB"],
          ["scopeC", "scopeE", "scopeA", "scopeD"],
          true
        );
      } catch (error) {
        errorExpected = error;
      }

      expect(errorExpected).toHaveProperty("error", "invalid_scope");
      expect(errorExpected).toHaveProperty(
        "more_info",
        "validateScopes(): The scope scopeE is not valid"
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
