import { describe, it } from "vitest";
import * as grantTypes from "../grant_types/index.js";

// ------------------------------------------------------------------------------------------------

describe("grantTypes", () => {
  // ----------------------------------------------------------------------------------------------

  it("validateGrant() - validating a valid and supported grant type", () => {
    expect(grantTypes.validateGrant("password", ["password"])).toBe(true);
  });

  // ----------------------------------------------------------------------------------------------

  it("validateGrant() - validating a invalid grant type", () => {
    let errorExpected;
    try {
      grantTypes.validateGrant("password", ["authorization_code"]);
    } catch (error) {
      errorExpected = error;
    }

    expect(errorExpected).toHaveProperty("error", "unsupported_grant_type");
    expect(errorExpected).toHaveProperty(
      "more_info",
      `validateGrant(): Unsupported grant type: password`
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("validateGrant() - validating a invalid param grant_type", () => {
    let errorExpected;
    try {
      grantTypes.validateGrant(undefined, ["authorization_code"]);
    } catch (error) {
      errorExpected = error;
    }

    expect(errorExpected).toHaveProperty("error", "server_error");
    expect(errorExpected).toHaveProperty(
      "more_info",
      "validateGrant(): grant_type must be a valid string"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("validateGrant() - validating a invalid param expected_grant_type", () => {
    let errorExpected;
    try {
      grantTypes.validateGrant("authorization_code", {
        authorization_code: true,
      });
    } catch (error) {
      errorExpected = error;
    }

    expect(errorExpected).toHaveProperty("error", "server_error");
    expect(errorExpected).toHaveProperty(
      "more_info",
      "validateGrant(): expected_grant_type must be a valid array"
    );
  });

  // ----------------------------------------------------------------------------------------------
});
