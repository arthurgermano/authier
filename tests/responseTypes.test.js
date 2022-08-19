import { describe, it } from "vitest";
import * as responseTypes from "../response_types/index.js";

// ------------------------------------------------------------------------------------------------

describe("responseTypes", () => {
  it("validateResponse() - validating a valid and supported response type", () => {
    expect(responseTypes.validateResponse("code", "code")).toBe(true);
  });

  // ----------------------------------------------------------------------------------------------

  it("validateResponse() - validating a invalid response type", () => {
    const resultFn = () => responseTypes.validateResponse("code", "token");
    expect(resultFn).toThrow();
  });

  // ----------------------------------------------------------------------------------------------

  it("validateResponse() - validating a invalid param response_type", () => {
    let errorExpected;
    try {
      responseTypes.validateResponse(undefined, "token");
    } catch (error) {
      errorExpected = error;
    }

    expect(errorExpected).toHaveProperty("error", "server_error");
    expect(errorExpected).toHaveProperty(
      "more_info",
      "validateResponse(): response_type must be a valid string"
    );
  });

  // ----------------------------------------------------------------------------------------------

  it("validateResponse() - validating a invalid param expected_response_type", () => {
    let errorExpected;
    try {
      responseTypes.validateResponse("token");
    } catch (error) {
      errorExpected = error;
    }

    expect(errorExpected).toHaveProperty("error", "server_error");
    expect(errorExpected).toHaveProperty(
      "more_info",
      "validateResponse(): expected_response_type must be a valid string"
    );
  });

  // ----------------------------------------------------------------------------------------------
});
