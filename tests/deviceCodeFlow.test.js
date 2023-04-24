import { describe, it, beforeEach } from "vitest";
import DeviceCodeFlow from "../flows/DeviceCodeFlow";
import { checkToken, decodeToken, signToken, clientData } from "./utils.js";

// ------------------------------------------------------------------------------------------------

let dcFlow;
let CopyDeviceCodeFlow;
let clientTestData;

// ------------------------------------------------------------------------------------------------

beforeEach(async () => {
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
        ...args.device_code_info,
        exp: Math.floor(Date.now() / 1000) + args.expires_in,
        scopes: args.scopes_granted || "",
        verification_uri: args.verification_uri,
        user_code: args.user_code,
        interval: args.interval,
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

  describe("requestDeviceCode()", () => {
    it("requestDeviceCode() - testing additional info on request device code", async () => {
      setGenerateDeviceCodeFunc();
      const dcFlow = new CopyDeviceCodeFlow();
      const { device_code } = await dcFlow.requestDeviceCode({
        interval: 5,
        expires_in: 1800,
        add_chars: "-",
        only_numbers: false,
        user_code_size: 10,
        verification_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientData.scopes.split(" "),
        device_code_info: { someInfo: 123 },
      });

      const decoded = await decodeToken(device_code);
      expect(decoded.someInfo).toBe(123);
    });

    // --------------------------------------------------------------------------------------------

    it("requestDeviceCode() - testing interval property set on device_code", async () => {
      setGenerateDeviceCodeFunc();
      const dcFlow = new CopyDeviceCodeFlow();
      const { device_code } = await dcFlow.requestDeviceCode({
        interval: 23,
        expires_in: 1800,
        add_chars: "-",
        only_numbers: false,
        user_code_size: 10,
        verification_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientData.scopes.split(" "),
        device_code_info: { someInfo: 123 },
      });

      const decoded = await decodeToken(device_code);
      expect(decoded.interval).toBe(23);
    });

    // --------------------------------------------------------------------------------------------

    it("requestDeviceCode() - testing user code length", async () => {
      setGenerateDeviceCodeFunc();
      const dcFlow = new CopyDeviceCodeFlow();
      const { user_code } = await dcFlow.requestDeviceCode({
        interval: 5,
        expires_in: 1800,
        add_chars: "-",
        only_numbers: false,
        user_code_size: 21,
        verification_uri: "http://localhost:3000/cb",
        requested_scopes: ["scopeA"],
        client_scopes: clientData.scopes.split(" "),
        device_code_info: { someInfo: 123 },
      });

      expect(user_code).toHaveProperty("length", 21);
    });

    // --------------------------------------------------------------------------------------------
  });

  // ----------------------------------------------------------------------------------------------

  // describe("getToken()", () => {});
});
