import { describe, it, expect } from "vitest";
import { OAuthError, ERROR_SPECS } from "../src/errors/index.js";

// ==================================================================================================================================================

describe("OAuthError Class and ERROR_SPECS", () => {
  // ================================================================================================================================================

  for (const [key, spec] of Object.entries(ERROR_SPECS)) {
    it(`OAuthError instanciado para ${key} deve conter propriedades corretas`, () => {
      const moreInfo = { detail: "info extra" };
      const error = new OAuthError(spec, moreInfo);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(OAuthError);
      expect(error.name).toBe("OAuthError");
      expect(error.error).toBe(spec.code);
      expect(error.error_description).toBe(spec.description);
      expect(error.status).toBe(spec.status);
      expect(error.more_info).toBe(moreInfo);
      expect(error.message).toBe(spec.description);
    });

    it(`toResponseObject() de OAuthError para ${key} retorna objeto esperado`, () => {
      const error = new OAuthError(spec);
      const response = error.toResponseObject();

      expect(response).toEqual({
        error: spec.code,
        error_description: spec.description,
        status: spec.status,
      });
    });
  }

  // ================================================================================================================================================

  describe("Método estático throw()", () => {
    it("deve lançar OAuthError para erro conhecido", () => {
      expect(() =>
        OAuthError.throw("INVALID_CLIENT", { extra: "x" })
      ).toThrowError(OAuthError);
      try {
        OAuthError.throw("INVALID_CLIENT", { extra: "x" });
      } catch (err) {
        expect(err.error).toBe(ERROR_SPECS.INVALID_CLIENT.code);
        expect(err.more_info).toEqual({ extra: "x" });
      }
    });

    it("deve lançar OAuthError SERVER_ERROR para erro desconhecido", () => {
      expect(() =>
        OAuthError.throw("ERRO_INEXISTENTE", { extra: "x" })
      ).toThrowError(OAuthError);
      try {
        OAuthError.throw("ERRO_INEXISTENTE", { extra: "x" });
      } catch (err) {
        console.log(err);
        expect(err.error).toBe(ERROR_SPECS.SERVER_ERROR.code);
        expect(err.more_info.originalErrorType).toMatch(/ERRO_INEXISTENTE/);
      }
    });

    it("lança erro mesmo sem more_info", () => {
      expect(() => OAuthError.throw("INVALID_SCOPE")).toThrowError(OAuthError);
      try {
        OAuthError.throw("INVALID_SCOPE");
      } catch (err) {
        expect(err.error).toBe(ERROR_SPECS.INVALID_SCOPE.code);
        expect(err.more_info).toBeUndefined();
      }
    });
  });

  // ================================================================================================================================================
});
