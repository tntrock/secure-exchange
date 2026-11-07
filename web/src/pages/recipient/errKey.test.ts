import { expect, test } from "vitest";
import { ApiError } from "../../api";
import { errKey } from "./errKey";

test("403 maps ip_denied explicitly; unknown codes fall back to generic", () => {
  expect(errKey(new ApiError(403, "ip_denied"))).toBe("ipDenied");
  expect(errKey(new ApiError(403, "something_new"))).toBe("generic");
  expect(errKey(new ApiError(403, "view_limit"))).toBe("viewLimit");
});
