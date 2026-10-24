import { expect, test } from "vitest";
import zhTW from "./zh-TW.json";
import en from "./en.json";

const keys = (o: object, p = ""): string[] =>
  Object.entries(o)
    .flatMap(([k, v]) => (typeof v === "object" && v ? keys(v, p + k + ".") : [p + k]))
    .sort();

test("zh-TW and en have identical key sets", () => {
  expect(keys(zhTW)).toEqual(keys(en));
});
