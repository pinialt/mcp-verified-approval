import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startServer } from "../src/index.js";
import { newClient } from "./helpers.js";
import { VERIFIED_APPROVAL_CAPABILITY_KEY } from "mcp-verified-approval/shared";

let handle: { port: number; close: () => Promise<void> };
let baseUrl: string;

beforeAll(async () => {
  handle = await startServer(0);
  baseUrl = `http://localhost:${handle.port}/mcp`;
});

afterAll(async () => {
  await handle.close();
});

describe("capability declaration", () => {
  it("server declares verifiedApproval capability in initialize", async () => {
    const c = await newClient(baseUrl);
    try {
      const caps = c.getServerCapabilities();
      expect(caps).toBeDefined();
      const extensions = (caps as Record<string, unknown>).extensions;
      expect(extensions).toBeDefined();
      const value = (extensions as Record<string, unknown>)[VERIFIED_APPROVAL_CAPABILITY_KEY];
      expect(value).toEqual({});
    } finally {
      await c.close();
    }
  });
});
