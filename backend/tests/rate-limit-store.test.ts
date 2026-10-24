import { EventEmitter } from "node:events";
import { describe, expect, it } from "@jest/globals";
import { sendCommandWhenReady } from "../src/infrastructure/rateLimitStore.js";

/** A stand-in for the Redis client: connecting at first, and refusing commands until it is ready (offline queue off). */
function fakeClient(initial: string) {
  const events = new EventEmitter();
  const sent: string[][] = [];
  const client = {
    status: initial,
    call: async (...args: string[]) => {
      if (client.status !== "ready") throw new Error("Stream isn't writeable and enableOfflineQueue options is false");
      sent.push(args);
      return "sha";
    },
    once: (e: "ready", l: () => void) => events.once(e, l),
    off: (e: "ready", l: () => void) => events.off(e, l),
    becomeReady() {
      client.status = "ready";
      events.emit("ready");
    },
  };
  return { client, sent };
}

describe("sendCommandWhenReady", () => {
  it("holds the script load until the connection opens, then sends it", async () => {
    const { client, sent } = fakeClient("connecting");
    const pending = sendCommandWhenReady(client, ["SCRIPT", "LOAD", "return 1"]);
    expect(sent).toEqual([]);
    client.becomeReady();
    await expect(pending).resolves.toBe("sha");
    expect(sent).toEqual([["SCRIPT", "LOAD", "return 1"]]);
  });

  it("sends at once when the connection is already open", async () => {
    const { client, sent } = fakeClient("ready");
    await expect(sendCommandWhenReady(client, ["SCRIPT", "LOAD", "x"])).resolves.toBe("sha");
    expect(sent).toHaveLength(1);
  });

  it("does NOT wait for any other command: a request fails fast while Redis is not there", async () => {
    const { client } = fakeClient("reconnecting");
    await expect(sendCommandWhenReady(client, ["EVALSHA", "sha", "1", "key"])).rejects.toThrow(/Stream isn't writeable/);
  });
});
