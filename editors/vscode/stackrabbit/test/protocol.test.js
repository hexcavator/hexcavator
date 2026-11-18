// The session protocol's framing: `node test/protocol.test.js`.
"use strict";

const assert = require("assert");
const { encode, Decoder, Session, MAX_HEADER } = require("../lib/protocol");

// A frame's bytes: the two lengths, the header, the payload.
{
  const f = encode({ a: 1 }, Buffer.from([9, 8, 7]));
  assert.deepStrictEqual([...f.subarray(0, 8)], [7, 0, 0, 0, 3, 0, 0, 0]);
  assert.strictEqual(f.subarray(8, 15).toString(), '{"a":1}');
  assert.deepStrictEqual([...f.subarray(15)], [9, 8, 7]);
}

// Frames split anywhere, and joined, decode the same.
{
  const frames = [
    [{ id: 1, result: { rows: [1, 2] } }, Buffer.alloc(0)],
    [{ method: "progress", params: { text: "ü✓" } }, Buffer.from("payload")],
    [{ id: 2, error: "no" }, Buffer.alloc(0)],
  ];
  const bytes = Buffer.concat(frames.map(([h, p]) => encode(h, p)));
  for (let cut = 0; cut <= bytes.length; cut++) {
    const d = new Decoder();
    const got = [...d.push(bytes.subarray(0, cut)), ...d.push(bytes.subarray(cut))];
    assert.strictEqual(got.length, frames.length, `cut at ${cut}`);
    got.forEach((g, i) => {
      assert.deepStrictEqual(g.header, frames[i][0]);
      assert.deepStrictEqual(Buffer.from(g.payload), frames[i][1]);
    });
  }
  // One byte at a time.
  const d = new Decoder();
  let n = 0;
  for (const b of bytes) {
    n += d.push(Buffer.from([b])).length;
  }
  assert.strictEqual(n, frames.length);
}

// Hostile frames are errors.
{
  const big = Buffer.alloc(8);
  big.writeUInt32LE(MAX_HEADER + 1, 0);
  assert.throws(() => new Decoder().push(big));
  for (const header of ["not json", "[1,2]", "42", "null"]) {
    const h = Buffer.from(header);
    const prefix = Buffer.alloc(8);
    prefix.writeUInt32LE(h.length, 0);
    assert.throws(() => new Decoder().push(Buffer.concat([prefix, h])), header);
  }
}

// A session pairs answers with requests, in any order, and fails what's
// left when it closes.
(async () => {
  const sent = [];
  const s = new Session((bytes) => sent.push(bytes));
  const a = s.request("hello");
  const b = s.request("tree.create", { trace: 1 });
  const c = s.request("summary", { trace: 9 });
  const requests = sent.map((bytes) => new Decoder().push(bytes)[0].header);
  assert.deepStrictEqual(
    requests.map((r) => [r.id, r.method]),
    [
      [1, "hello"],
      [2, "tree.create"],
      [3, "summary"],
    ]
  );
  assert.deepStrictEqual(requests[1].params, { trace: 1 });
  s.receive(encode({ id: 2, result: { view: 1 } }));
  s.receive(Buffer.concat([encode({ id: 99, result: "nobody asked" }), encode({ id: 1, result: { version: "x" } })]));
  assert.deepStrictEqual(await b, { view: 1 });
  assert.deepStrictEqual(await a, { version: "x" });
  s.close("gone");
  await assert.rejects(c, /gone/);
  // An error answer rejects.
  const d = s.request("summary", { trace: 1 });
  s.receive(encode({ id: 4, error: "summary: no such trace" }));
  await assert.rejects(d, /no such trace/);
  console.log("protocol: ok");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
