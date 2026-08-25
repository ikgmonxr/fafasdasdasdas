const assert = require("assert");
const { obfuscate } = require("./obfuscate");

function unpackVm(output) {
  const keys = [...output.matchAll(/K=\{(\{(?:0x[0-9a-f]+(?:,0x[0-9a-f]+)*)?\}(?:,\{(?:0x[0-9a-f]+(?:,0x[0-9a-f]+)*)?\})*)\}/gi)][0];
  const data = /D=\{((?:0x[0-9a-f]+(?:,0x[0-9a-f]+)*)?)\}/i.exec(output);
  assert(keys && data, "VM payload was not emitted");
  const keySets = [...keys[1].matchAll(/\{([^}]*)\}/g)].map((m) => m[1].split(",").map((v) => Number(v)));
  let bytes = data[1] ? data[1].split(",").map((v) => Number(v)) : [];
  for (let layer = keySets.length - 1; layer >= 0; layer--) {
    const key = keySets[layer];
    const salt = layer + 3;
    bytes = bytes.map((value, index) => value ^ key[index % key.length] ^ ((index * salt) & 0xff));
  }
  return Buffer.from(bytes).toString("utf8");
}

const input = [
  "local x = 300",
  "local message = 'hello'",
  "if x >= 16 then print(message .. x) end"
].join("\n");
const result = obfuscate(input, { antiTamper: false });
const plain = unpackVm(result.code);

assert.match(plain, /local x=/, "keywords and identifiers must remain separated");
assert.doesNotMatch(plain, /localx/, "token joining changed the program");
assert.match(plain, /0x[0-9a-f]+\+0x[0-9a-f]+/i, "integer obfuscation was not generated");
assert.strictEqual(result.stats.numbersMutated, 2);
console.log("obfuscator regression checks passed");
