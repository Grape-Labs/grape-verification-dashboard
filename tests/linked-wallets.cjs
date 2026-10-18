const { test } = require('node:test');
const assert = require('node:assert/strict');
const ts = require('typescript');
const fs = require('node:fs');
const { PublicKey } = require('@solana/web3.js');
const PROGRAM_ID = new PublicKey(Buffer.alloc(32, 8));
const source = ts.transpileModule(fs.readFileSync('lib/linked-wallets.ts', 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
const output = { exports: {} };
new Function('require', 'module', 'exports', source)(name => name === '@grapenpm/grape-verification-registry' ? { PROGRAM_ID } : require(name), output, output.exports);
const { loadLinkedWallets } = output.exports;
const key = n => new PublicKey(Buffer.alloc(32, n));
function link(identity, wallet, time) {
  const data = Buffer.alloc(82);
  identity.toBuffer().copy(data, 9);
  wallet.toBuffer().copy(data, 41);
  data.writeBigInt64LE(BigInt(time), 73);
  return { pubkey: key(9), account: { owner: PROGRAM_ID, data } };
}
test('loads all identities, deduplicates wallets, marks connected wallet and preserves earliest link', async () => {
  let requests = 0;
  const connection = { getProgramAccounts: async (_, { filters }) => {
    requests++;
    const identity = new PublicKey(filters[1].memcmp.bytes);
    return [link(identity, key(3), 10), link(identity, key(4), identity.equals(key(1)) ? 20 : 5)];
  } };
  const result = await loadLinkedWallets(connection, [key(1), key(2), key(1)], key(3).toBytes());
  assert.equal(requests, 2);
  assert.equal(result.length, 2);
  assert.equal(result[0].isCurrentWallet, true);
  assert.equal(result[1].isCurrentWallet, false);
  assert.equal(result[1].linkedAt, 5);
});
test('empty identities need no RPC request', async () => {
  assert.deepEqual(await loadLinkedWallets({ getProgramAccounts: () => { throw Error('unexpected'); } }, [], key(3).toBytes()), []);
});
test('RPC errors propagate instead of reporting zero wallets', async () => {
  await assert.rejects(loadLinkedWallets({ getProgramAccounts: async () => { throw Error('offline'); } }, [key(1)], key(3).toBytes()), /offline/);
});
