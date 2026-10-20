const { test } = require('node:test');
const assert = require('node:assert/strict');
const ts = require('typescript');
const fs = require('node:fs');
const { PublicKey } = require('@solana/web3.js');
const key = n => new PublicKey(Buffer.alloc(32, n));
const PROGRAM_ID = key(8);
const output = { exports: {} };
const source = ts.transpileModule(fs.readFileSync('lib/community-stats.ts', 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
new Function('require', 'module', 'exports', source)(name => name === '@grapenpm/grape-verification-registry' ? { PROGRAM_ID } : require(name), output, output.exports);
const { loadCommunityStats } = output.exports;
function identity(id, verified, expires) {
  const data = Buffer.alloc(128);
  key(1).toBuffer().copy(data, 9);
  data[74] = Number(verified);
  data.writeBigInt64LE(BigInt(expires), 83);
  return { pubkey: key(id), account: { owner: PROGRAM_ID, data } };
}
function link(id, wallet) {
  const data = Buffer.alloc(88);
  key(id).toBuffer().copy(data, 9);
  key(wallet).toBuffer().copy(data, 41);
  return { pubkey: key(9), account: { owner: PROGRAM_ID, data } };
}
test('counts distinct community wallets, excluding revoked and expired verification and other communities', async () => {
  const connection = { getProgramAccounts: async (_, { filters }) => filters.length === 2
    ? [identity(2, true, 0), identity(3, true, 0), identity(4, false, 0), identity(5, true, 1)]
    : [link(2, 10), link(3, 10), link(4, 11), link(5, 12), link(6, 13)] };
  const result = await loadCommunityStats(connection, key(1));
  assert.equal(result.linked, 3);
  assert.equal(result.verified, 1);
  assert.equal(result.identities, 4);
});
test('empty community returns zero counts', async () => {
  const result = await loadCommunityStats({ getProgramAccounts: async () => [] }, key(1));
  assert.equal(result.linked, 0);
  assert.equal(result.verified, 0);
});
test('RPC failure propagates instead of becoming a zero count', async () => {
  await assert.rejects(loadCommunityStats({ getProgramAccounts: async () => { throw Error('offline'); } }, key(1)), /offline/);
});
test('breaks down methods, expiration, and identities without wallets', async () => {
  const now = Math.floor(Date.now() / 1000);
  const discord = identity(2, true, now + 3600);
  const email = identity(3, true, 0);
  email.account.data[41] = 3;
  const expired = identity(4, true, 1);
  const revoked = identity(5, false, 1);
  const unlinked = identity(6, true, now + 8 * 86400);
  const result = await loadCommunityStats({ getProgramAccounts: async (_, { filters }) => filters.length === 2
    ? [discord, email, expired, revoked, unlinked]
    : [link(2, 10), link(3, 10), link(4, 11), link(5, 12)] }, key(1));
  assert.equal(result.activeIdentities, 3);
  assert.equal(result.expired, 1);
  assert.equal(result.revoked, 1);
  assert.equal(result.expiringSoon, 1);
  assert.equal(result.unverifiedWallets, 2);
  assert.equal(result.identitiesWithoutWallets, 1);
  assert.equal(result.methods.find(m => m.platform === 'Discord').wallets, 1);
  assert.equal(result.methods.find(m => m.platform === 'Email').wallets, 1);
  assert.equal(result.verified, 1);
});
