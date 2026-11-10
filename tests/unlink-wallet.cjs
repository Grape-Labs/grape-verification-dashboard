const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ts = require('typescript');
const crypto = require('node:crypto');
const web3 = require('@solana/web3.js');
const registry = {
  PROGRAM_ID: new web3.PublicKey(Buffer.alloc(32, 8)),
  VerificationPlatform: { Discord: 0 },
  deriveSpacePda: () => [new web3.PublicKey(Buffer.alloc(32, 6))],
  deriveIdentityPda: () => [new web3.PublicKey(Buffer.alloc(32, 7))],
  deriveLinkPda: () => [new web3.PublicKey(Buffer.alloc(32, 9))],
  walletHash: () => Buffer.alloc(32, 4),
};
const key = n => new web3.PublicKey(Buffer.alloc(32, n));
const dao = key(1);
const [space] = registry.deriveSpacePda(dao);
const hash = Buffer.alloc(32, 3);
const [identity] = registry.deriveIdentityPda(space, 0, hash);
let accounts = [];
const source = ts.transpileModule(fs.readFileSync('app/api/attestor/unlink/route.ts', 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
}).outputText;
const output = { exports: {} };
new Function('require', 'module', 'exports', source)(name => name === '@solana/web3.js'
  ? { ...web3, Connection: class { async getAccountInfo() { return accounts.shift(); } } }
  : name === '@grapenpm/grape-verification-registry' ? registry : require(name), output, output.exports);
process.env.NEXT_PUBLIC_SOLANA_RPC = 'http://localhost:8899';
process.env.ATTESTOR_SECRET_KEY = 'test';
function request(overrides = {}) {
  return output.exports.POST(new Request('http://localhost/api/attestor/unlink', { method: 'POST',
    body: JSON.stringify({ payload: { daoId: dao.toBase58(), identity: identity.toBase58(), platform: 'discord',
      wallet: key(4).toBase58(), walletHashHex: Buffer.alloc(32, 5).toString('hex'), ts: Date.now(), ...overrides }, signatureBase64: 'test' }) }));
}
function records(identitySpace = space) {
  const spaceData = Buffer.alloc(143);
  const data = Buffer.alloc(128);
  crypto.createHash('sha256').update('account:GrapeVerificationIdentity').digest().copy(data, 0, 0, 8);
  identitySpace.toBuffer().copy(data, 9);
  hash.copy(data, 42);
  return [{ data: spaceData, owner: registry.PROGRAM_ID }, { data, owner: registry.PROGRAM_ID }];
}
test('rejects expired identity unlink consent before accessing chain', async () => {
  accounts = [];
  assert.equal((await request({ ts: Date.now() - 600000 })).status, 400);
});
test('rejects identity from a different community', async () => {
  accounts = records(key(9));
  const response = await request();
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /community/);
});
test('requires an existing signer link even without Discord cookies', async () => {
  accounts = [...records(), null];
  const response = await request();
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /not linked/);
});
