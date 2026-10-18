const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ts = require('typescript');
const { PublicKey } = require('@solana/web3.js');
const key = (n) => new PublicKey(Buffer.alloc(32, n));
const program = key(1), space = key(2), wallet = key(3), other = key(4);
const identityKeys = [key(5), key(6), key(7)];
function fixture({ fail = false, expired = false, revoked = false, foreign = false } = {}) {
  const spaceData = Buffer.alloc(139);
  function identity(index) {
    const data = Buffer.alloc(123);
    (foreign ? key(9) : space).toBuffer().copy(data, 9);
    data[41] = index;
    data[74] = revoked ? 0 : 1;
    data.writeBigInt64LE(expired ? 1n : 0n, 83);
    return { owner: program, data };
  }
  function link(id, target) {
    const data = Buffer.alloc(73);
    id.toBuffer().copy(data, 9);
    target.toBuffer().copy(data, 41);
    return { account: { owner: program, data } };
  }
  class Connection {
    async getAccountInfo() { return { data: spaceData }; }
    async getMultipleAccountsInfo() { return identityKeys.map((_, i) => identity(i)); }
    async getProgramAccounts(_, options) {
      if (options.filters[1].memcmp.offset === 41) return identityKeys.map(id => link(id, wallet));
      if (fail) throw Error('RPC unavailable');
      const id = new PublicKey(options.filters[1].memcmp.bytes);
      return [link(id, wallet), link(id, other)];
    }
  }
  const source = ts.transpileModule(fs.readFileSync('lib/public-verification.ts', 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const module = { exports: {} };
  const mockRequire = name => {
    if (name === 'react') return { cache: fn => fn };
    if (name === '@solana/web3.js') return { Connection, PublicKey };
    if (name === '@grapenpm/grape-verification-registry') return {
      PROGRAM_ID: program, deriveSpacePda: () => [space],
      fetchSpaceMetadataByDaoId: async () => null, walletHash: (_, value) => value.toBuffer(),
    };
    return require(name);
  };
  new Function('require', 'module', 'exports', source)(mockRequire, module, module.exports);
  return compare => module.exports.getPublicVerification(key(8).toBase58(), wallet.toBase58(), compare);
}
process.env.NEXT_PUBLIC_SOLANA_RPC = 'http://localhost:8899';
test('deduplicates wallets across methods and confirms a supplied shared wallet', async () => {
  const result = await fixture()(other.toBase58());
  assert.equal(result.methods.length, 3);
  assert.equal(result.linkedWalletCount, 1);
  assert.equal(result.comparison, 'linked');
  assert.equal(JSON.stringify(result).includes(other.toBase58()), false);
});
test('unknown wallet, same wallet, and invalid input are distinct', async () => {
  const check = fixture();
  assert.equal((await check(key(10).toBase58())).comparison, 'notLinked');
  assert.equal((await check(wallet.toBase58())).comparison, 'sameWallet');
  assert.equal((await check('invalid')).comparison, 'invalid');
});
test('expired, revoked, and other-DAO identities cannot establish a connection', async () => {
  for (const options of [{ expired: true }, { revoked: true }, { foreign: true }]) {
    const result = await fixture(options)(other.toBase58());
    assert.equal(result.verified, false);
    assert.equal(result.linkedWalletCount, 0);
    assert.equal(result.comparison, 'notLinked');
  }
});
test('failed sibling lookup preserves verification and reports unknown linkage', async () => {
  const result = await fixture({ fail: true })(other.toBase58());
  assert.equal(result.verified, true);
  assert.equal(result.linkedWalletCount, null);
  assert.equal(result.comparison, 'unavailable');
  assert.ok(result.linkageError);
});
