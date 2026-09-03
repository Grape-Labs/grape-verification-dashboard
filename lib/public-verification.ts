import { cache } from "react";
import { Buffer } from "buffer";
import { Connection, PublicKey } from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";
import {
  PROGRAM_ID,
  deriveSpacePda,
  fetchSpaceMetadataByDaoId,
  walletHash,
} from "@grapenpm/grape-verification-registry";

export type PublicVerificationMethod = {
  platform: "Discord" | "Telegram" | "X" | "Email";
  verifiedAt: number;
  expiresAt: number;
};

export type PublicVerificationResult = {
  valid: boolean;
  error: string | null;
  daoId: string;
  wallet: string;
  communityName: string;
  spaceExists: boolean;
  spaceFrozen: boolean;
  verified: boolean;
  methods: PublicVerificationMethod[];
  checkedAt: number;
};

const LINK_DISC = sha256(utf8ToBytes("account:GrapeVerificationLink")).slice(0, 8);
const PLATFORM_NAMES = ["Discord", "Telegram", "X", "Email"] as const;

function readI64(data: Uint8Array, offset: number) {
  return Number(new DataView(data.buffer, data.byteOffset, data.byteLength).getBigInt64(offset, true));
}

function communityNameFromMetadata(data: Uint8Array | undefined, fallback: string) {
  if (!data) return fallback;
  const text = new TextDecoder().decode(data).replace(/\u0000+/g, " ");
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start >= 0 && end > start) {
    try {
      const value = JSON.parse(text.slice(start, end + 1)) as { name?: unknown };
      if (typeof value.name === "string" && value.name.trim()) return value.name.trim();
    } catch {
      // Older metadata layouts may contain a plain string.
    }
  }
  const candidates = text.match(/[A-Za-z0-9][A-Za-z0-9 _.-]{2,80}/g);
  return candidates?.at(-1)?.trim() || fallback;
}

export const getPublicVerification = cache(async (
  daoValue: string,
  walletValue: string
): Promise<PublicVerificationResult> => {
  const checkedAt = Math.floor(Date.now() / 1000);
  const base = {
    daoId: daoValue,
    wallet: walletValue,
    communityName: "Community",
    spaceExists: false,
    spaceFrozen: false,
    verified: false,
    methods: [] as PublicVerificationMethod[],
    checkedAt,
  };

  let dao: PublicKey;
  let wallet: PublicKey;
  try {
    dao = new PublicKey(daoValue);
    wallet = new PublicKey(walletValue);
  } catch {
    return { ...base, valid: false, error: "The DAO or wallet address is invalid." };
  }

  const rpc = process.env.NEXT_PUBLIC_SOLANA_RPC || process.env.REACT_APP_RPC_ENDPOINT;
  if (!rpc) {
    return { ...base, valid: true, error: "Verification service is not configured." };
  }

  try {
    const connection = new Connection(rpc, "confirmed");
    const [space] = deriveSpacePda(dao);
    const [spaceAccount, metadataAccount] = await Promise.all([
      connection.getAccountInfo(space),
      fetchSpaceMetadataByDaoId(connection, dao).catch(() => null),
    ]);

    const communityName = communityNameFromMetadata(metadataAccount?.data, "Community");
    if (!spaceAccount || spaceAccount.data.length < 139) {
      return {
        ...base,
        valid: true,
        daoId: dao.toBase58(),
        wallet: wallet.toBase58(),
        communityName,
        error: null,
      };
    }

    const spaceFrozen = spaceAccount.data[105] === 1;
    const salt = spaceAccount.data.slice(107, 139);
    const targetWalletHash = walletHash(salt, wallet);
    const links = await connection.getProgramAccounts(PROGRAM_ID, {
      filters: [
        {
          memcmp: {
            offset: 0,
            bytes: Buffer.from(LINK_DISC).toString("base64"),
            encoding: "base64",
          },
        },
        {
          memcmp: {
            offset: 41,
            bytes: Buffer.from(targetWalletHash).toString("base64"),
            encoding: "base64",
          },
        },
      ],
    });

    const identityKeys = links
      .filter(({ account }) => account.data.length >= 73)
      .map(({ account }) => new PublicKey(account.data.slice(9, 41)));
    const identities = identityKeys.length
      ? await connection.getMultipleAccountsInfo(identityKeys)
      : [];

    const methods = identities.flatMap((account): PublicVerificationMethod[] => {
      if (!account || !account.owner.equals(PROGRAM_ID) || account.data.length < 123) return [];
      const identitySpace = new PublicKey(account.data.slice(9, 41));
      if (!identitySpace.equals(space)) return [];
      const platform = account.data[41];
      const verified = account.data[74] === 1;
      const verifiedAt = readI64(account.data, 75);
      const expiresAt = readI64(account.data, 83);
      if (!verified || (expiresAt > 0 && expiresAt < checkedAt) || !PLATFORM_NAMES[platform]) return [];
      return [{ platform: PLATFORM_NAMES[platform], verifiedAt, expiresAt }];
    });

    const uniqueMethods = Array.from(
      new Map(methods.map((method) => [method.platform, method])).values()
    );

    return {
      valid: true,
      error: null,
      daoId: dao.toBase58(),
      wallet: wallet.toBase58(),
      communityName,
      spaceExists: true,
      spaceFrozen,
      verified: uniqueMethods.length > 0,
      methods: uniqueMethods,
      checkedAt,
    };
  } catch {
    return {
      ...base,
      valid: true,
      daoId: dao.toBase58(),
      wallet: wallet.toBase58(),
      error: "The Solana verification record could not be checked right now.",
    };
  }
});

