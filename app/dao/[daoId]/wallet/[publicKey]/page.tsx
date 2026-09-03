import type { Metadata } from "next";
import Link from "next/link";
import { getPublicVerification } from "@/lib/public-verification";
import ShareActions from "./ShareActions";
import styles from "./page.module.css";

export const dynamic = "force-dynamic";

type RouteProps = {
  params: Promise<{ daoId: string; publicKey: string }>;
};

function short(value: string) {
  return value.length > 16 ? `${value.slice(0, 7)}…${value.slice(-7)}` : value;
}

function date(timestamp: number) {
  return timestamp ? new Date(timestamp * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  }) : "—";
}

export async function generateMetadata({ params }: RouteProps): Promise<Metadata> {
  const { daoId, publicKey } = await params;
  const result = await getPublicVerification(daoId, publicKey);
  const title = result.verified
    ? `Verified for ${result.communityName}`
    : `Verification status for ${result.communityName}`;
  const description = result.verified
    ? `${short(result.wallet)} has an active on-chain verification for ${result.communityName}.`
    : `${short(result.wallet)} does not have an active on-chain verification for ${result.communityName}.`;

  return {
    title: `${title} | Grape Verification`,
    description,
    robots: { index: false, follow: false },
    openGraph: { title, description, type: "website", siteName: "Grape Verification" },
    twitter: { card: "summary", title, description },
  };
}

export default async function PublicVerificationPage({ params }: RouteProps) {
  const { daoId, publicKey } = await params;
  const result = await getPublicVerification(daoId, publicKey);
  const status = result.error
    ? "unavailable"
    : result.verified
    ? "verified"
    : "notVerified";

  return (
    <main className={styles.page}>
      <div className={styles.shell}>
        <header className={styles.header}>
          <Link href="/" className={styles.brand}>
            {/* A tiny local brand asset; avoiding image optimization keeps this status route lean. */}
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/grape_logo_square.png" alt="" />
            <span>Grape Verification</span>
          </Link>
          <span className={styles.network}>Solana • On-chain status</span>
        </header>

        <section className={`${styles.card} ${styles[status]}`}>
          <div className={styles.statusIcon} aria-hidden="true">
            {status === "verified" ? "✓" : status === "unavailable" ? "!" : "—"}
          </div>
          <p className={styles.eyebrow}>Public verification</p>
          <h1>
            {status === "verified"
              ? "Wallet verified"
              : status === "unavailable"
              ? "Status unavailable"
              : "Not currently verified"}
          </h1>
          <p className={styles.summary}>
            {result.error || (result.verified
              ? `This wallet has an active identity verification for ${result.communityName}.`
              : `No active identity verification was found for this wallet in ${result.communityName}.`)}
          </p>

          <div className={styles.addressBlock}>
            <span>Wallet address</span>
            <code>{result.wallet}</code>
          </div>

          <ShareActions wallet={result.wallet} />

          <dl className={styles.details}>
            <div>
              <dt>Community</dt>
              <dd>{result.communityName}</dd>
            </div>
            <div>
              <dt>DAO address</dt>
              <dd title={result.daoId}>{short(result.daoId)}</dd>
            </div>
            <div>
              <dt>Verification methods</dt>
              <dd>{result.methods.length ? result.methods.map((m) => m.platform).join(", ") : "None active"}</dd>
            </div>
            <div>
              <dt>Checked</dt>
              <dd>{new Date(result.checkedAt * 1000).toLocaleString("en-US", { timeZone: "UTC", timeZoneName: "short" })}</dd>
            </div>
          </dl>

          {result.methods.length > 0 && (
            <div className={styles.methods}>
              {result.methods.map((method) => (
                <div key={method.platform}>
                  <span className={styles.methodCheck}>✓</span>
                  <span><strong>{method.platform}</strong><small>Verified {date(method.verifiedAt)}</small></span>
                </div>
              ))}
            </div>
          )}

          {result.spaceFrozen && (
            <p className={styles.notice}>This community is currently paused. Existing verification records remain visible.</p>
          )}
        </section>

        <p className={styles.privacy}>
          This page confirms a wallet’s community verification status. It does not reveal linked email addresses, usernames, or other wallets.
        </p>
        <Link className={styles.back} href={`/?dao=${encodeURIComponent(result.daoId)}`}>
          Open verification dashboard →
        </Link>
      </div>
    </main>
  );
}
