import type { ReactNode } from "react";
import { Link } from "react-router-dom";

type AuthPageLayoutProps = {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  footer: ReactNode;
};

export function AuthPageLayout({
  eyebrow,
  title,
  description,
  children,
  footer,
}: AuthPageLayoutProps) {
  return (
    <main className="auth-layout">
      <section className="auth-story" aria-label="About TrustGate">
        <Link className="auth-brand" to="/" aria-label="TrustGate home">
          <span className="brand-mark" aria-hidden="true">
            TG
          </span>
          <span>
            <strong>TrustGate</strong>
            <small>ADAPTIVE ACCESS CONTROL</small>
          </span>
        </Link>
        <div className="auth-story-copy">
          <span className="auth-eyebrow">Zero Trust access control</span>
          <h1>
            Every request.
            <br />
            Explicitly verified.
          </h1>
          <p>TrustGate evaluates each access request before a protected resource is approved.</p>
          <div className="auth-flow" aria-label="Authenticate, evaluate, authorize">
            <span>Authenticate</span>
            <i aria-hidden="true">›</i>
            <span>Evaluate context</span>
            <i aria-hidden="true">›</i>
            <span>Authorize</span>
          </div>
        </div>
        <p className="auth-story-foot">
          A signed-in session does not automatically authorize access.
        </p>
      </section>
      <section className="auth-form-region">
        <div className="auth-form-card">
          <span className="auth-eyebrow">{eyebrow}</span>
          <h2>{title}</h2>
          <p className="auth-form-intro">{description}</p>
          {children}
          {footer}
        </div>
      </section>
    </main>
  );
}
