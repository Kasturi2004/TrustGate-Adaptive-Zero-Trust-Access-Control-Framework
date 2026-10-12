import { AlertCircle, FileSearch, LoaderCircle } from "./Icons";

export function LoadingState({
  label = "Loading security data",
  fullPage = false,
}: {
  label?: string;
  fullPage?: boolean;
}) {
  return (
    <div className={fullPage ? "state-page" : undefined}>
      <div className="state-card" role="status" aria-live="polite" aria-busy="true">
        <LoaderCircle className="spin" size={18} />
        {label}
      </div>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="state-card state-error" role="alert">
      <AlertCircle size={18} />
      <span>{message}</span>
      {onRetry && (
        <button className="text-button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  detail,
}: {
  title: string;
  detail: string;
}) {
  return (
    <div className="empty-state">
      <span className="empty-mark" aria-hidden="true">
        <FileSearch size={22} />
      </span>
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  );
}
