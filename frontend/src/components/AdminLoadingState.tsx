export function AdminLoadingState({ label }: { label: string }) {
  return (
    <section className="panel admin-state" role="status" aria-live="polite">
      <p>{label}</p>
      <div className="admin-skeleton" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
    </section>
  );
}
