type PlaceholderPageProps = {
  title: string;
};

export function PlaceholderPage({ title }: PlaceholderPageProps) {
  return (
    <section className="panel">
      <h1>{title}</h1>
      <p className="lede">This route is a placeholder. It is not implemented in Phase 1.</p>
    </section>
  );
}
