/**
 * Honest header count for a list page. Renders the true total from meta.total,
 * and — when the response was capped and rows were dropped — says so explicitly
 * rather than letting the visible-row count masquerade as the whole inventory.
 */
export function RowCount({
  shown,
  total,
  noun,
}: {
  shown: number;
  total: number | null;
  noun: string;
}) {
  const n = total ?? shown;
  const truncated = total != null && shown < total;
  return (
    <span className="page__count">
      {n} {noun}
      {truncated && <span className="page__count-more"> · showing first {shown}</span>}
    </span>
  );
}
