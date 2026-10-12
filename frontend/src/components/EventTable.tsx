import { Link } from "react-router-dom";
import type { SecurityEvent } from "../types/api";
import { formatAuditTimestamp, investigationPath } from "../pages/eventView";
import { EmptyState } from "./States";
import { StatusBadge } from "./StatusBadge";

function compactIdentifier(value: string, visibleStart = 8, visibleEnd = 6) {
  if (value.length <= visibleStart + visibleEnd + 1) return value;
  return `${value.slice(0, visibleStart)}...${value.slice(-visibleEnd)}`;
}

function MissingValue() {
  return <span className="table-empty" aria-label="Not available" title="Not available">{"\u2014"}</span>;
}

function eventLabel(value: string) {
  return value.toLowerCase().split("_").map((word, index) =>
    word === "mfa" ? "MFA" : index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word,
  ).join(" ");
}

export function EventTable({
  events,
  emptyTitle = "No security events match these filters",
  emptyDetail = "Try a wider date range or clear one or more filters.",
}: {
  events: SecurityEvent[];
  emptyTitle?: string;
  emptyDetail?: string;
}) {
  if (events.length === 0)
    return <EmptyState title={emptyTitle} detail={emptyDetail} />;

  return (
    <div className="table-scroll" role="region" aria-label="Recent security events" tabIndex={0}>
      <table className="audit-table">
        <caption className="sr-only">Recent security events</caption>
        <colgroup>
          <col className="audit-col-event" />
          <col className="audit-col-user" />
          <col className="audit-col-time" />
          <col className="audit-col-device" />
          <col className="audit-col-score" />
          <col className="audit-col-decision" />
          <col className="audit-col-risk" />
          <col className="audit-col-action" />
        </colgroup>
        <thead>
          <tr>
            <th scope="col">Event</th>
            <th scope="col">User ID</th>
            <th scope="col">Time (local)</th>
            <th scope="col">Device</th>
            <th scope="col">Trust score</th>
            <th scope="col">Decision</th>
            <th scope="col">Risk</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>
                <span className="audit-event-name">{eventLabel(event.event_type)}</span>
                <code className="mono audit-id" title={event.id} aria-label={`Event ID: ${event.id}`}>
                  {compactIdentifier(event.id)}
                </code>
              </td>
              <td className="audit-user-cell" title={event.user_id ?? "Not available"} aria-label={event.user_id ? `User ID: ${event.user_id}` : "User ID not available"}>
                {event.user_id ? <code className="mono audit-secondary-id">{compactIdentifier(event.user_id)}</code> : <MissingValue />}
              </td>
              <td className="muted" title={event.created_at}>
                <time dateTime={event.created_at}>{formatAuditTimestamp(event.created_at)}</time>
              </td>
              <td className="mono" title={event.device ?? undefined} aria-label={event.device ?? "Device ID not available"}>
                {event.device ? compactIdentifier(event.device) : <MissingValue />}
              </td>
              <td className="score-cell">
                {event.trust_score == null ? <MissingValue /> : event.trust_score}
              </td>
              <td>
                {event.decision ? <StatusBadge value={event.decision} variant="decision" /> : <MissingValue />}
              </td>
              <td>
                {event.risk_category ? <StatusBadge value={event.risk_category} variant="risk" /> : <MissingValue />}
              </td>
              <td>
                <Link
                  className="row-link"
                  to={investigationPath(event.id)}
                  aria-label={`Investigate event ${event.id}`}
                >
                  Investigate
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
