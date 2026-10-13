import { useEffect, useMemo, useRef, useState } from "react";
import "./NotificationCenter.css";

export type NotificationKind = "info" | "success" | "warning" | "people";

export type EmployeeNotification = {
  id: string;
  type: NotificationKind;
  title: string;
  description: string;
  details?: string;
  createdAt: number;
  read: boolean;
  actor?: { name: string; avatarSrc?: string };
};

export type NotificationDraft = Pick<EmployeeNotification, "type" | "title" | "description"> &
  Partial<Pick<EmployeeNotification, "details">>;

type NotificationCenterProps = {
  notifications: EmployeeNotification[];
  onChange: (notifications: EmployeeNotification[]) => void;
  showUnreadBadge?: boolean;
};

function relativeTime(timestamp: number): string {
  const elapsed = Math.max(0, Date.now() - timestamp);
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return days < 7 ? `${days}d ago` : new Date(timestamp).toLocaleDateString();
}

function StatusIcon({ type }: { type: NotificationKind }) {
  if (type === "success") {
    return <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="9"/><path d="m5.8 10.2 2.7 2.7 5.8-6"/></svg>;
  }
  if (type === "warning") {
    return <svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 1.8 19 18H1z"/><path d="M10 7v5m0 2.2v.1"/></svg>;
  }
  if (type === "people") {
    return <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="7" cy="6" r="3"/><path d="M1.5 17v-1.2A4.8 4.8 0 0 1 6.3 11h1.4a4.8 4.8 0 0 1 4.8 4.8V17m1.3-12.4a3 3 0 0 1 0 5.7m1.1 1a4.5 4.5 0 0 1 3.6 4.4V17"/></svg>;
  }
  return <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8"/><path d="M10 9v5m0-8h.01"/></svg>;
}

export function NotificationCenter({ notifications, onChange, showUnreadBadge = true }: NotificationCenterProps) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<"all" | "unread">("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const unreadCount = notifications.filter((notification) => !notification.read).length;
  const readCount = notifications.length - unreadCount;
  const visibleNotifications = useMemo(
    () => [...notifications]
      .filter((notification) => filter === "all" || !notification.read)
      .sort((a, b) => b.createdAt - a.createdAt),
    [filter, notifications],
  );

  function closePanel() {
    setOpen(false);
    triggerRef.current?.focus();
  }

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    const onPointerDown = (event: PointerEvent) => {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closePanel();
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  function updateOne(id: string, update: Partial<EmployeeNotification>) {
    onChange(notifications.map((notification) => notification.id === id ? { ...notification, ...update } : notification));
  }

  return (
    <div className="notification-center" ref={rootRef}>
      <button
        className="notification-trigger"
        type="button"
        ref={triggerRef}
        aria-label="Notifications"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls="employee-notification-panel"
        onClick={() => setOpen((value) => !value)}
      >
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 12a2 2 0 0 0 4 0"/></svg>
        {showUnreadBadge && unreadCount > 0 && <span className="notification-badge" aria-hidden="true">{unreadCount > 99 ? "99+" : unreadCount}</span>}
      </button>

      {open && (
        <section className="notification-panel" id="employee-notification-panel" role="dialog" aria-modal="false" aria-labelledby="notification-heading">
          <header className="notification-panel-header">
            <div>
              <div className="notification-title-row">
                <h2 id="notification-heading">Notifications</h2>
                {unreadCount > 0 && <span className="notification-count">{unreadCount}</span>}
              </div>
              <p>{unreadCount === 0 ? "You’re all caught up" : `${unreadCount} update${unreadCount === 1 ? "" : "s"} waiting for you`}</p>
            </div>
            <button className="notification-close" type="button" ref={closeRef} aria-label="Close notifications" onClick={closePanel}>
              <svg viewBox="0 0 20 20" aria-hidden="true"><path d="m5 5 10 10M15 5 5 15"/></svg>
            </button>
          </header>

          <div className="notification-toolbar">
            <div className="notification-filters" role="group" aria-label="Filter notifications">
              <button type="button" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All</button>
              <button type="button" aria-pressed={filter === "unread"} onClick={() => setFilter("unread")}>Unread{unreadCount > 0 ? ` ${unreadCount}` : ""}</button>
            </div>
            <button className="notification-text-action" type="button" disabled={unreadCount === 0} onClick={() => onChange(notifications.map((item) => ({ ...item, read: true })))}>Mark all read</button>
          </div>

          <div className="notification-list" aria-live="polite">
            {visibleNotifications.length === 0 ? (
              <div className="notification-empty">
                <span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 12a2 2 0 0 0 4 0"/></svg></span>
                <b>{filter === "unread" ? "No unread notifications" : "No notifications yet"}</b>
                <p>TrustGate activity from this session will appear here.</p>
              </div>
            ) : visibleNotifications.map((notification) => {
              const expanded = expandedId === notification.id;
              return (
                <article key={notification.id} className={`notification-row ${notification.read ? "is-read" : "is-unread"} type-${notification.type}`}>
                  <span className="notification-status-icon">
                    {notification.actor?.avatarSrc
                      ? <img src={notification.actor.avatarSrc} alt="" />
                      : <StatusIcon type={notification.type} />}
                  </span>
                  <div className="notification-row-copy">
                    <button className="notification-expand" type="button" aria-expanded={expanded} onClick={() => setExpandedId(expanded ? null : notification.id)}>
                      <span className="notification-row-title">{notification.title}</span>
                      <span className="notification-row-description">{notification.description}</span>
                      {expanded && notification.details && <span className="notification-row-details">{notification.details}</span>}
                    </button>
                    <div className="notification-row-meta">
                      <time dateTime={new Date(notification.createdAt).toISOString()}>{relativeTime(notification.createdAt)}</time>
                      <button type="button" onClick={() => updateOne(notification.id, { read: !notification.read })}>{notification.read ? "Mark unread" : "Mark read"}</button>
                      <button type="button" aria-label={`Dismiss ${notification.title}`} onClick={() => onChange(notifications.filter((item) => item.id !== notification.id))}>Dismiss</button>
                    </div>
                  </div>
                  {!notification.read && <span className="notification-unread-dot" aria-label="Unread" />}
                </article>
              );
            })}
          </div>

          <footer className="notification-panel-footer">
            <span>{readCount} read notification{readCount === 1 ? "" : "s"}</span>
            <button className="notification-text-action" type="button" disabled={readCount === 0} onClick={() => onChange(notifications.filter((item) => !item.read))}>Clear read</button>
          </footer>
        </section>
      )}
    </div>
  );
}
