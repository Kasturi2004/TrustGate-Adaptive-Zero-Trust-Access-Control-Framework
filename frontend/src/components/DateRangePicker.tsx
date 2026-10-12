import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { CalendarDays, ChevronDown, ChevronLeft, ChevronRight } from "./Icons";

export type DateRangeValue = { from: string; to: string };
type DateRangePickerProps = {
  value: DateRangeValue;
  appliedValue: DateRangeValue;
  onChange: (range: DateRangeValue) => void;
  openRequest?: number;
};

const pad = (number: number) => String(number).padStart(2, "0");
function localDateKey(date: Date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}
function dateFromKey(key: string) {
  const [year, month, day] = key.split("-").map(Number);
  return new Date(year!, month! - 1, day!, 12);
}
function firstOfMonth(date: Date) { return new Date(date.getFullYear(), date.getMonth(), 1, 12); }
function dateRange(from: Date, to: Date): DateRangeValue {
  return { from: `${localDateKey(from)}T00:00`, to: `${localDateKey(to)}T23:59:59.999` };
}
function keysFromRange(value: DateRangeValue) {
  return { from: value.from.slice(0, 10), to: value.to.slice(0, 10) };
}
function formatRange(from: string, to: string, locale: string) {
  if (!from && !to) return "Choose date range";
  const formatter = new Intl.DateTimeFormat(locale, { month: "short", day: "numeric", year: "numeric" });
  if (from && to) return `${formatter.format(dateFromKey(from))} – ${formatter.format(dateFromKey(to))}`;
  return from ? `From ${formatter.format(dateFromKey(from))}` : `Through ${formatter.format(dateFromKey(to))}`;
}
function countDays(from: string, to: string) {
  if (!from || !to) return 0;
  const start = new Date(`${from}T00:00:00Z`).getTime();
  const end = new Date(`${to}T00:00:00Z`).getTime();
  return Math.floor((end - start) / 86_400_000) + 1;
}

export function DateRangePicker({ value, appliedValue, onChange, openRequest = 0 }: DateRangePickerProps) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const dayRefs = useRef(new Map<string, HTMLButtonElement>());
  const [open, setOpen] = useState(false);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [activePreset, setActivePreset] = useState("");
  const [visibleMonth, setVisibleMonth] = useState(() => firstOfMonth(new Date()));
  const [focusKey, setFocusKey] = useState(localDateKey(new Date()));
  const [position, setPosition] = useState({ top: -1000, left: 12, width: 760 });
  const locale = typeof navigator === "undefined" ? "en" : navigator.language;
  const firstDay = useMemo(() => {
    try {
      const info = new Intl.Locale(locale) as Intl.Locale & { getWeekInfo?: () => { firstDay: number } };
      return (info.getWeekInfo?.().firstDay ?? 7) % 7;
    } catch { return 0; }
  }, [locale]);
  const weekdays = useMemo(() => {
    const formatter = new Intl.DateTimeFormat(locale, { weekday: "short", timeZone: "UTC" });
    return Array.from({ length: 7 }, (_, index) => formatter.format(new Date(Date.UTC(2023, 0, 1 + ((firstDay + index) % 7)))));
  }, [locale, firstDay]);
  const months = [visibleMonth, new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() + 1, 1, 12)];
  const rangeKeys = keysFromRange(value);
  const monthName = (month: Date) => new Intl.DateTimeFormat(locale, { month: "long", year: "numeric" }).format(month);

  function openPicker() {
    const current = keysFromRange(value);
    const first = current.from || localDateKey(new Date());
    setStart(current.from);
    setEnd(current.to);
    setActivePreset("");
    const month = firstOfMonth(dateFromKey(first));
    setVisibleMonth(month);
    setFocusKey(first);
    setOpen(true);
  }

  useEffect(() => {
    if (openRequest > 0) openPicker();
  // openRequest is an event counter; read the current controlled value when invoked.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openRequest]);

  useLayoutEffect(() => {
    if (!open || !triggerRef.current || !popoverRef.current) return;
    const update = () => {
      const anchor = triggerRef.current?.getBoundingClientRect();
      const popup = popoverRef.current?.getBoundingClientRect();
      if (!anchor || !popup) return;
      const margin = 12;
      const content = document.querySelector(".page-content")?.getBoundingClientRect();
      const leftBound = content ? Math.max(margin, content.left + margin) : margin;
      const rightBound = content ? Math.min(window.innerWidth - margin, content.right - margin) : window.innerWidth - margin;
      const width = Math.max(0, Math.min(760, window.innerWidth - margin * 2, rightBound - leftBound));
      const left = Math.max(leftBound, Math.min(anchor.left, rightBound - width));
      const below = anchor.bottom + 8;
      const above = anchor.top - popup.height - 8;
      const top = below + popup.height <= window.innerHeight - margin
        ? below
        : above >= margin ? above : Math.max(margin, Math.min(below, window.innerHeight - popup.height - margin));
      setPosition({ top, left, width });
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open, visibleMonth]);

  useEffect(() => {
    if (!open) return;
    const frame = requestAnimationFrame(() => dayRefs.current.get(focusKey)?.focus());
    const outside = (event: PointerEvent) => {
      if (!popoverRef.current?.contains(event.target as Node) && !triggerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { cancel(); return; }
      const delta = event.key === "ArrowLeft" ? -1 : event.key === "ArrowRight" ? 1 : event.key === "ArrowUp" ? -7 : event.key === "ArrowDown" ? 7 : 0;
      if (delta) {
        event.preventDefault();
        const next = dateFromKey(focusKey);
        next.setDate(next.getDate() + delta);
        moveTo(next);
      } else if (event.key === "Home" || event.key === "End") {
        event.preventDefault();
        const next = dateFromKey(focusKey);
        const offset = (next.getDay() - firstDay + 7) % 7;
        next.setDate(next.getDate() + (event.key === "Home" ? -offset : 6 - offset));
        moveTo(next);
      } else if (event.key === "PageUp" || event.key === "PageDown") {
        event.preventDefault();
        const next = dateFromKey(focusKey);
        const day = next.getDate();
        const direction = event.key === "PageUp" ? -1 : 1;
        next.setDate(1);
        if (event.shiftKey) next.setFullYear(next.getFullYear() + direction);
        else next.setMonth(next.getMonth() + direction);
        next.setDate(Math.min(day, new Date(next.getFullYear(), next.getMonth() + 1, 0).getDate()));
        moveTo(next);
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", keydown);
    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", keydown);
    };
  // Helpers are stable for the lifetime of the open interaction.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, focusKey, firstDay]);

  useLayoutEffect(() => { if (open) dayRefs.current.get(focusKey)?.focus(); }, [open, focusKey, visibleMonth]);

  function moveTo(date: Date) {
    const key = localDateKey(date);
    setFocusKey(key);
    setVisibleMonth(firstOfMonth(date));
  }
  function chooseDay(key: string) {
    setActivePreset("");
    if (!start || (start && end)) { setStart(key); setEnd(""); }
    else if (key < start) { setStart(key); setEnd(""); }
    else setEnd(key);
  }
  function setPreset(name: string) {
    const today = new Date();
    const todayKey = localDateKey(today);
    const from = new Date(today.getFullYear(), today.getMonth(), today.getDate(), 12);
    const to = new Date(from);
    switch (name) {
      case "Yesterday": from.setDate(from.getDate() - 1); to.setDate(to.getDate() - 1); break;
      case "Last 7 days": from.setDate(from.getDate() - 6); break;
      case "Last 30 days": from.setDate(from.getDate() - 29); break;
      case "This month": from.setDate(1); break;
      case "Last month": from.setMonth(from.getMonth() - 1, 1); to.setDate(0); break;
      case "This quarter": from.setMonth(Math.floor(from.getMonth() / 3) * 3, 1); break;
      case "Year to date": from.setMonth(0, 1); break;
      default: break;
    }
    const fromKey = localDateKey(from);
    const toKey = name === "Yesterday" ? localDateKey(to) : todayKey;
    setStart(fromKey);
    setEnd(toKey);
    setVisibleMonth(firstOfMonth(from));
    setFocusKey(fromKey);
    setActivePreset(name);
  }
  function apply() {
    if (start && end) onChange(dateRange(dateFromKey(start), dateFromKey(end)));
    else if (!start && !end) onChange({ from: "", to: "" });
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  }
  function cancel() {
    onChange(appliedValue);
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  }
  const selectedDays = countDays(start, end);

  return (
    <>
      <button ref={triggerRef} type="button" className="audit-range-trigger" aria-haspopup="dialog" aria-expanded={open} aria-label={`Date range: ${formatRange(rangeKeys.from, rangeKeys.to, locale)}`} onClick={() => open ? cancel() : openPicker()}>
        <CalendarDays size={16} /><span>{formatRange(rangeKeys.from, rangeKeys.to, locale)}</span><ChevronDown size={14} />
      </button>
      {open && createPortal(
        <div ref={popoverRef} className={`audit-range-popover${position.width < 640 ? " is-compact" : ""}`} role="dialog" aria-label="Choose audit log date range" style={position}>
          <div className="audit-range-layout">
            <aside className="audit-range-presets" aria-label="Date range presets">
              <p>Presets</p>
              {["Today", "Yesterday", "Last 7 days", "Last 30 days", "This month", "Last month", "This quarter", "Year to date"].map((preset) => <button key={preset} type="button" className={activePreset === preset ? "active" : ""} onClick={() => setPreset(preset)}>{preset}</button>)}
            </aside>
            <section className="audit-range-calendar-area">
              <div className="audit-range-months">
                {months.map((month, monthIndex) => {
                  const monthStartDay = new Date(month.getFullYear(), month.getMonth(), 1, 12);
                  const offset = (monthStartDay.getDay() - firstDay + 7) % 7;
                  const numberOfDays = new Date(month.getFullYear(), month.getMonth() + 1, 0).getDate();
                  return <div className="audit-range-month" key={month.toISOString()}>
                    <header>
                      {monthIndex === 0 && <button type="button" className="icon-button" aria-label="Previous month" onClick={() => setVisibleMonth(firstOfMonth(new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() - 1, 1, 12)))}><ChevronLeft size={16} /></button>}
                      <h3 aria-live={monthIndex === 0 ? "polite" : undefined}>{monthName(month)}</h3>
                      {monthIndex === 1 && <button type="button" className="icon-button" aria-label="Next month" onClick={() => setVisibleMonth(firstOfMonth(new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() + 1, 1, 12)))}><ChevronRight size={16} /></button>}
                    </header>
                    <div className="audit-range-grid" role="grid" aria-label={monthName(month)}>
                      {weekdays.map((weekday, index) => <span role="columnheader" className="audit-range-weekday" key={`${weekday}-${index}`}>{weekday}</span>)}
                      {Array.from({ length: offset }, (_, index) => <span aria-hidden="true" className="audit-range-empty" key={`blank-${index}`} />)}
                      {Array.from({ length: numberOfDays }, (_, index) => {
                        const date = new Date(month.getFullYear(), month.getMonth(), index + 1, 12);
                        const key = localDateKey(date);
                        const isStart = key === start;
                        const isEnd = key === end;
                        const inRange = Boolean(start && end && key >= start && key <= end);
                        const today = key === localDateKey(new Date());
                        return <button ref={(node) => { if (node) dayRefs.current.set(key, node); else dayRefs.current.delete(key); }} key={key} type="button" role="gridcell" className={`audit-range-day${isStart ? " is-start" : ""}${isEnd ? " is-end" : ""}${inRange ? " is-in-range" : ""}${today ? " is-today" : ""}`} aria-label={new Intl.DateTimeFormat(locale, { dateStyle: "full" }).format(date)} aria-pressed={isStart || isEnd} tabIndex={focusKey === key ? 0 : -1} onFocus={() => setFocusKey(key)} onClick={() => chooseDay(key)}>{date.getDate()}</button>;
                      })}
                    </div>
                  </div>;
                })}
              </div>
              <div className="audit-range-summary">
                <div><strong>{formatRange(start, end, locale)}</strong><span>{selectedDays ? `${selectedDays} ${selectedDays === 1 ? "day" : "days"} selected` : start ? "Select an end date" : "No dates selected"}</span></div>
                <div className="audit-range-actions">
                  {(start || end) && <button className="secondary-button" type="button" onClick={() => { setStart(""); setEnd(""); setActivePreset(""); }}>Clear range</button>}
                  <button className="secondary-button" type="button" onClick={cancel}>Cancel</button>
                  <button className="primary-button" type="button" disabled={Boolean(start) !== Boolean(end)} onClick={apply}>Use range</button>
                </div>
              </div>
            </section>
          </div>
        </div>, document.body,
      )}
    </>
  );
}
