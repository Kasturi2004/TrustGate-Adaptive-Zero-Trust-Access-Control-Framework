import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { EventTable } from "./EventTable";
import { ErrorState } from "./States";

describe("audit event table", () => {
  it("shows a truthful empty result state", () => {
    const markup = renderToStaticMarkup(createElement(EventTable, { events: [] }));
    expect(markup).toContain("No security events match these filters");
    expect(markup).toContain("clear one or more filters");
  });

  it("supports dashboard-specific empty copy without implying active filters", () => {
    const markup = renderToStaticMarkup(createElement(EventTable, {
      events: [],
      emptyTitle: "No recent events to show",
      emptyDetail: "Events will appear here as TrustGate records activity.",
    }));
    expect(markup).toContain("No recent events to show");
    expect(markup).toContain("Events will appear here as TrustGate records activity.");
    expect(markup).not.toContain("clear one or more filters");
  });

  it("renders an accessible error with a retry action", () => {
    const markup = renderToStaticMarkup(createElement(ErrorState, {
      message: "Unable to load events",
      onRetry: () => undefined,
    }));
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Unable to load events");
    expect(markup).toContain("Try again");
  });

  it("links each returned event ID to its investigation", () => {
    const event = {
      id: "event-id-1234567890abcdef",
      event_type: "ACCESS_BLOCKED",
      created_at: "2026-10-12T10:00:00Z",
      user_id: null,
      decision: "BLOCK",
      risk_category: "HIGH",
      trust_score: 0,
      device: "device-fingerprint-1234567890abcdef",
    };
    const markup = renderToStaticMarkup(createElement(
      MemoryRouter,
      { initialEntries: ["/events"] },
      createElement(EventTable, { events: [event] }),
    ));
    expect(markup).toContain("<th scope=\"col\">Event</th>");
    expect(markup).toContain("Time (local)");
    expect(markup).toContain("Device</th>");
    expect(markup).toContain("Trust score</th>");
    expect(markup).toContain("Details</th>");
    expect(markup).toContain("Access blocked");
    expect(markup.indexOf("Access blocked")).toBeLessThan(markup.indexOf("event-id...abcdef"));
    expect(markup).toContain("event-id...abcdef");
    expect(markup).toContain('aria-label="Event ID: event-id-1234567890abcdef"');
    expect(markup).toContain('href="/investigations/event-id-1234567890abcdef"');
    expect(markup).toContain("Investigate");
    expect(markup).toContain('aria-label="User ID not available"');
    expect(markup).toContain("table-empty");
    expect(markup).toContain("device-f...abcdef");
    expect(markup).toContain('class="score-cell">0');
    expect(markup).toContain("\u2014");
    expect(markup).toContain("badge-danger badge-risk");
    expect(markup).toContain("BLOCK");
    expect(markup).toContain("HIGH");
  });
});
