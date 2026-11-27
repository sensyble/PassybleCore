// node --test Core/desktop-app/ui/test/*.test.mjs (Node 22 or later)
// Help and support: the diagnostics filter (only the allowed fields, values without / : @ = and
// under 64 characters), guest ticket codes and app links, the new-ticket checks and where a guest
// ticket stands. Demo data only.
import assert from "node:assert/strict";
import test from "node:test";

import {
  cleanDiagnostics, diagnosticsLines, ERRORS_MAX, formatCode, linkArrival, normalizeCode, parseAppLink, parseCodeInput, parseReference,
  problemMessage, sortTickets, ticketProblems, ticketStage, topicChoices, TOPICS, totalUnread, validEmail, valueOk,
} from "../views/support-model.js";

const DIAG = {
  app: "Passyble desktop",
  app_version: "1.4.0",
  platform: "windows",
  os_version: "Windows 11 24H2 (build 26100.2894)",
  sync: "google_drive",
  errors: ["sync.network", "api.too_many_requests"],
  locale: "de",
};

test("diagnostics keep the allowed fields and nothing else", () => {
  assert.deepEqual(cleanDiagnostics(DIAG), DIAG);
  const sneaky = {
    ...DIAG,
    vault: "Personal",
    email: "alice@example.com",
    item: "Bank login",
    sync: "https://cloud.example.com/dav/alice",
    os_version: "C:\\Users\\alice",
    locale: "token=abc",
    errors: ["sync.network", "x y", "a".repeat(41), "sync.network", 7, "ok_code"],
  };
  assert.deepEqual(cleanDiagnostics(sneaky), {
    app: "Passyble desktop",
    app_version: "1.4.0",
    platform: "windows",
    errors: ["sync.network", "ok_code"],
  });
  for (const bad of ["alice@example.com", "a/b", "a:b", "k=v", "#x", "?x", "", "x".repeat(64)]) assert.equal(valueOk(bad), false, bad);
  assert.equal(valueOk("x".repeat(63)), true);
  assert.equal(cleanDiagnostics({ vault: "x" }), null);
  assert.equal(cleanDiagnostics(null), null);
  assert.equal(cleanDiagnostics(["app"]), null);
  const many = cleanDiagnostics({ errors: Array.from({ length: 20 }, (_, i) => `e${i}`) });
  assert.equal(many.errors.length, ERRORS_MAX);
});

test("the person sees every line that is sent, in order", () => {
  const lines = diagnosticsLines({ locale: "de", app: "Passyble desktop", errors: ["a.b", "c"], path: "/x" });
  assert.deepEqual(lines, [["app", "Passyble desktop"], ["errors", "a.b, c"], ["locale", "de"]]);
  assert.deepEqual(diagnosticsLines(null), []);
});

test("codes, references and app links", () => {
  assert.equal(normalizeCode("abcd-efgh"), "ABCDEFGH");
  assert.equal(normalizeCode(" ABCD EFGH "), "ABCDEFGH");
  assert.equal(normalizeCode("ABCD-EFG0"), null, "0 is not in the alphabet");
  assert.equal(normalizeCode("ABCDEFG"), null);
  assert.equal(formatCode("abcdefgh"), "ABCD-EFGH");
  assert.equal(parseReference("ps-abcdef"), "PS-ABCDEF");
  assert.equal(parseReference("PS-ABCDE1"), null);
  assert.deepEqual(parseAppLink("passyble://support/app?r=PS-ABCDEF&c=WXYZ-2345"), { reference: "PS-ABCDEF", code: "WXYZ2345" });
  assert.deepEqual(parseAppLink("https://account.passyble.com/support/app?r=ps-abcdef&c=wxyz2345"), { reference: "PS-ABCDEF", code: "WXYZ2345" });
  assert.deepEqual(parseAppLink("https://HELP.passyble.com/support/app?r=ps-abcdef&c=wxyz2345"), { reference: "PS-ABCDEF", code: "WXYZ2345" });
  assert.equal(parseAppLink("https://help.passyble.com.evil.example/support/app?r=PS-ABCDEF&c=WXYZ2345"), null);
  assert.equal(parseAppLink("https://evil.example/support/app?r=PS-ABCDEF&c=WXYZ2345"), null);
  assert.equal(parseAppLink("http://account.passyble.com/support/app?r=PS-ABCDEF&c=WXYZ2345"), null);
  assert.equal(parseAppLink("https://account.passyble.com/support/t?k=x"), null);
  assert.equal(parseAppLink("not a link"), null);
  assert.deepEqual(parseCodeInput("wxyz-2345"), { reference: null, code: "WXYZ2345" });
  assert.deepEqual(parseCodeInput("passyble://support/app?r=PS-BCDEFG&c=WXYZ2345"), { reference: "PS-BCDEFG", code: "WXYZ2345" });
  assert.equal(parseCodeInput("1234"), null);
});

test("a new ticket needs a topic, a subject, a message and, for guests, an address", () => {
  const ok = { topic: "sync", subject: "Sync stopped", body: "It says offline.", email: "alice@example.com" };
  assert.deepEqual(ticketProblems(ok, { guest: true }), {});
  assert.deepEqual(ticketProblems({ ...ok, email: "" }, { guest: false }), {}, "signed in: the account's address");
  assert.deepEqual(ticketProblems({ ...ok, email: "" }, { guest: true }), { email: "missing" });
  assert.deepEqual(ticketProblems({ ...ok, email: "alice@" }, { guest: true }), { email: "invalid" });
  assert.deepEqual(ticketProblems({ ...ok, subject: " ", body: "", topic: "" }), { subject: "missing", body: "missing", topic: "missing" });
  assert.deepEqual(ticketProblems({ ...ok, subject: "x".repeat(151), body: "y".repeat(5001), name: "z".repeat(101) }),
    { subject: "long", body: "long", name: "long" });
  assert.equal(validEmail("bob@example.co.uk"), true);
  for (const bad of ["bob", "bob@example", "@example.com", "b ob@example.com", "bob@.example.com", "a@b@c.com"]) assert.equal(validEmail(bad), false, bad);
});

test("where a guest ticket stands", () => {
  const now = 1_000_000;
  assert.equal(ticketStage({ guest: true, claimed: false, confirm_by: now + 1 }, now), "waiting");
  assert.equal(ticketStage({ guest: true, claimed: false, confirm_by: now - 1 }, now), "expired");
  assert.equal(ticketStage({ guest: true, claimed: false, status: "expired" }, now), "expired");
  assert.equal(ticketStage({ guest: true, claimed: true, status: "waiting_on_us" }, now), "open");
  assert.equal(ticketStage({ guest: true, claimed: true, status: "gone" }, now), "gone");
  assert.equal(ticketStage({ guest: false, status: "closed" }, now), "closed");
  assert.equal(ticketStage({ guest: false, status: "waiting_on_customer" }, now), "open");
  assert.equal(ticketStage(null, now), "gone");
});

test("topics, unread counts, order and the quoted problem", () => {
  assert.deepEqual(topicChoices(null).map((c) => c.id), TOPICS);
  assert.deepEqual(topicChoices({ categories: [{ id: "sync", label: "Synchronisation" }, { id: "other", label: " " }, { label: "x" }] }),
    [{ id: "sync", label: "Synchronisation" }, { id: "other", label: null }]);
  assert.equal(totalUnread([{ unread: 2 }, { unread: 0 }, { unread: -1 }, {}, { unread: 1 }]), 3);
  assert.deepEqual(sortTickets([{ reference: "a", last_message_at: 1 }, { reference: "b", last_message_at: 3 }, { reference: "c", created_at: 2 }]).map((t) => t.reference),
    ["b", "c", "a"]);
  assert.equal(problemMessage("  Can't reach\n  the server.  "), "Can't reach the server.");
  assert.equal(problemMessage("x".repeat(400)).length, 300);
});

test("an app link with a guest code waits for Confirm and never submits by itself", () => {
  assert.equal(linkArrival(null), null);
  assert.equal(linkArrival({ link_pending: false, link_reference: null }), null);
  const arrival = linkArrival({ link_pending: true, link_reference: "PS-ABCDEF" });
  assert.deepEqual(arrival, { step: "confirm", reference: "PS-ABCDEF", submit: false });
  // The status carries the reference only, never the code.
  assert.ok(!JSON.stringify(arrival).includes("code"));
});
