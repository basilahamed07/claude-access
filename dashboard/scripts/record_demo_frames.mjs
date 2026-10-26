// Screenshots for docs/demo.gif: two terminal frames (the real transcripts) and the dashboard tape. Run by scripts/make_demo_gif.py.
import { readFileSync } from "node:fs";
import { chromium } from "playwright-core";

const [base, email, password, dir] = process.argv.slice(2);
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
const term = (cmd, out, banner, bg, fg) => `<html><body style="margin:0;background:#0f1720;color:#e4eaee;font:16px/1.55 ui-monospace,Menlo,'DejaVu Sans Mono',monospace;width:1280px;height:720px;position:relative">
<div style="padding:30px 40px"><div style="color:#8fa3b1;margin-bottom:14px">$ ${esc(cmd)}</div><pre style="margin:0;white-space:pre-wrap;font:inherit">${esc(out)}</pre></div>
<div style="position:absolute;left:40px;bottom:40px;font:600 26px system-ui,sans-serif;padding:10px 18px;border-radius:4px;background:${bg};color:${fg}">${esc(banner)}</div></body></html>`;

const b = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium" });
const ctx = await b.newContext({ viewport: { width: 1280, height: 720 }, colorScheme: "light", baseURL: base });
const page = await ctx.newPage();
let n = 0;
const shot = async () => page.screenshot({ path: `${dir}/frames/${String(++n).padStart(2, "0")}.png` });
const unprotected = readFileSync(`${dir}/unprotected.txt`, "utf8");
const protectedRun = readFileSync(`${dir}/protected.txt`, "utf8");

await page.setContent(term("python demo/email_agent/run_unprotected.py", unprotected, "Leaked: the invoices went to x@unknown.com", "#e5560b", "#16202a")); await shot();
await page.setContent(term("python demo/email_agent/run_protected.py   # same agent, same prompt, only the base URL and key differ", protectedRun, "Blocked: nothing left the company", "#2e6b5a", "#ffffff")); await shot();

await page.goto("/login");
await page.getByLabel("Email").fill(email);
await page.getByLabel("Password").fill(password);
await page.getByRole("button", { name: "Sign in" }).click();
await page.getByRole("heading", { name: "Needs you" }).waitFor();
await page.waitForTimeout(600);
await shot();                                                               // overview: what needs you
await page.goto("/sessions");
await page.getByRole("row", { name: /Open session for email-reader-01/ }).first().click();
const tape = page.getByRole("grid", { name: "Session events" });
await tape.waitFor();
await page.getByText(/Chain verified/).waitFor();
await page.waitForTimeout(500);
await shot();                                                               // the tape
const block = tape.locator(".trow.is-blocked", { hasText: "deny-external-send" }).first();
await block.click();
await page.waitForTimeout(300);
await shot();                                                               // cursor on the blocked step
await page.keyboard.press("Enter");
await page.getByRole("dialog").waitFor();
await page.waitForTimeout(400);
await shot();                                                               // its recorded payload
await page.keyboard.press("Escape");
await page.goto("/policies");
await page.waitForTimeout(900);
await shot();                                                               // policy editor with simulate
await b.close();
