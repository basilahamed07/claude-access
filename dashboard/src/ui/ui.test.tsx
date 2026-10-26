import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DecisionBadge } from "./DecisionBadge";
import { Value, displayText } from "./Value";
import { applyTheme, readTheme, saveTheme } from "../theme/ThemeToggle";
import { readFileSync } from "node:fs";

describe("DecisionBadge", () => {
  it.each([["allow", "Cleared"], ["ask", "Holding"], ["block", "Blocked"]])("%s shows an icon and the word %s", (d, word) => {
    const { container } = render(<DecisionBadge decision={d} />);
    expect(screen.getByText(word)).toBeInTheDocument();
    expect(container.querySelector("svg")).not.toBeNull();
    expect(container.firstElementChild).toHaveAttribute("title", `API value: ${d}`);
  });
  it("uses the recorder colour only for block", () => {
    const css = readFileSync("src/theme/global.css", "utf8");
    const users = [...css.matchAll(/([^{}]+)\{[^}]*var\(--recorder\)[^}]*\}/g)].map((m) => m[1].trim());
    expect(users.some((s) => s.includes(".badge--block"))).toBe(true);
    expect(users.some((s) => /badge--(allow|ask|none)/.test(s))).toBe(false);
  });
  it("says so when there is no decision", () => {
    render(<DecisionBadge decision={null} />);
    expect(screen.getByText("No decision")).toBeInTheDocument();
  });
});

describe("Value", () => {
  it("renders markup as text, never as elements", () => {
    const { container } = render(<Value value={'<script>alert(1)</script><img src=x onerror=alert(1)>'} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
  });
  it("shows bidi control characters as visible text but copies the original", async () => {
    const hostile = "invoice‮gnp.exe";
    expect(displayText(hostile)).toBe("invoice\\u202Egnp.exe");
    const write = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText: write }, configurable: true });
    render(<Value value={hostile} />);
    expect(screen.getByText("invoice\\u202Egnp.exe")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(write).toHaveBeenCalledWith(hostile);
  });
  it("truncates past 300 characters and offers Show all", async () => {
    const long = "a".repeat(5000);
    const { container } = render(<Value value={long} />);
    expect(container.querySelector(".value")!.textContent!.length).toBeLessThan(310);
    await userEvent.click(screen.getByRole("button", { name: "Show all" }));
    expect(container.querySelector(".value")!.textContent).toHaveLength(5000);
    expect(screen.getByRole("button", { name: "Show less" })).toBeInTheDocument();
  });
  it("pretty-prints objects", () => {
    const { container } = render(<Value value={{ to: "a@b.com" }} block />);
    expect(container.textContent).toContain('"to": "a@b.com"');
  });
});

describe("theme", () => {
  it("survives localStorage throwing", () => {
    const orig = Storage.prototype.getItem;
    Storage.prototype.getItem = () => { throw new Error("blocked"); };
    const set = Storage.prototype.setItem;
    Storage.prototype.setItem = () => { throw new Error("blocked"); };
    try {
      expect(readTheme()).toBe("system");
      expect(() => saveTheme("dark")).not.toThrow();
      applyTheme("dark");
      expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
      applyTheme("system");
      expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
    } finally { Storage.prototype.getItem = orig; Storage.prototype.setItem = set; }
  });
});
