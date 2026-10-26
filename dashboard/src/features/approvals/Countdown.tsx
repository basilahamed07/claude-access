import { useEffect, useState } from "react";

export function secondsLeft(expiresAt: string, now = Date.now()): number {
  return Math.max(0, Math.floor((new Date(expiresAt).getTime() - now) / 1000));
}
export function formatLeft(s: number): string {
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function Countdown({ expiresAt, onExpire }: { expiresAt: string; onExpire?: () => void }) {
  const [left, setLeft] = useState(() => secondsLeft(expiresAt));
  useEffect(() => {
    setLeft(secondsLeft(expiresAt));
    const t = setInterval(() => setLeft(secondsLeft(expiresAt)), 1000);
    return () => clearInterval(t);
  }, [expiresAt]);
  useEffect(() => { if (left === 0) onExpire?.(); }, [left, onExpire]);
  return left === 0 ? <span>Expired</span> : <span aria-label={`${left} seconds left`}>{formatLeft(left)} left</span>;
}
