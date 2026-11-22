"use client";
import { inView } from "motion";
import { useEffect, useState } from "react";

const LINKS = [
  ["#story", "Story"], ["#analyze", "Analyze"], ["#redteam", "Red team"], ["#incident", "Incident"], ["#results", "Results"], ["#use", "Use it"],
] as const;

export default function Nav() {
  const [active, setActive] = useState<string>("");
  useEffect(() => {
    const stops = LINKS.map(([href]) => {
      const el = document.querySelector(href);
      return el ? inView(el, () => setActive(href), { amount: 0.3 }) : () => {};
    });
    return () => stops.forEach((s) => s());
  }, []);
  return (
    <header className="nav glass-bar">
      <a className="brand" href="#top" aria-label="AlertLens home">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/media/mark.svg" alt="" width={28} height={28} />
        <span>alertlens</span>
      </a>
      <nav aria-label="Sections">
        {LINKS.map(([href, label]) => (
          <a key={href} href={href} className={active === href ? "active" : undefined}>{label}</a>
        ))}
      </nav>
      <a className="btn glass small" href="https://github.com/LSUDOKO/AlertLens" target="_blank" rel="noopener">GitHub</a>
    </header>
  );
}
