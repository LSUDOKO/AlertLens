"use client";
// Page-wide motion, the way Pharmakon does it: blur-up reveals and liquid-glass buttons that follow the pointer.
import { animate, inView } from "motion";
import { useEffect } from "react";

const EASE = [0.22, 1, 0.36, 1] as const;

export default function MotionRoot() {
  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.documentElement.classList.add("js");
    // Sections that load data render their .reveal elements later, so watch for those too.
    const stops: (() => void)[] = [];
    const watch = (root: ParentNode) => {
      root.querySelectorAll<HTMLElement>(".reveal:not([data-rv])").forEach((el) => {
        el.dataset.rv = "1";
        if (reduce) return;
        stops.push(inView(el, () => {
          animate(el, { opacity: [0, 1], y: [28, 0], filter: ["blur(6px)", "blur(0px)"] }, { duration: 0.9, ease: EASE });
        }, { amount: 0.25 }));
      });
    };
    watch(document);
    const mo = new MutationObserver(() => watch(document));
    mo.observe(document.body, { childList: true, subtree: true });
    const stop = () => { mo.disconnect(); stops.forEach((s) => s()); };
    const move = (e: PointerEvent) => {
      const btn = (e.target as Element | null)?.closest?.(".btn.glass") as HTMLElement | null;
      if (!btn) return;
      const r = btn.getBoundingClientRect();
      btn.style.setProperty("--gx", `${((e.clientX - r.left) / r.width) * 100}%`);
      btn.style.setProperty("--gy", `${((e.clientY - r.top) / r.height) * 100}%`);
      if (!reduce && btn.hasAttribute("data-magnetic")) {
        animate(btn, { x: (e.clientX - r.left - r.width / 2) * 0.18, y: (e.clientY - r.top - r.height / 2) * 0.3 }, { type: "spring", stiffness: 300, damping: 18 });
      }
    };
    const leave = (e: PointerEvent) => {
      const btn = (e.target as Element | null)?.closest?.(".btn.glass") as HTMLElement | null;
      if (!btn || btn.contains(e.relatedTarget as Node)) return;
      btn.style.setProperty("--gx", "50%");
      btn.style.setProperty("--gy", "0%");
      if (!reduce) animate(btn, { x: 0, y: 0 }, { type: "spring", stiffness: 260, damping: 15 });
    };
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerout", leave);
    return () => { stop(); document.removeEventListener("pointermove", move); document.removeEventListener("pointerout", leave); };
  }, []);
  return null;
}
