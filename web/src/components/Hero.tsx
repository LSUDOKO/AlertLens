"use client";
// The Pharmakon hero, in crimson: two torn sheets, a hatched band, a chrome wordmark, and a tear on scroll.
import { animate, scroll, stagger } from "motion";
import { useEffect, useRef } from "react";
import { useApiData } from "./data";

const EASE = [0.22, 1, 0.36, 1] as const;
const fmt = (n: number) => n.toLocaleString("en-GB");

export default function Hero() {
  const ref = useRef<HTMLElement>(null);
  const { bench } = useApiData();
  const alerts = bench?.simulated?.meta?.alerts;
  const real = bench?.real?.meta?.injected_malicious;
  const realFooled = real ? Math.round((bench?.real?.asr?.alertlens ?? 0) * real) : null;

  useEffect(() => {
    const hero = ref.current;
    if (!hero || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const a = hero.querySelector(".sheet-a") as HTMLElement;
    const b = hero.querySelector(".sheet-b") as HTMLElement;
    const band = hero.querySelector(".band") as HTMLElement;
    const mark = hero.querySelector(".wordmark .chrome") as HTMLElement;
    animate(a, { x: ["18%", "0%"], y: ["-18%", "0%"], opacity: [0, 1] }, { duration: 1.4, ease: EASE });
    animate(b, { x: ["-18%", "0%"], y: ["18%", "0%"], opacity: [0, 1] }, { duration: 1.4, ease: EASE, delay: 0.08 });
    animate(band, { clipPath: ["inset(0 50% 0 50%)", "inset(-200px -200vw -200px -200vw)"] }, { duration: 1.1, ease: EASE, delay: 0.45 });
    animate(hero.querySelector(".wm-mark")!, { rotate: [-90, 0], scale: [0.4, 1], opacity: [0, 1] }, { type: "spring", stiffness: 120, damping: 14, delay: 0.9 });
    mark.style.backgroundSize = "100% 260%";
    animate(mark, { backgroundPositionY: ["100%", "0%"], opacity: [0, 1] }, { duration: 1.6, ease: EASE, delay: 0.8 });
    animate(hero.querySelectorAll(".dim"), { opacity: [0, 1] }, { duration: 0.8, delay: stagger(0.15, { startDelay: 1.3 }) });
    animate(hero.querySelectorAll(".hero-copy > *"), { opacity: [0, 1], y: [18, 0] }, { duration: 0.9, ease: EASE, delay: stagger(0.12, { startDelay: 1.2 }) });
    // Leaving the hero tears the sheets apart and sinks the band.
    const opts = { target: hero, offset: ["start start", "end start"] as ["start start", "end start"] };
    const stops = [
      scroll(animate(a, { x: ["0%", "22%"], y: ["0%", "-20%"], rotate: [0, 4] }, { ease: "linear" }), opts),
      scroll(animate(b, { x: ["0%", "-22%"], y: ["0%", "20%"], rotate: [0, -4] }, { ease: "linear" }), opts),
      scroll(animate(band, { scale: [1, 0.9], opacity: [1, 0.2] }, { ease: "linear" }), opts),
      scroll(animate(hero.querySelector(".hero-copy")!, { y: [0, 80], opacity: [1, 0] }, { ease: "linear" }), opts),
    ];
    return () => stops.forEach((s) => s());
  }, []);

  return (
    <section className="hero" aria-label="Introduction" ref={ref}>
      <div className="sheet sheet-a" aria-hidden="true">
        <div className="fringe" />
        <div className="paper">
          <video autoPlay muted loop playsInline poster="/media/hero-poster.jpg">
            <source src="/media/hero-loop.webm" type="video/webm" />
            <source src="/media/hero-loop.mp4" type="video/mp4" />
          </video>
        </div>
      </div>
      <div className="sheet sheet-b" aria-hidden="true">
        <div className="fringe" />
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <div className="paper"><img src="/media/folio-colossus.webp" alt="" /></div>
      </div>

      <div className="band">
        <div className="dim dim-h" aria-hidden="true"><span>{alerts ? fmt(alerts) : "2,000"}</span> alerts attacked in the benchmark</div>
        <div className="dim dim-v" aria-hidden="true">{realFooled !== null && real ? `${realFooled} of ${real} real attacks got through` : "tested on a real model"}</div>
        <h1 className="wordmark">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/media/mark.svg" alt="" className="wm-mark" />
          <span className="chrome">alertlens</span>
        </h1>
      </div>

      <div className="hero-copy">
        <p className="lede">Security alerts are written for machines, and attackers can hide orders inside them. AlertLens explains every alert without taking those orders.</p>
        <div className="cta-row">
          <a className="btn glass" href="#analyze" data-magnetic>Analyze an alert</a>
          <a className="btn glass ghost" href="#redteam" data-magnetic>Attack it yourself</a>
        </div>
      </div>
      <p className="hero-note">Synthetic data. Every action is simulated.</p>
      <a className="scroll-cue" href="#story" aria-label="Scroll to the story"><span /></a>
    </section>
  );
}
