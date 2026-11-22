"use client";
import { animate, inView, scroll } from "motion";
import { useEffect, useRef, useState } from "react";

export default function Tour() {
  const v = useRef<HTMLVideoElement>(null);
  const [paused, setPaused] = useState(true);
  useEffect(() => {
    const video = v.current;
    if (!video) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const sync = () => setPaused(video.paused);
    video.addEventListener("play", sync);
    video.addEventListener("pause", sync);
    const stop = reduce ? () => {} : scroll(animate(".tour-frame", { rotateX: [12, 0], scale: [0.92, 1] }, { ease: "linear" }),
      { target: document.querySelector(".tour") as HTMLElement, offset: ["start end", "center center"] });
    const stopView = inView(video, () => () => video.pause(), { amount: 0.5 });
    return () => { stop(); stopView(); video.removeEventListener("play", sync); video.removeEventListener("pause", sync); };
  }, []);
  return (
    <section className="tour section" aria-labelledby="tour-h">
      <div className="tour-frame reveal">
        <video ref={v} controls playsInline preload="none" poster="/media/demo-poster.jpg" aria-describedby="tour-h">
          <source src="/media/demo.mp4" type="video/mp4" />
        </video>
      </div>
      <div className="tour-copy">
        <h2 id="tour-h" className="reveal">Two minutes through the whole system</h2>
        <p className="reveal">The hackathon film: a planted instruction, a side-by-side attack, the incident graph, the architecture and the measured results, including a real llama3.2 run.</p>
        <button className="btn glass small" onClick={() => (paused ? v.current?.play() : v.current?.pause())}>{paused ? "Play film" : "Pause film"}</button>
      </div>
    </section>
  );
}
