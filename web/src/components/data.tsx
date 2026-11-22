"use client";
// Health and benchmark results are read once and shared by every section.
import { createContext, useContext, useEffect, useState } from "react";
import { api, ApiError, type Benchmark, type Health } from "@/lib/api";

type State = { health: Health | null; bench: Benchmark | null; error: string | null; waking: boolean };
const Ctx = createContext<State>({ health: null, bench: null, error: null, waking: true });
export const useApiData = () => useContext(Ctx);

export function DataProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<State>({ health: null, bench: null, error: null, waking: true });
  useEffect(() => {
    let live = true;
    (async () => {
      // A free backend sleeps when idle, so the first call may take a while. Try a few times.
      for (let i = 0; i < 4 && live; i++) {
        try {
          const health = await api.health();
          const bench = await api.benchmark();
          if (live) setState({ health, bench, error: null, waking: false });
          return;
        } catch (e) {
          if (live) setState((s) => ({ ...s, error: (e as ApiError).message, waking: i < 3 }));
          await new Promise((r) => setTimeout(r, 4000));
        }
      }
    })();
    return () => { live = false; };
  }, []);
  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}
