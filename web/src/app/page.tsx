import Analyzer from "@/components/Analyzer";
import { DataProvider } from "@/components/data";
import Hero from "@/components/Hero";
import IncidentView from "@/components/IncidentView";
import MotionRoot from "@/components/MotionRoot";
import Nav from "@/components/Nav";
import RedTeam from "@/components/RedTeam";
import Results from "@/components/Results";
import { Footer, Sources, UseIt } from "@/components/Static";
import Steps from "@/components/Steps";
import Story from "@/components/Story";
import Tour from "@/components/Tour";

export default function Home() {
  return (
    <DataProvider>
      <a className="skip" href="#analyze">Skip to the analyzer</a>
      <Nav />
      <main id="top">
        <Hero />
        <Story />
        <Steps />
        <Tour />
        <Analyzer />
        <RedTeam />
        <IncidentView />
        <Results />
        <UseIt />
        <Sources />
      </main>
      <Footer />
      <MotionRoot />
    </DataProvider>
  );
}
