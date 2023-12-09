import Navbar from "../components/navbar";

export default function Home(props) {
  return (
    <div className="bg-slate-50 dark:bg-bluish-black h-screen bg-light-bg dark:bg-dark-bg absolute bg-cover w-screen">
      <Navbar></Navbar>
      <h1 className="text-center dark:text-white font-extrabold text-5xl mx-auto mt-24 animate-slide-in">
        Stay Ahead in the Crypto Game
        <br /> Monitor Illegal Moves in Real Time.
      </h1>
      <p className="text-slate-800 dark:text-slate-400 font-light mt-10 text-center">
        The exclusive hub for all the tools essential to trace transactions{" "}
        <span className="text-cyan-400">effortlessly</span> and <span className="text-cyan-400">effectively</span>
      </p>
    </div>
  );
}
