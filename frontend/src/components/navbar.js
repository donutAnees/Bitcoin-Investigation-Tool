import Navlist from "./navlist";

export default function Navbar() {
  return (
    <section className="dark:text-slate-50 flex justify-between items-center px-6 pt-2">
      <div className="flex items-center">
        <img className="h-16" src="/images/logo.png" alt="" />
        <h1 className="font-semibold">blockTracker</h1>
      </div>
      <Navlist></Navlist>
    </section>
  );
}
