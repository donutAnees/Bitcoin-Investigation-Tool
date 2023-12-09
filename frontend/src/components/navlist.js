const item = ["About us", "Profile", "Team", "Contact"];

export default function Navlist() {
  return (
    <div className="flex items-center">
      <ul className="flex">
        {item.map((i, index) => {
          return (
            <button key={index} className="md:px-6 font-medium text-xs hover:text-cyan-400">
              {i}
            </button>
          );
        })}
      </ul>
    </div>
  );
}
