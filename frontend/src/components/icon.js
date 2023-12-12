import { Link } from "react-router-dom";

const items = [
  {
    icon: "GRAPH",
    description: "Visualize the transaction data as a graph",
    img: "/images/graph.png",
    link: "/graph"
  },
  {
    icon: "WALLET",
    description: "Find out if a wallet is illegal or not",
    img: "/images/wallet.png",
    link:"/wallet"
  },
];

export default function Icon() {
  return (
    <div className="flex justify-center">
      {items.map((item,index) => {
        return (
          <Link key={index} to={item.link} className="dark:bg-icon-dark-bg bg-icon-bg h-64 w-64 bg-no-repeat bg-cover mx-10 rounded-3xl flex flex-col items-center hover:scale-110 cursor-pointer">
            <div className="w-3/4 text-center m-8">
              <h3 className="text-white text-xl font-extrabold">{item.icon}</h3>
              <img src={item.img} alt="" className="h-20 mx-auto my-3" />
              <p className="text-white text-l font-medium">
                {item.description}
              </p>
            </div>
          </Link>
          
        );
      })}
    </div>
  );
}
