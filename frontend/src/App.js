import { createBrowserRouter } from "react-router-dom";
import { RouterProvider } from "react-router-dom";
import { loader as TransactionGraphLoader } from "./pages/transaction";
import "./index.css";
import Root from "./pages/root";
import Graph from "./pages/graph";
import Home from "./pages/home";
import Transaction from "./pages/transaction";
import Wallet from "./pages/wallet";

function App() {
  const router = createBrowserRouter([
    {
      path: "/",
      element: <Root />,
      children: [
        {
          path: "/graph",
          element: <Graph />,
        },
        {
          path: "/",
          element: <Home />,
        },
        {
          path: "/wallet",
          element: <Wallet />,
        },
        {
          path: `/transaction/:hash`,
          element: <Transaction />,
          loader: TransactionGraphLoader,
        },
      ],
    },
  ]);

  return (
    <div className="App">
      <RouterProvider router={router} />
    </div>
  );
}

export default App;
